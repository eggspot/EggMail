using System.Text;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Tls;

/// <summary>
/// Issues and renews the ACME certificate stored in the database (decision K). Renewal must run on one replica at a time:
/// a lease row with a fencing token (works on both backends) guards each order, because a DNS-01 flow takes minutes and cannot
/// hold a transaction or a pooled session lock (design §7.3). Failures back off exponentially (capped) so rate limits are respected.
/// </summary>
public sealed class AcmeRenewalService
{
    public static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(20);

    /// <summary>How long an order waits for the HTTP-01 listener's first attempt to bind its port (it binds within milliseconds of the start).</summary>
    private static readonly TimeSpan ListenerStartWait = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan MinimumRetryDelay = TimeSpan.FromSeconds(30);

    /// <summary>When the listener could not be bound the CA was never asked, so the next attempt is soon (the listener retries every minute itself).</summary>
    private static readonly TimeSpan ListenerRetry = TimeSpan.FromMinutes(5);

    /// <summary>The CA in use: <c>Acme:Directory</c> (a name or URL) or <c>Acme:DirectoryUrl</c>.</summary>
    private string Directory => _options.EffectiveDirectoryUrl() ?? throw new AcmeException($"Acme:Directory '{_options.Directory}' is neither a known CA name (LetsEncrypt, LetsEncryptStaging, ZeroSsl) nor an http(s) URL.");

    /// <summary>
    /// Which challenge proves the names of an order: DNS-01 when the server has DNS credentials (<c>Acme:Challenge=Auto</c>) or is told to, else HTTP-01.
    /// Wildcard names can only be proven by DNS-01.
    /// </summary>
    private AcmeChallengeType ChooseChallenge(IReadOnlyList<string> domains)
    {
        string? wildcard = domains.FirstOrDefault(AcmeNames.IsWildcard);
        var challenge = _options.Challenge switch
        {
            AcmeChallengeMode.Dns01 => AcmeChallengeType.Dns01,
            AcmeChallengeMode.Http01 => AcmeChallengeType.Http01,
            _ => _dns is not null ? AcmeChallengeType.Dns01 : AcmeChallengeType.Http01,
        };
        if (challenge == AcmeChallengeType.Dns01 && _dns is null)
        {
            throw new AcmeException("Acme:Challenge=Dns01 needs a DNS provider: set Acme:CloudflareApiToken (or Acme:CloudflareApiTokenFile).");
        }

        if (challenge == AcmeChallengeType.Http01)
        {
            if (wildcard is not null)
            {
                throw new AcmeException($"'{wildcard}' is a wildcard name, which only DNS-01 can prove (RFC 8555 section 8.3); set Acme:CloudflareApiToken (DNS-01 with Cloudflare) or remove the wildcard.");
            }

            if (_http is null)
            {
                throw new AcmeException("HTTP-01 is not available on this server (the built-in challenge listener is not running).");
            }
        }

        return challenge;
    }

    /// <summary>The EAB HMAC key (base64url) for registering an account: inline or from <c>Acme:EabHmacKeyFile</c>; null without EAB.</summary>
    private string? ReadEabHmacKey() =>
        !string.IsNullOrWhiteSpace(_options.EabHmacKey) ? _options.EabHmacKey.Trim()
        : !string.IsNullOrWhiteSpace(_options.EabHmacKeyFile) ? File.ReadAllText(_options.EabHmacKeyFile).Trim()
        : null;

    private readonly IConfigStore _config;
    private readonly ISecretProtector _protector;
    private readonly IAcmeOrderRunner _runner;
    private readonly IDnsChallengeProvider? _dns;
    private readonly IHttpChallengePublisher? _http;
    private readonly AcmeSection _options;
    private readonly IClock _clock;
    private readonly IMtaLog _log;
    private readonly Func<double> _random;
    private readonly string _owner = "acme-" + Ids.ToCompact(Ids.New())[..12];

    /// <param name="dns">The DNS-01 provider; null when the server has no DNS credentials (HTTP-01 only).</param>
    /// <param name="random">Position inside a CA's renewal window (a number in [0, 1)); tests fix it.</param>
    /// <param name="http">Publishes the HTTP-01 answers; null when the server does not answer HTTP-01 challenges.</param>
    public AcmeRenewalService(IConfigStore config, ISecretProtector protector, IAcmeOrderRunner runner, IDnsChallengeProvider? dns, AcmeSection options, IClock? clock = null, IMtaLog? log = null,
        Func<double>? random = null, IHttpChallengePublisher? http = null)
    {
        _random = random ?? Random.Shared.NextDouble;
        _config = config;
        _protector = protector;
        _runner = runner;
        _dns = dns is NoDnsChallengeProvider ? null : dns;
        _http = http;
        _options = options;
        _clock = clock ?? SystemClock.Instance;
        _log = log ?? NullMtaLog.Instance;
    }

    /// <summary>When should a certificate be renewed? Pure and testable.</summary>
    public static bool NeedsRenewal(CertificateRecord? current, IReadOnlyList<string> wantedDomains, DateTimeOffset now, double remainingFraction)
    {
        if (current is null)
        {
            return true;
        }

        if (NamesDiffer(current, wantedDomains))
        {
            return true;
        }

        var lifetime = current.NotAfter - current.NotBefore;
        var remaining = current.NotAfter - now;
        return remaining <= lifetime * remainingFraction;
    }

    private static bool NamesDiffer(CertificateRecord current, IReadOnlyList<string> wantedDomains)
    {
        var wanted = wantedDomains.Select(d => d.ToLowerInvariant()).OrderBy(d => d).ToList();
        var have = current.Subjects.Select(d => d.ToLowerInvariant()).OrderBy(d => d).ToList();
        return !wanted.SequenceEqual(have);
    }

    /// <summary>Backoff after <paramref name="failures"/> consecutive failures: 10 min, 20 min, 40 min, … capped at 6 hours.</summary>
    public static TimeSpan Backoff(int failures) =>
        TimeSpan.FromMinutes(Math.Min(360, 10 * Math.Pow(2, Math.Max(0, failures - 1))));

    public async Task RunAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await CheckOnceAsync(ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log.Write(MtaLogLevel.Error, "acme", "renewal check failed", ex);
                }

                await Task.Delay(await NextCheckDelayAsync(ct).ConfigureAwait(false), ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>
    /// The pause before the next check: <see cref="AcmeSection.CheckInterval"/>, or less when a failed order is due for its next attempt sooner (at least 30 seconds),
    /// so that a back-off of 5 or 10 minutes means 5 or 10 minutes and not the next hourly check.
    /// </summary>
    internal async Task<TimeSpan> NextCheckDelayAsync(CancellationToken ct)
    {
        var delay = _options.CheckInterval;
        try
        {
            var now = _clock.UtcNow;
            foreach (var row in await _config.GetAcmeRenewalsAsync(ct).ConfigureAwait(false))
            {
                if (row.Status == "failed" && row.NextAttemptAt is { } next)
                {
                    delay = TimeSpan.FromTicks(Math.Min(delay.Ticks, Math.Max((next - now).Ticks, MinimumRetryDelay.Ticks)));
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The database is unavailable: the regular interval applies (and the next check will find out again).
            _log.Write(MtaLogLevel.Debug, "acme", $"could not read the renewal state to plan the next check ({ex.Message})");
        }

        return delay;
    }

    /// <summary>
    /// Issues or renews if needed. Returns true if a new certificate was stored. Renews the configured certificate and then every other active
    /// ACME certificate that was requested through the API (<see cref="RequestAsync"/>), each for the names it was issued for.
    /// </summary>
    public async Task<bool> CheckOnceAsync(CancellationToken ct)
    {
        if (!_options.Enabled)
        {
            return false;
        }

        bool issued = false;
        if (_options.Domains.Count > 0)
        {
            issued |= await RenewAsync(_options.CertificateName, AcmeNames.NormalizeAll(_options.Domains), force: false, ct).ConfigureAwait(false);
        }

        var others = (await _config.GetCertificatesAsync(ct).ConfigureAwait(false))
            .Where(c => c.Active && c.Source == "acme" && c.Name != _options.CertificateName)
            .GroupBy(c => c.Name)
            .Select(g => g.OrderByDescending(c => c.NotAfter).First())
            .ToList();
        foreach (var certificate in others)
        {
            issued |= await RenewAsync(certificate.Name, certificate.Subjects, force: false, ct).ConfigureAwait(false);
        }

        return issued;
    }

    /// <summary>
    /// Orders a certificate for <paramref name="domains"/> now (the dashboard's "request a certificate"), ignoring the renewal schedule and
    /// failure backoff. A set equal to the configured names renews the configured certificate; any other set is stored as <c>acme:&lt;first name&gt;</c>
    /// and renewed with the others by <see cref="CheckOnceAsync"/>. Returns true when a certificate was stored; failures are recorded in the
    /// renewal state (<see cref="IConfigStore.GetAcmeRenewalsAsync"/>).
    /// </summary>
    public async Task<bool> RequestAsync(IReadOnlyList<string> domains, CancellationToken ct)
    {
        if (!_options.Enabled)
        {
            throw new AcmeException("ACME is not enabled on this server (Acme:Enabled).");
        }

        ArgumentNullException.ThrowIfNull(domains);
        var wanted = AcmeNames.NormalizeAll(domains).OrderBy(d => d, StringComparer.Ordinal).ToList();
        var configured = AcmeNames.NormalizeAll(_options.Domains).OrderBy(d => d, StringComparer.Ordinal).ToList();
        // One name per set of names: a different set must never replace the row of another. The first name is for people, the hash tells sets apart.
        string name = wanted.SequenceEqual(configured)
            ? _options.CertificateName
            : wanted.Count == 1
                ? "acme:" + wanted[0]
                : "acme:" + wanted[0] + "+" + Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', wanted))))[..8];
        return await RenewAsync(name, wanted, force: true, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Is the certificate due? Without a certificate, or with other names than wanted: yes. Otherwise the CA's advice (ARI) decides when it is enabled and the
    /// CA gives some, else the lifetime rule (<see cref="AcmeRenewalSchedule"/>). What the CA answers is saved in the renewal row, in that column only.
    /// </summary>
    private async Task<bool> IsDueAsync(string name, CertificateRecord? current, IReadOnlyList<string> domains, AcmeRenewalRecord? renewal, DateTimeOffset now, CancellationToken ct)
    {
        if (current is null || NamesDiffer(current, domains))
        {
            return true;
        }

        if (!_options.UseRenewalInfo)
        {
            return NeedsRenewal(current, domains, now, _options.RenewAtRemainingFraction);
        }

        var advice = AcmeRenewalAdvice.Parse(renewal?.AriJson, current.Thumbprint);
        if (AcmeRenewalSchedule.ShouldCheck(advice, now))
        {
            advice = await FetchAdviceAsync(current, advice, now, ct).ConfigureAwait(false);
            try
            {
                // Only the advice column: the row is shared with the other replicas, whose status and back-off must not be overwritten with what was read before the question.
                await _config.SetAcmeRenewalAdviceAsync(name, advice.ToJson(), ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                // The advice in hand is still used for this decision; a database problem must not hold up a renewal or the other certificates.
                _log.Write(MtaLogLevel.Warning, "acme", $"the renewal advice for certificate '{name}' could not be saved ({ex.Message}); using it for this check only", ex);
            }
        }

        return AcmeRenewalSchedule.IsDue(advice, current.NotBefore, current.NotAfter, now, _options.RenewAtRemainingFraction, _options.CheckInterval);
    }

    /// <summary>Asks the CA for its renewal advice; a CA that cannot answer never throws here (the lifetime rule applies until it can).</summary>
    private async Task<AcmeRenewalAdvice> FetchAdviceAsync(CertificateRecord current, AcmeRenewalAdvice? previous, DateTimeOffset now, CancellationToken ct)
    {
        try
        {
            var info = await _runner.GetRenewalInfoAsync(Directory, current.ChainPem, ct).ConfigureAwait(false);
            if (info is null)
            {
                _log.Write(MtaLogLevel.Debug, "acme", $"the CA offers no renewal information; certificate '{current.Name}' renews by its lifetime");
                return AcmeRenewalSchedule.FromDirectoryWithoutRenewalInfo(current.Thumbprint, now);
            }

            var advice = AcmeRenewalSchedule.FromInfo(current.Thumbprint, info, previous, now, _random);
            if (previous?.RenewAt != advice.RenewAt)
            {
                _log.Write(MtaLogLevel.Information, "acme",
                    $"the CA suggests renewing certificate '{current.Name}' between {info.WindowStart:u} and {info.WindowEnd:u}; planned for {advice.RenewAt:u}" + (info.ExplanationUrl is null ? "" : $" ({info.ExplanationUrl})"));
            }

            return advice;
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            var failed = AcmeRenewalSchedule.FromFailure(current.Thumbprint, previous, now, ex.Message, transient: ex is AcmeException { Transient: true } or HttpRequestException or TimeoutException);
            _log.Write(MtaLogLevel.Warning, "acme", $"renewal information for certificate '{current.Name}' is unavailable ({ex.Message}); using the {(previous is { HasWindow: true } ? "earlier window" : "lifetime rule")}, asking again at {failed.NextCheckAt:u}", ex);
            return failed;
        }
    }

    private async Task<bool> RenewAsync(string name, IReadOnlyList<string> domains, bool force, CancellationToken ct)
    {
        var now = _clock.UtcNow;
        var current = (await _config.GetCertificatesAsync(ct).ConfigureAwait(false))
            .Where(c => c.Active && c.Source == "acme" && c.Name == name)
            .OrderByDescending(c => c.NotAfter).FirstOrDefault();
        var renewal = (await _config.GetAcmeRenewalsAsync(ct).ConfigureAwait(false)).FirstOrDefault(r => r.CertificateName == name);
        if (!force)
        {
            if (!await IsDueAsync(name, current, domains, renewal, now, ct).ConfigureAwait(false))
            {
                return false;
            }
        }

        if (!force && renewal?.NextAttemptAt is { } next && next > now)
        {
            return false;
        }

        var lease = await _config.TryAcquireLeaseAsync($"acme-renew:{name}", _owner, LeaseDuration, now, ct).ConfigureAwait(false);
        if (lease is null)
        {
            _log.Write(MtaLogLevel.Debug, "acme", $"another replica is renewing '{name}'");
            return false;
        }

        try
        {
            // The row read before the CA was asked may be stale by now (another replica may have failed an order and set a back-off in the meantime): read it again under the lease.
            renewal = (await _config.GetAcmeRenewalsAsync(ct).ConfigureAwait(false)).FirstOrDefault(r => r.CertificateName == name);
            if (!force && renewal?.NextAttemptAt is { } backoff && backoff > now)
            {
                return false;
            }

            var challenge = ChooseChallenge(domains);
            if (challenge == AcmeChallengeType.Http01 && await _http!.WaitUntilReadyAsync(ListenerStartWait, ct).ConfigureAwait(false) is { } unavailable)
            {
                // Asking the CA to connect to a port nobody listens on is a failed validation there (rate limited); say what is wrong here instead.
                throw new AcmeListenerUnavailableException(unavailable);
            }

            _log.Write(MtaLogLevel.Information, "acme", $"ordering certificate '{name}' for {string.Join(", ", domains)} ({(challenge == AcmeChallengeType.Http01 ? "HTTP-01" : "DNS-01")}, {Directory})");
            await _config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord(name, "ordering", now, null, renewal?.Failures ?? 0, renewal?.LastError, null, renewal?.AriJson), ct).ConfigureAwait(false);

            var account = await _config.GetAcmeAccountAsync(Directory, ct).ConfigureAwait(false);
            string? accountKey = account is null ? null : Encoding.UTF8.GetString(_protector.Unprotect(account.AccountKeyProtected, SecretPurposes.AcmeAccountKey));
            // The account is stored the moment the CA has created it, not after the order: a failed order (a DNS record that never appears) must
            // not strand an account whose key is lost, because every retry would then register another one and CAs rate-limit registrations.
            bool accountSaved = account is not null;
            async Task SaveAccountAsync(AcmeAccountCreated created, CancellationToken token)
            {
                await _config.UpsertAcmeAccountAsync(new AcmeAccountRecord(Ids.New(), Directory, _options.Email ?? "",
                    _protector.Protect(Encoding.UTF8.GetBytes(created.AccountKeyPem), SecretPurposes.AcmeAccountKey), created.AccountUrl, now), token).ConfigureAwait(false);
                accountSaved = true;
            }

            // A certificate that shares a name with the order is the one this order renews: say so (ARI "replaces"); the runner does it where the CA supports it.
            string? replaces = current is not null && current.Subjects.Intersect(domains, StringComparer.OrdinalIgnoreCase).Any() ? current.ChainPem : null;
            var request = new AcmeOrderRequest(Directory, _options.Email ?? "", domains, accountKey, _options.PropagationDelay, SaveAccountAsync, replaces,
                challenge, _http, name, accountKey is null ? _options.EabKeyId : null, accountKey is null ? ReadEabHmacKey() : null);
            var issued = await _runner.IssueAsync(request, _dns ?? NoDnsChallengeProvider.Instance, ct).ConfigureAwait(false);
            if (!accountSaved)
            {
                // A runner that does not report accounts as they are created (the fake in tests): store it with the result.
                await SaveAccountAsync(new AcmeAccountCreated(issued.AccountKeyPem, issued.AccountUrl), ct).ConfigureAwait(false);
            }

            var leaf = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();
            leaf.ImportFromPem(issued.ChainPem);
            var first = leaf[0];
            // A renewal replaces the row of the certificate it renews (the name is unique), so the old one is not left active next to it.
            var record = new CertificateRecord(
                current?.Id ?? Ids.New(), name, domains.Select(d => d.ToLowerInvariant()).ToList(), first.NotBefore.ToUniversalTime(), first.NotAfter.ToUniversalTime(),
                issued.ChainPem, _protector.Protect(issued.PrivateKeyPkcs8, SecretPurposes.TlsPrivateKey), "acme", first.Thumbprint, Active: true,
                Version: _clock.UtcNow.ToUnixTimeMilliseconds(), CreatedAt: now);
            await _config.UpsertCertificateAsync(record, ct).ConfigureAwait(false);
            await _config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord(name, "issued", now, null, 0, null, null, null), ct).ConfigureAwait(false);
            _log.Write(MtaLogLevel.Information, "acme", $"certificate '{name}' issued, valid until {record.NotAfter:u}");
            return true;
        }
        catch (AcmeListenerUnavailableException ex) when (!ct.IsCancellationRequested)
        {
            // The CA was not asked: record why, count it, and try again soon (the listener retries its bind every minute).
            int failures = (renewal?.Failures ?? 0) + 1;
            var retryAt = now + ListenerRetry;
            await _config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord(name, "failed", now, retryAt, failures, ex.Message, null, renewal?.AriJson), ct).ConfigureAwait(false);
            _log.Write(MtaLogLevel.Error, "acme", $"certificate order for '{name}' not started (attempt {failures}); next try {retryAt:u}: {ex.Message}");
            return false;
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            // Any failure of the attempt (the CA refusing, unreachable or too slow, the DNS provider failing, an unreadable chain) is recorded and
            // backed off, never thrown: an exception escaping here would end the renewal loop until the next restart.
            int failures = (renewal?.Failures ?? 0) + 1;
            var retryAt = now + Backoff(failures);
            await _config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord(name, "failed", now, retryAt, failures, ex.Message, null, renewal?.AriJson), ct).ConfigureAwait(false);
            _log.Write(MtaLogLevel.Error, "acme", $"certificate order for '{name}' failed (attempt {failures}); next try {retryAt:u}", ex);
            return false;
        }
        finally
        {
            await _config.ReleaseLeaseAsync($"acme-renew:{name}", _owner, CancellationToken.None).ConfigureAwait(false);
        }
    }
}
