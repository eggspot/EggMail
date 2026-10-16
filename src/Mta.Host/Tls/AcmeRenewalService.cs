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
    private string CaDirectoryUrl => _options.EffectiveDirectoryUrl() ?? throw new AcmeException($"Acme:Directory '{_options.Directory}' is neither a known CA name (LetsEncrypt, LetsEncryptStaging, ZeroSsl) nor an http(s) URL.");

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
    // Random, not a prefix of Ids.New(): the first 12 hex digits of a version 7 id are its millisecond timestamp, so two replicas created in the same millisecond would share an
    // owner name and both be let into the renewal lease.
    private readonly string _owner = "acme-" + Guid.NewGuid().ToString("N")[..16];

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

    /// <summary>The lease that makes one replica at a time order the certificate called <paramref name="certificateName"/>.</summary>
    internal static string LeaseName(string certificateName) => $"acme-renew:{certificateName}";

    /// <summary>The longest a CA's <c>Retry-After</c> postpones the next attempt (a rate limit can ask for days; a day keeps a wrong or hostile value harmless).</summary>
    public static readonly TimeSpan MaxRetryAfter = TimeSpan.FromDays(1);

    /// <summary>
    /// The wait after the <paramref name="failures"/>-th failure in a row: the back-off, or what the CA asked for in <c>Retry-After</c> (up to <see cref="MaxRetryAfter"/>)
    /// when that is longer, since asking earlier cannot work and a rate-limited client that keeps asking is the one that stays limited.
    /// </summary>
    internal static TimeSpan WaitAfterFailure(int failures, Exception error)
    {
        var wait = Backoff(failures);
        if (error is AcmeException { RetryAfter: { } asked } && asked > wait)
        {
            wait = asked < MaxRetryAfter ? asked : MaxRetryAfter;
        }

        return wait;
    }

    /// <summary>
    /// Is what the CA sent the answer to this order? The leaf (first certificate) must go with the private key we hold, cover every name ordered (the runner also
    /// refuses an expired one; it judges by its own clock): a CA bug or a mixed-up answer must end as a recorded failure with the old certificate still served, never as a
    /// stored certificate that fails every handshake (or is served for names it does not carry).
    /// </summary>
    private static void VerifyIssued(AcmeIssuedCertificate issued, IReadOnlyList<string> domains)
    {
        var chain = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection();
        try
        {
            chain.ImportFromPem(issued.ChainPem);
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            throw new AcmeException($"The certificate chain the CA sent cannot be read: {ex.Message}", ex);
        }

        if (chain.Count == 0)
        {
            throw new AcmeException("The CA sent no certificate.");
        }

        var leaf = chain[0];
        var covered = CertificateMaterial.SubjectsOf(leaf);
        if (domains.FirstOrDefault(d => !AcmeNames.IsCovered(covered, d)) is { } missing)
        {
            throw new AcmeException($"The CA issued a certificate that does not cover '{missing}' (it covers {string.Join(", ", covered)}).");
        }

        try
        {
            using var withKey = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(leaf.ExportCertificatePem(), System.Security.Cryptography.PemEncoding.WriteString("PRIVATE KEY", issued.PrivateKeyPkcs8));
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or ArgumentException)
        {
            throw new AcmeException("The private key of the order does not belong to the certificate the CA sent.", ex);
        }
    }

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
            // Only certificates that CheckOnceAsync retries count: a failed record of names nobody retries must not keep every replica polling.
            var retried = AcmeFailureCategory.RetriedNames(_options, await _config.GetCertificatesAsync(ct).ConfigureAwait(false));
            foreach (var row in await _config.GetAcmeRenewalsAsync(ct).ConfigureAwait(false))
            {
                if (row.Status == "failed" && row.NextAttemptAt is { } next && retried.Contains(row.CertificateName))
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
            var info = await _runner.GetRenewalInfoAsync(CaDirectoryUrl, current.ChainPem, ct).ConfigureAwait(false);
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
            var failed = AcmeRenewalSchedule.FromFailure(current.Thumbprint, previous, now, ex.Message, transient: ex is AcmeException { Transient: true } or HttpRequestException or TimeoutException,
                (ex as AcmeException)?.RetryAfter);
            _log.Write(MtaLogLevel.Warning, "acme", $"renewal information for certificate '{current.Name}' is unavailable ({ex.Message}); using the {(previous is { HasWindow: true } ? "earlier window" : "lifetime rule")}, asking again at {failed.NextCheckAt:u}", ex);
            return failed;
        }
    }

    /// <summary>Renews the lease with its fencing token; false (and a Warning saying <paramref name="what"/>) when another replica took it over.</summary>
    private async Task<bool> StillHoldsLeaseAsync(string name, LeaseRecord lease, string what, CancellationToken ct)
    {
        if (await _config.RenewLeaseAsync(LeaseName(name), _owner, lease.FencingToken, LeaseDuration, _clock.UtcNow, ct).ConfigureAwait(false))
        {
            return true;
        }

        _log.Write(MtaLogLevel.Warning, "acme", $"the renewal lease of '{name}' was taken over by another replica; {what}, and nothing is recorded for it");
        return false;
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

        var lease = await _config.TryAcquireLeaseAsync(LeaseName(name), _owner, LeaseDuration, now, ct).ConfigureAwait(false);
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

            _log.Write(MtaLogLevel.Information, "acme", $"ordering certificate '{name}' for {string.Join(", ", domains)} ({(challenge == AcmeChallengeType.Http01 ? "HTTP-01" : "DNS-01")}, {CaDirectoryUrl})");
            await _config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord(name, "ordering", now, null, renewal?.Failures ?? 0, renewal?.LastError, null, renewal?.AriJson), ct).ConfigureAwait(false);

            var account = await _config.GetAcmeAccountAsync(CaDirectoryUrl, ct).ConfigureAwait(false);
            string? accountKey = account is null ? null : Encoding.UTF8.GetString(_protector.Unprotect(account.AccountKeyProtected, SecretPurposes.AcmeAccountKey));
            // The account is stored the moment the CA has created it, not after the order: a failed order (a DNS record that never appears) must
            // not strand an account whose key is lost, because every retry would then register another one and CAs rate-limit registrations.
            // A replacement of an account the CA forgot takes over the row of the old one, so the directory never has two.
            bool accountSaved = account is not null;
            async Task SaveAccountAsync(AcmeAccountCreated created, CancellationToken token)
            {
                await _config.UpsertAcmeAccountAsync(new AcmeAccountRecord(account?.Id ?? Ids.New(), CaDirectoryUrl, _options.Email ?? "",
                    _protector.Protect(Encoding.UTF8.GetBytes(created.AccountKeyPem), SecretPurposes.AcmeAccountKey), created.AccountUrl, now), token).ConfigureAwait(false);
                accountSaved = true;
            }

            // A certificate that shares a name with the order is the one this order renews: say so (ARI "replaces"); the runner does it where the CA supports it.
            string? replaces = current is not null && current.Subjects.Intersect(domains, StringComparer.OrdinalIgnoreCase).Any() ? current.ChainPem : null;
            AcmeOrderRequest OrderFor(string? key) => new(CaDirectoryUrl, _options.Email ?? "", domains, key, _options.PropagationDelay, SaveAccountAsync, replaces,
                challenge, _http, name, key is null ? _options.EabKeyId : null, key is null ? ReadEabHmacKey() : null);
            AcmeIssuedCertificate issued;
            try
            {
                issued = await _runner.IssueAsync(OrderFor(accountKey), _dns ?? NoDnsChallengeProvider.Instance, ct).ConfigureAwait(false);
            }
            catch (AcmeException ex) when (ex.AccountUnknown && accountKey is not null)
            {
                // The CA has no account for the stored key (a test CA that was reset, a CA that lost its database): the key is useless and no order can ever succeed with it.
                // Register a new account once, in place of the old one; any other refusal of the account (deactivated, unauthorized) is for the operator.
                _log.Write(MtaLogLevel.Warning, "acme", $"the CA does not know the stored ACME account for {CaDirectoryUrl}; registering a new one for certificate '{name}'");
                accountKey = null;
                accountSaved = false;
                issued = await _runner.IssueAsync(OrderFor(null), _dns ?? NoDnsChallengeProvider.Instance, ct).ConfigureAwait(false);
            }

            if (!accountSaved)
            {
                // A runner that does not report accounts as they are created (the fake in tests): store it with the result.
                await SaveAccountAsync(new AcmeAccountCreated(issued.AccountKeyPem, issued.AccountUrl), ct).ConfigureAwait(false);
            }

            VerifyIssued(issued, domains);

            // The order can outlast the lease (a stalled process, a CA that took minutes): when it expired and another replica took over, that replica's result stands and
            // this one is dropped without touching the renewal row (the other replica's status is the truth). Renewing here also extends the lease over the write.
            if (!await _config.RenewLeaseAsync(LeaseName(name), _owner, lease.FencingToken, LeaseDuration, _clock.UtcNow, ct).ConfigureAwait(false))
            {
                _log.Write(MtaLogLevel.Warning, "acme", $"the renewal lease of '{name}' was taken over by another replica while the CA was issuing; the certificate of this order is discarded");
                return false;
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
            if (!await StillHoldsLeaseAsync(name, lease, "the order was not started", ct).ConfigureAwait(false))
            {
                return false;
            }

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
            // The renewal row belongs to whoever holds the lease: a replica that lost it (its order outlasted 20 minutes) must not write its failure over the result
            // of the replica that took over.
            if (!await StillHoldsLeaseAsync(name, lease, $"the order failed ({ex.Message})", ct).ConfigureAwait(false))
            {
                return false;
            }

            int failures = (renewal?.Failures ?? 0) + 1;
            var retryAt = now + WaitAfterFailure(failures, ex);
            await _config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord(name, "failed", now, retryAt, failures, ex.Message, null, renewal?.AriJson), ct).ConfigureAwait(false);
            _log.Write(MtaLogLevel.Error, "acme", $"certificate order for '{name}' failed (attempt {failures}); next try {retryAt:u}", ex);
            return false;
        }
        finally
        {
            await _config.ReleaseLeaseAsync(LeaseName(name), _owner, CancellationToken.None).ConfigureAwait(false);
        }
    }
}
