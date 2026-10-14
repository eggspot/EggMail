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

    private readonly IConfigStore _config;
    private readonly ISecretProtector _protector;
    private readonly IAcmeOrderRunner _runner;
    private readonly IDnsChallengeProvider _dns;
    private readonly AcmeSection _options;
    private readonly IClock _clock;
    private readonly IMtaLog _log;
    private readonly Func<double> _random;
    private readonly string _owner = "acme-" + Ids.ToCompact(Ids.New())[..12];

    /// <param name="random">Position inside a CA's renewal window (a number in [0, 1)); tests fix it.</param>
    public AcmeRenewalService(IConfigStore config, ISecretProtector protector, IAcmeOrderRunner runner, IDnsChallengeProvider dns, AcmeSection options, IClock? clock = null, IMtaLog? log = null,
        Func<double>? random = null)
    {
        _random = random ?? Random.Shared.NextDouble;
        _config = config;
        _protector = protector;
        _runner = runner;
        _dns = dns;
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
        using var timer = new PeriodicTimer(_options.CheckInterval);
        try
        {
            do
            {
                try
                {
                    await CheckOnceAsync(ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log.Write(MtaLogLevel.Error, "acme", "renewal check failed", ex);
                }
            }
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
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
            issued |= await RenewAsync(_options.CertificateName, _options.Domains, force: false, ct).ConfigureAwait(false);
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
        var wanted = domains.Select(d => d.Trim().ToLowerInvariant()).Distinct().OrderBy(d => d, StringComparer.Ordinal).ToList();
        var configured = _options.Domains.Select(d => d.ToLowerInvariant()).OrderBy(d => d, StringComparer.Ordinal).ToList();
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
    /// CA gives some, else the lifetime rule (<see cref="AcmeRenewalSchedule"/>). Asking the CA is persisted in the renewal row, which is returned.
    /// </summary>
    private async Task<(bool Due, AcmeRenewalRecord? Renewal)> IsDueAsync(string name, CertificateRecord? current, IReadOnlyList<string> domains, AcmeRenewalRecord? renewal, DateTimeOffset now, CancellationToken ct)
    {
        if (current is null || NamesDiffer(current, domains))
        {
            return (true, renewal);
        }

        if (!_options.UseRenewalInfo)
        {
            return (NeedsRenewal(current, domains, now, _options.RenewAtRemainingFraction), renewal);
        }

        var advice = AcmeRenewalAdvice.Parse(renewal?.AriJson, current.Thumbprint);
        if (AcmeRenewalSchedule.ShouldCheck(advice, now))
        {
            advice = await FetchAdviceAsync(current, advice, now, ct).ConfigureAwait(false);
            renewal = (renewal ?? new AcmeRenewalRecord(name, "issued", null, null, 0, null, null, null)) with { AriJson = advice.ToJson() };
            await _config.UpsertAcmeRenewalAsync(renewal, ct).ConfigureAwait(false);
        }

        return (AcmeRenewalSchedule.IsDue(advice, current.NotBefore, current.NotAfter, now, _options.RenewAtRemainingFraction), renewal);
    }

    /// <summary>Asks the CA for its renewal advice; a CA that cannot answer never throws here (the lifetime rule applies until it can).</summary>
    private async Task<AcmeRenewalAdvice> FetchAdviceAsync(CertificateRecord current, AcmeRenewalAdvice? previous, DateTimeOffset now, CancellationToken ct)
    {
        try
        {
            var info = await _runner.GetRenewalInfoAsync(_options.DirectoryUrl, current.ChainPem, ct).ConfigureAwait(false);
            if (info is null)
            {
                _log.Write(MtaLogLevel.Debug, "acme", $"the CA offers no renewal information; certificate '{current.Name}' renews by its lifetime");
                return AcmeRenewalSchedule.FromFailure(current.Thumbprint, previous, now, "", unsupported: true);
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
            _log.Write(MtaLogLevel.Warning, "acme", $"renewal information for certificate '{current.Name}' is unavailable ({ex.Message}); using the lifetime rule", ex);
            return AcmeRenewalSchedule.FromFailure(current.Thumbprint, previous, now, ex.Message);
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
            bool due;
            (due, renewal) = await IsDueAsync(name, current, domains, renewal, now, ct).ConfigureAwait(false);
            if (!due)
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
            _log.Write(MtaLogLevel.Information, "acme", $"ordering certificate '{name}' for {string.Join(", ", domains)}");
            await _config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord(name, "ordering", now, null, renewal?.Failures ?? 0, renewal?.LastError, null, renewal?.AriJson), ct).ConfigureAwait(false);

            var account = await _config.GetAcmeAccountAsync(_options.DirectoryUrl, ct).ConfigureAwait(false);
            string? accountKey = account is null ? null : Encoding.UTF8.GetString(_protector.Unprotect(account.AccountKeyProtected, SecretPurposes.AcmeAccountKey));
            // The account is stored the moment the CA has created it, not after the order: a failed order (a DNS record that never appears) must
            // not strand an account whose key is lost, because every retry would then register another one and CAs rate-limit registrations.
            bool accountSaved = account is not null;
            async Task SaveAccountAsync(AcmeAccountCreated created, CancellationToken token)
            {
                await _config.UpsertAcmeAccountAsync(new AcmeAccountRecord(Ids.New(), _options.DirectoryUrl, _options.Email ?? "",
                    _protector.Protect(Encoding.UTF8.GetBytes(created.AccountKeyPem), SecretPurposes.AcmeAccountKey), created.AccountUrl, now), token).ConfigureAwait(false);
                accountSaved = true;
            }

            // A certificate that shares a name with the order is the one this order renews: say so (ARI "replaces"); the runner does it where the CA supports it.
            string? replaces = current is not null && current.Subjects.Intersect(domains, StringComparer.OrdinalIgnoreCase).Any() ? current.ChainPem : null;
            var request = new AcmeOrderRequest(_options.DirectoryUrl, _options.Email ?? "", domains, accountKey, _options.PropagationDelay, SaveAccountAsync, replaces);
            var issued = await _runner.IssueAsync(request, _dns, ct).ConfigureAwait(false);
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
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            // Any failure of the attempt (the CA refusing, unreachable or too slow, the DNS provider failing, an unreadable chain) is recorded and
            // backed off, never thrown: an exception escaping here would end the renewal loop until the next restart.
            int failures = (renewal?.Failures ?? 0) + 1;
            var retryAt = now + Backoff(failures);
            await _config.UpsertAcmeRenewalAsync(new AcmeRenewalRecord(name, "failed", now, retryAt, failures, ex.Message, null, null), ct).ConfigureAwait(false);
            _log.Write(MtaLogLevel.Error, "acme", $"certificate order for '{name}' failed (attempt {failures}); next try {retryAt:u}", ex);
            return false;
        }
        finally
        {
            await _config.ReleaseLeaseAsync($"acme-renew:{name}", _owner, CancellationToken.None).ConfigureAwait(false);
        }
    }
}
