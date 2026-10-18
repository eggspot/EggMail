using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Mta.Core;
using Mta.Dkim;
using Mta.Host.Domains;
using Mta.Policy;
using Mta.Storage;
using StoredDkimKey = Mta.Storage.DkimKeyRecord;

namespace Mta.Host.Api;

/// <summary>What the last check found for one record (persisted per record in the config store; the next check replaces it).</summary>
public sealed record RecordCheckSnapshot(DomainRecordStatus Status, string? Found);

/// <summary>The outcome of the last check of a domain: per record, keyed by <c>type|host</c>.</summary>
public sealed record DomainCheckSnapshot(DateTimeOffset CheckedAt, IReadOnlyDictionary<string, RecordCheckSnapshot> Records)
{
    public static string KeyOf(string type, string host) => type.ToUpperInvariant() + "|" + host.ToLowerInvariant();
}

/// <summary>
/// Domain verification (design section 8): a background loop that checks the domains that are due (<see cref="IConfigStore.GetDomainsDueForCheckAsync"/>),
/// and the same check for "Verify now". A check looks the planned records up in DNS (<see cref="DomainChecker"/>), applies the result to the
/// state machine (<see cref="VerificationSchedule.Apply"/>: Pending, Verifying, Verified, TemporaryFailure, Failed, and pausing sending after the
/// grace period), persists it, and switches signing to a rotated DKIM key once that key's record is published.
/// <para>The per-record result of each check is persisted (<see cref="IRuntimeStateStore.ReplaceDomainRecordChecksAsync"/>), so after a restart or on another replica a
/// domain shows what was really found. A check, and a DKIM rotation, run under a lease of the config store (<see cref="TryLockAsync"/>), so replicas never check or rotate the same
/// domain at the same time.</para>
/// <para>Only records of the key that signs are <i>required</i>; a rotation's new key, and a retired key during its 7-day grace, are checked as advice
/// so publishing the next key late (or removing the old one) never degrades a verified domain.</para>
/// </summary>
public sealed class DomainVerificationService : BackgroundService
{
    private readonly IStorage _storage;
    private readonly DomainChecker _checker;
    private readonly VerificationSchedule _schedule;
    private readonly DomainRecordOptions _recordOptions;
    private readonly ApiOptions _options;
    private readonly IClock _clock;
    private readonly ILogger<DomainVerificationService> _logger;
    private readonly HashSet<Guid> _inFlight = [];
    private readonly string _owner = "domain-verification-" + Guid.NewGuid().ToString("N");

    /// <summary>How long a check or rotation holds its lease; a replica that dies mid-check frees the domain after this.</summary>
    public static readonly TimeSpan LockDuration = TimeSpan.FromMinutes(5);

    public DomainVerificationService(
        IStorage storage,
        DomainChecker checker,
        VerificationSchedule schedule,
        DomainRecordOptions recordOptions,
        ApiOptions options,
        IClock clock,
        ILogger<DomainVerificationService> logger)
    {
        _storage = storage;
        _checker = checker;
        _schedule = schedule;
        _recordOptions = recordOptions;
        _options = options;
        _clock = clock;
        _logger = logger;
    }

    public VerificationSchedule Schedule => _schedule;

    public DomainRecordOptions RecordOptions => _recordOptions;

    private IConfigStore Config => _storage.Config;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(_options.VerificationPollInterval);
        try
        {
            do
            {
                try
                {
                    await RunDueChecksAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "Domain verification pass failed; it will be retried");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>Checks every domain that is due now. Returns how many were checked.</summary>
    public async Task<int> RunDueChecksAsync(CancellationToken ct)
    {
        var due = await Config.GetDomainsDueForCheckAsync(_clock.UtcNow, _options.VerificationBatchSize, ct).ConfigureAwait(false);
        int checkedCount = 0;
        await Parallel.ForEachAsync(due, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, _options.VerificationMaxParallel), CancellationToken = ct }, async (domain, token) =>
        {
            try
            {
                await using IAsyncDisposable? held = await TryLockAsync(domain.Id, token).ConfigureAwait(false);
                if (held is null)
                {
                    return;   // being checked by this process or another replica
                }

                // The list was read before the lock: another replica may have checked the domain meanwhile (and moved its next check on).
                DomainRecord? current = await Config.GetDomainAsync(domain.Id, token).ConfigureAwait(false);
                if (current is null || current.NextCheckAt is not { } next || next > _clock.UtcNow)
                {
                    return;
                }

                if (await CheckAsync(domain.Id, token).ConfigureAwait(false) is not null)
                {
                    Interlocked.Increment(ref checkedCount);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Verification of domain {Domain} failed", domain.Name);
            }
        }).ConfigureAwait(false);
        return checkedCount;
    }

    /// <summary>
    /// Reserves the right to check or rotate a domain, in this process (concurrent "Verify now" clicks) and across replicas (a lease of the config store, so two replicas never
    /// check or rotate the same domain at once). Null when someone else holds it. Disposing the result releases both.
    /// </summary>
    public async ValueTask<IAsyncDisposable?> TryLockAsync(Guid domainId, CancellationToken ct)
    {
        lock (_inFlight)
        {
            if (!_inFlight.Add(domainId))
            {
                return null;
            }
        }

        try
        {
            if (await Config.TryAcquireLeaseAsync(LeaseName(domainId), _owner, LockDuration, _clock.UtcNow, ct).ConfigureAwait(false) is null)
            {
                Leave(domainId);
                return null;
            }
        }
        catch
        {
            Leave(domainId);
            throw;
        }

        return new DomainLock(this, domainId);
    }

    private static string LeaseName(Guid domainId) => "domain-verification:" + domainId.ToString("N");

    private void Leave(Guid domainId)
    {
        lock (_inFlight)
        {
            _inFlight.Remove(domainId);
        }
    }

    private sealed class DomainLock(DomainVerificationService owner, Guid domainId) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            try
            {
                await owner.Config.ReleaseLeaseAsync(LeaseName(domainId), owner._owner, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                owner._logger.LogWarning(ex, "Could not release the lease of domain {DomainId}; it expires on its own", domainId);
            }
            finally
            {
                owner.Leave(domainId);
            }
        }
    }

    /// <summary>The per-record results of the last check of a domain, or null if it was never checked (or only before results were persisted).</summary>
    public async ValueTask<DomainCheckSnapshot?> GetSnapshotAsync(Guid domainId, CancellationToken ct)
    {
        var rows = await Config.GetDomainRecordChecksAsync(domainId, ct).ConfigureAwait(false);
        if (rows.Count == 0)
        {
            return null;
        }

        return new DomainCheckSnapshot(rows.Max(r => r.CheckedAt), rows.ToDictionary(r => r.RecordKey, r => new RecordCheckSnapshot(ParseStatus(r.Status), r.Found), StringComparer.Ordinal));
    }

    /// <summary>The status word of the API (and of the stored check result) for a record status.</summary>
    public static string StatusWord(DomainRecordStatus status) => status switch
    {
        DomainRecordStatus.Ok => "ok",
        DomainRecordStatus.Missing => "missing",
        DomainRecordStatus.Invalid => "invalid",
        DomainRecordStatus.Mismatch => "mismatch",
        _ => "pending",
    };

    private static DomainRecordStatus ParseStatus(string word) => word switch
    {
        "ok" => DomainRecordStatus.Ok,
        "missing" => DomainRecordStatus.Missing,
        "invalid" => DomainRecordStatus.Invalid,
        "mismatch" => DomainRecordStatus.Mismatch,
        _ => DomainRecordStatus.Pending,
    };

    /// <summary>The DKIM keys that must currently be published: the signing key, a pending (rotated-in) key, and retired keys during their grace.</summary>
    public IReadOnlyList<StoredDkimKey> PublishedKeys(IReadOnlyList<StoredDkimKey> keys, DateTimeOffset now) => PublishedKeys(keys, now, _options.DkimRetirementGrace);

    public static IReadOnlyList<StoredDkimKey> PublishedKeys(IReadOnlyList<StoredDkimKey> keys, DateTimeOffset now, TimeSpan retirementGrace) =>
        keys.Where(k => k.Active || k.RetiredAt is null || now < k.RetiredAt.Value + retirementGrace).OrderBy(k => k.CreatedAt).ThenBy(k => k.Id).ToList();

    /// <summary>The records the customer has to publish for <paramref name="domain"/> (required ones decide verification; the rest is advice).</summary>
    public IReadOnlyList<ExpectedDomainRecord> PlanRecords(DomainRecord domain, IReadOnlyList<StoredDkimKey> keys, DateTimeOffset now, bool inboundEnabled) =>
        PlanRecords(domain, keys, now, _recordOptions, _options.DkimRetirementGrace, inboundEnabled);

    /// <summary>The records of <paramref name="domain"/> including the inbound MX while inbound mail is enabled for it (read from the domain's inbound settings).</summary>
    public async ValueTask<IReadOnlyList<ExpectedDomainRecord>> PlanRecordsAsync(DomainRecord domain, IReadOnlyList<StoredDkimKey> keys, DateTimeOffset now, CancellationToken ct)
    {
        InboundDomainSettings? inbound = await ((IInboundConfigStore)Config).GetSettingsAsync(domain.Id, ct).ConfigureAwait(false);
        return PlanRecords(domain, keys, now, inbound is { Enabled: true });
    }

    public static IReadOnlyList<ExpectedDomainRecord> PlanRecords(DomainRecord domain, IReadOnlyList<StoredDkimKey> keys, DateTimeOffset now, DomainRecordOptions recordOptions, TimeSpan retirementGrace, bool inboundEnabled)
    {
        var published = PublishedKeys(keys, now, retirementGrace);
        var plan = DomainRecordPlanner.Plan(domain.Name, published.Select(k => new DomainDkimKey(k.Selector, k.PublicKeyBase64)), recordOptions, inboundEnabled);
        var signing = published.Where(k => k.Active).Select(k => DkimKeyTools.GetDnsName(domain.Name, k.Selector).ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);
        if (signing.Count == 0 && published.Count > 0)
        {
            // No key signs yet (only possible mid-repair): the newest one decides.
            signing.Add(DkimKeyTools.GetDnsName(domain.Name, published[^1].Selector).ToLowerInvariant());
        }

        return plan.Select(r => r.Purpose == DomainRecordPurpose.Dkim && !signing.Contains(r.Host.ToLowerInvariant()) ? r with { Required = false } : r).ToList();
    }

    /// <summary>Checks the domain now, persists the new state and returns it; null if the domain no longer exists.</summary>
    public async Task<DomainRecord?> CheckAsync(Guid domainId, CancellationToken ct)
    {
        DomainRecord? domain = await Config.GetDomainAsync(domainId, ct).ConfigureAwait(false);
        if (domain is null)
        {
            return null;
        }

        var keys = await Config.GetDkimKeysAsync(domain.Id, ct).ConfigureAwait(false);
        DateTimeOffset started = _clock.UtcNow;
        var plan = await PlanRecordsAsync(domain, keys, started, ct).ConfigureAwait(false);
        DomainCheckResult result;
        try
        {
            result = await _checker.CheckAsync(plan, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "DNS check of {Domain} failed unexpectedly; treating it as a temporary DNS failure", domain.Name);
            result = new DomainCheckResult(plan.Select(r => new DomainRecordCheck(r, DomainRecordStatus.Pending, null)).ToList(), VerificationCheckResult.DnsTemporaryFailure, "DNS lookup failed");
        }

        // The domain may have changed or vanished while DNS was being queried: apply the result to the fresh row.
        DomainRecord? fresh = await Config.GetDomainAsync(domainId, ct).ConfigureAwait(false);
        if (fresh is null)
        {
            return null;
        }

        DateTimeOffset now = _clock.UtcNow;
        DomainRecord updated = _schedule.Apply(fresh, result.Result, now, result.Error);
        if (result.Result != VerificationCheckResult.DnsTemporaryFailure)
        {
            var returnPath = result.Records.FirstOrDefault(r => r.Expected.Purpose == DomainRecordPurpose.ReturnPath);
            updated = updated with { ReturnPathVerified = returnPath?.Status == DomainRecordStatus.Ok };
        }

        if (updated.ReturnPathHost is null && !string.IsNullOrWhiteSpace(_recordOptions.BounceDomain))
        {
            updated = updated with { ReturnPathHost = DomainRecordPlanner.ReturnPathHost(updated.Name, _recordOptions) };
        }

        await Config.UpsertDomainAsync(updated, ct).ConfigureAwait(false);

        Mta.Host.Submission.DomainChangeSignal.Bump();
        if (result.Result != VerificationCheckResult.DnsTemporaryFailure)
        {
            await ActivateRotatedKeyAsync(updated, keys, result, now, ct).ConfigureAwait(false);
        }

        await PersistRecordChecksAsync(domainId, result, now, ct).ConfigureAwait(false);

        if (updated.Status != fresh.Status)
        {
            _logger.LogInformation("Domain {Domain} is now {Status} (was {Previous}){Paused}", updated.Name, updated.Status, fresh.Status, updated.SendingPaused ? "; sending paused" : "");
        }

        return updated;
    }

    /// <summary>
    /// Stores what the check found for each record. After a DNS outage a record the check could not look up keeps its previous result (an outage never changes the state),
    /// so only a record that was really looked up replaces what was known.
    /// </summary>
    private async Task PersistRecordChecksAsync(Guid domainId, DomainCheckResult result, DateTimeOffset now, CancellationToken ct)
    {
        IReadOnlyDictionary<string, DomainRecordCheckRecord> previous = result.Result == VerificationCheckResult.DnsTemporaryFailure
            ? (await Config.GetDomainRecordChecksAsync(domainId, ct).ConfigureAwait(false)).ToDictionary(r => r.RecordKey, StringComparer.Ordinal)
            : new Dictionary<string, DomainRecordCheckRecord>();
        var rows = new List<DomainRecordCheckRecord>(result.Records.Count);
        foreach (DomainRecordCheck r in result.Records)
        {
            string key = DomainCheckSnapshot.KeyOf(r.Expected.Type, r.Expected.Host);
            rows.Add(r.Status == DomainRecordStatus.Pending && previous.TryGetValue(key, out DomainRecordCheckRecord? known)
                ? known
                : new DomainRecordCheckRecord(domainId, key, StatusWord(r.Status), TruncateFound(r.Found), now));
        }

        await Config.ReplaceDomainRecordChecksAsync(domainId, rows, ct).ConfigureAwait(false);
    }

    /// <summary>The most of what DNS returned that is kept per record: a hostile zone can publish a record of any size, and the text is only shown next to the expected value.</summary>
    public const int MaxFoundLength = 2048;

    private static string? TruncateFound(string? found) =>
        found is null || found.Length <= MaxFoundLength ? found : string.Concat(found.AsSpan(0, MaxFoundLength), "... (truncated)");

    /// <summary>Switches signing to the newest rotated-in key whose DNS record was found (design section 8: publish N+1, verify, switch, keep N for 7 days).</summary>
    private async Task ActivateRotatedKeyAsync(DomainRecord domain, IReadOnlyList<StoredDkimKey> keys, DomainCheckResult result, DateTimeOffset now, CancellationToken ct)
    {
        var published = result.Records.Where(r => r.Expected.Purpose == DomainRecordPurpose.Dkim && r.Status == DomainRecordStatus.Ok).Select(r => r.Expected.Host.ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);
        StoredDkimKey? next = keys
            .Where(k => !k.Active && k.RetiredAt is null && published.Contains(DkimKeyTools.GetDnsName(domain.Name, k.Selector).ToLowerInvariant()))
            .OrderByDescending(k => k.CreatedAt).FirstOrDefault();
        if (next is null)
        {
            return;
        }

        await Config.SetActiveDkimKeyAsync(domain.Id, next.Id, now, ct).ConfigureAwait(false);
        _logger.LogInformation("Domain {Domain} now signs with DKIM selector {Selector}; the previous key stays published for {Days} days", domain.Name, next.Selector, _options.DkimRetirementGrace.TotalDays);
    }

    /// <summary>Generates an RSA-2048 DKIM key pair; the private key is stored as PKCS#8 DER protected with <see cref="SecretPurposes.DkimKey"/>.</summary>
    public static async Task<StoredDkimKey> CreateKeyAsync(Guid domainId, string selector, ISecretProtector protector, DateTimeOffset now, bool active)
    {
        return await Task.Run(() =>
        {
            using RSA rsa = DkimKeyTools.GenerateRsa2048();
            byte[] der = DkimKeyTools.ExportPrivateKeyDer(rsa);
            try
            {
                return new StoredDkimKey(Ids.New(now), domainId, selector, protector.Protect(der, SecretPurposes.DkimKey), DkimKeyTools.ExportPublicKeyBase64(rsa), now, active, null);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(der);
            }
        }).ConfigureAwait(false);
    }

    /// <summary>The next unused selector: the suggested <c>eggYYYYMM</c>, or with <c>-2</c>, <c>-3</c>... when that month's name exists (selector names are never reused).</summary>
    public static string NextSelector(IEnumerable<StoredDkimKey> existing, DateTimeOffset now)
    {
        var used = existing.Select(k => k.Selector).ToHashSet(StringComparer.OrdinalIgnoreCase);
        string baseName = DkimKeyTools.SuggestSelector(now);
        if (!used.Contains(baseName))
        {
            return baseName;
        }

        for (int i = 2; ; i++)
        {
            string candidate = $"{baseName}-{i}";
            if (!used.Contains(candidate))
            {
                return candidate;
            }
        }
    }
}
