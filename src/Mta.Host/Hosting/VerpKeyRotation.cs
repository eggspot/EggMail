using System.Security.Cryptography;
using Mta.Core;
using Mta.Dsn;
using Mta.Host.Ingest;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>
/// Rotates the VERP signing keys in <c>verp_key</c> and keeps the running codec in step with the table (decision 110). Every <see cref="ReloadInterval"/>, on every replica:
/// <list type="number">
/// <item>when the key that signs is <c>Secrets:VerpKeyRotationDays</c> old and no newer key is waiting, one replica (under the lease the first key set is created under) adds a new key
/// with the next free id that activates <see cref="PendingPeriod"/> later, so every replica has loaded it, and verifies with it, before any of them signs with it (as long as the
/// reload interval plus the clock difference between replicas stays under the pending hour: about 50 minutes of skew);</item>
/// <item>a key that a newer key has replaced for at least <see cref="PendingPeriod"/> is retired (the hour covers replicas whose clocks are behind: none of them finds the old key retired
/// while the new one is not active yet for it);</item>
/// <item>a key retired for longer than the retention (<see cref="RetentionFor"/>: the longest an address it signed is accepted, plus a day) is deleted, freeing its id;</item>
/// <item>the codec is given the table's keys and the key that signs now (<see cref="VerpCodec.Replace"/>), which the bounce, SRS and hop-marker paths use from their next call.</item>
/// </list>
/// A run that fails (database down, a key this key ring cannot open) leaves the codec as it was and is retried at the next interval.
/// </summary>
public sealed class VerpKeyRotation
{
    /// <summary>How long a new key waits before it signs.</summary>
    public static readonly TimeSpan PendingPeriod = TimeSpan.FromHours(1);

    /// <summary>How often each replica re-reads the table.</summary>
    public static readonly TimeSpan ReloadInterval = TimeSpan.FromMinutes(10);

    public const int MinRotationDays = 7;
    public const int MaxRotationDays = 365;

    private const int KeyIdCount = 16;
    private const string LeaseName = "verp-keys";

    private readonly IConfigStore _config;
    private readonly ISecretProtector _secrets;
    private readonly VerpCodec _codec;
    private readonly IClock _clock;
    private readonly IMtaLog? _log;
    private readonly TimeSpan _period;
    private readonly TimeSpan _retention;
    private string? _loaded;

    /// <param name="rotationDays"><c>Secrets:VerpKeyRotationDays</c>; 0 turns the rotation off (retired keys are still pruned and changes made by hand still reloaded).</param>
    /// <param name="srsMaxAgeDays"><c>Inbound:Srs:MaxAgeDays</c>: an SRS address verifies against every key of the ring, so a key stays as long as the oldest SRS address it signed is accepted.</param>
    public VerpKeyRotation(IConfigStore config, ISecretProtector secrets, VerpCodec codec, IClock clock, int rotationDays, int srsMaxAgeDays, IMtaLog? log = null)
    {
        _config = config;
        _secrets = secrets;
        _codec = codec;
        _clock = clock;
        _log = log;
        _period = TimeSpan.FromDays(rotationDays);
        _retention = RetentionFor(srsMaxAgeDays);
    }

    /// <summary>How long a key is kept after it was retired: the longest a bounce or SRS address it signed is accepted, plus a day.</summary>
    public static TimeSpan RetentionFor(int srsMaxAgeDays) => TimeSpan.FromDays(Math.Max((int)BounceProcessor.MaxTokenAge.TotalDays, srsMaxAgeDays) + 1);

    /// <summary>
    /// The configuration check: the period is 0 or in range, and the keys held at once (one per period over the retention, plus the one that signs and the one waiting) fit in the 16 ids
    /// a bounce address can name. Beyond that an id would be reused while addresses signed with its previous key are still accepted.
    /// </summary>
    public static void Validate(int rotationDays, int srsMaxAgeDays, List<string> errors)
    {
        if (rotationDays == 0)
        {
            return;
        }

        if (rotationDays is < MinRotationDays or > MaxRotationDays)
        {
            errors.Add($"Secrets:VerpKeyRotationDays must be 0 (off) or between {MinRotationDays} and {MaxRotationDays}.");
            return;
        }

        int retentionDays = (int)RetentionFor(srsMaxAgeDays).TotalDays;
        if ((retentionDays + rotationDays - 1) / rotationDays + 2 > KeyIdCount)
        {
            errors.Add($"Secrets:VerpKeyRotationDays ({rotationDays}) is too short for Inbound:Srs:MaxAgeDays ({srsMaxAgeDays}): retired keys are kept {retentionDays} days and at most {KeyIdCount} keys can exist at once. Raise the period or lower the SRS age.");
        }
    }

    /// <summary>A pass at once (a process restarted more often than the interval still rotates), then one every <see cref="ReloadInterval"/>.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(ReloadInterval);
        try
        {
            do
            {
                try
                {
                    await RunOnceAsync(ct).ConfigureAwait(false);
                }
                catch (InvalidOperationException ex)
                {
                    // A key this replica cannot open: it keeps signing with a key the others may delete, so its bounce addresses would stop verifying there.
                    _log?.Write(MtaLogLevel.Error, "verp", "the VERP keys could not be reloaded; this replica keeps the keys it has, check its Data Protection key ring", ex);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log?.Write(MtaLogLevel.Warning, "verp", "the VERP key rotation failed; the keys in use stay as they are and it is tried again in " + ReloadInterval.TotalMinutes + " minutes", ex);
                }
            }
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }

    /// <summary>One pass: add a key when the period is up, retire the keys a newer key replaced, delete the expired ones, and give the codec what the table holds.</summary>
    public async Task RunOnceAsync(CancellationToken ct)
    {
        DateTimeOffset now = _clock.UtcNow;
        IReadOnlyList<VerpKeyRecord> keys = await _config.GetVerpKeysAsync(ct).ConfigureAwait(false);
        if (_period > TimeSpan.Zero && NeedsNewKey(keys, now))
        {
            keys = await AddKeyAsync(now, ct).ConfigureAwait(false);
        }

        if (VerpKeyStore.SigningKey(keys, now) is not { } signing)
        {
            _log?.Write(MtaLogLevel.Error, "verp", "no VERP key in verp_key can sign (every key is retired or not active yet); the keys in use stay as they are");
            return;
        }

        bool changed = false;
        foreach (VerpKeyRecord key in keys)
        {
            if (key.RetiredAt is null && key.KeyId != signing.KeyId && key.ActivatesAt <= signing.ActivatesAt && signing.ActivatesAt + PendingPeriod <= now)
            {
                if (await _config.RetireVerpKeyAsync(key.KeyId, now, ct).ConfigureAwait(false))   // false: another replica retired it first
                {
                    changed = true;
                    _log?.Write(MtaLogLevel.Information, "verp", $"VERP key {key.KeyId} retired (key {signing.KeyId} signs); it still verifies for {_retention.TotalDays:F0} days");
                }
            }
            else if (key.RetiredAt is { } retired && retired + _retention <= now)
            {
                if (await _config.DeleteVerpKeyAsync(key.KeyId, ct).ConfigureAwait(false))
                {
                    changed = true;
                    _log?.Write(MtaLogLevel.Information, "verp", $"VERP key {key.KeyId} deleted: the addresses it signed have expired");
                }
            }
        }

        if (changed)
        {
            keys = await _config.GetVerpKeysAsync(ct).ConfigureAwait(false);
            signing = VerpKeyStore.SigningKey(keys, now) ?? signing;
        }

        Load(keys, signing);
    }

    /// <summary>True when the key that signs has signed for the whole period and no newer key is waiting to replace it.</summary>
    private bool NeedsNewKey(IReadOnlyList<VerpKeyRecord> keys, DateTimeOffset now)
    {
        if (keys.Any(k => k.RetiredAt is null && k.ActivatesAt > now) || VerpKeyStore.SigningKey(keys, now) is not { } signing)
        {
            return false;
        }

        // A first key activates at the epoch, so its age counts from its creation.
        DateTimeOffset since = signing.ActivatesAt > signing.CreatedAt ? signing.ActivatesAt : signing.CreatedAt;
        return now - since >= _period;
    }

    /// <summary>Adds the next key under the lease (another replica holding it is adding one already: this pass skips) and returns the table as it is afterwards.</summary>
    private async Task<IReadOnlyList<VerpKeyRecord>> AddKeyAsync(DateTimeOffset now, CancellationToken ct)
    {
        string owner = "verp-rotation-" + Guid.NewGuid().ToString("N");
        if (await _config.TryAcquireLeaseAsync(LeaseName, owner, TimeSpan.FromSeconds(30), now, ct).ConfigureAwait(false) is null)
        {
            return await _config.GetVerpKeysAsync(ct).ConfigureAwait(false);
        }

        try
        {
            IReadOnlyList<VerpKeyRecord> keys = await _config.GetVerpKeysAsync(ct).ConfigureAwait(false);   // another replica may have added it since the first read
            if (!NeedsNewKey(keys, now))
            {
                return keys;
            }

            int signingId = VerpKeyStore.SigningKey(keys, now)!.KeyId;
            int? id = NextFreeId(keys, signingId);
            if (id is null)
            {
                _log?.Write(MtaLogLevel.Warning, "verp", $"no free VERP key id (all {KeyIdCount} are in use); key {signingId} keeps signing until a retired key expires");
                return keys;
            }

            byte[] key = VerpCodec.GenerateKey();
            try
            {
                await _config.AddVerpKeysAsync([new VerpKeyRecord(id.Value, _secrets.Protect(key, SecretPurposes.VerpKey), now, now + PendingPeriod, null)], ct).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }

            _log?.Write(MtaLogLevel.Information, "verp", $"VERP key {id} created; it signs from {now + PendingPeriod:u} and replaces key {signingId}");
            return await _config.GetVerpKeysAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            await _config.ReleaseLeaseAsync(LeaseName, owner, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>The first id after the signing key's (wrapping after 15) that no key holds, so a freed id is the last to be used again.</summary>
    private static int? NextFreeId(IReadOnlyList<VerpKeyRecord> keys, int signingId)
    {
        for (int step = 1; step < KeyIdCount; step++)
        {
            int id = (signingId + step) % KeyIdCount;
            if (keys.All(k => k.KeyId != id))
            {
                return id;
            }
        }

        return null;
    }

    /// <summary>Gives the codec the table's keys when they or the signing key changed since the last load.</summary>
    private void Load(IReadOnlyList<VerpKeyRecord> keys, VerpKeyRecord signing)
    {
        string fingerprint = signing.KeyId + ":" + string.Join(",", keys.Select(k => k.KeyId + "@" + k.CreatedAt.UtcTicks));
        if (fingerprint == _loaded)
        {
            return;
        }

        var plain = new Dictionary<int, byte[]>();
        foreach (VerpKeyRecord key in keys)
        {
            try
            {
                plain[key.KeyId] = _secrets.Unprotect(key.KeyProtected, SecretPurposes.VerpKey);
            }
            catch (CryptographicException ex)
            {
                // The codec keeps its keys and the next pass tries again.
                throw new InvalidOperationException($"The VERP key {key.KeyId} cannot be unprotected with this Data Protection key ring ({ex.Message}); the keys in use are kept.", ex);
            }
        }

        int previous = _codec.ActiveKeyId;
        _codec.Replace(plain, signing.KeyId);
        _loaded = fingerprint;
        if (previous != signing.KeyId)
        {
            _log?.Write(MtaLogLevel.Information, "verp", $"VERP key {signing.KeyId} signs from now on (was key {previous})");
        }
    }
}
