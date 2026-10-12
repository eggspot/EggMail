using System.Collections.Concurrent;
using Mta.Core;
using Mta.Dns;

namespace Mta.Tls.MtaSts;

/// <summary>Storage for fetched MTA-STS policies. The default is in memory; a host may persist entries across restarts.</summary>
public interface IMtaStsCache
{
    /// <summary>Returns the entry for <paramref name="domain"/> (a normalised name), or <see langword="null"/>. May return expired entries.</summary>
    ValueTask<MtaStsCacheEntry?> GetAsync(string domain, CancellationToken cancellationToken = default);

    /// <summary>Stores or replaces the entry for <see cref="MtaStsCacheEntry.Domain"/>.</summary>
    ValueTask SetAsync(MtaStsCacheEntry entry, CancellationToken cancellationToken = default);

    /// <summary>Removes the entry for <paramref name="domain"/>, if any.</summary>
    ValueTask RemoveAsync(string domain, CancellationToken cancellationToken = default);
}

/// <summary>A bounded in-memory <see cref="IMtaStsCache"/>. When full it evicts expired entries, then the oldest fetch.</summary>
public sealed class InMemoryMtaStsCache : IMtaStsCache
{
    private readonly ConcurrentDictionary<string, MtaStsCacheEntry> _entries = new(StringComparer.Ordinal);
    private readonly IClock _clock;
    private readonly int _maxEntries;
    private readonly object _evictionLock = new();

    /// <summary>Creates a cache.</summary>
    /// <param name="clock">Time source used to decide which entries are expired when evicting.</param>
    /// <param name="maxEntries">The maximum number of entries (default 50,000).</param>
    public InMemoryMtaStsCache(IClock? clock = null, int maxEntries = 50_000)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxEntries, 1);
        _clock = clock ?? SystemClock.Instance;
        _maxEntries = maxEntries;
    }

    /// <summary>The current number of entries.</summary>
    public int Count => _entries.Count;

    /// <inheritdoc />
    public ValueTask<MtaStsCacheEntry?> GetAsync(string domain, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(_entries.TryGetValue(domain, out var e) ? e : null);

    /// <inheritdoc />
    public ValueTask SetAsync(MtaStsCacheEntry entry, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        _entries[entry.Domain] = entry;
        if (_entries.Count > _maxEntries)
        {
            Evict();
        }

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask RemoveAsync(string domain, CancellationToken cancellationToken = default)
    {
        _entries.TryRemove(domain, out _);
        return ValueTask.CompletedTask;
    }

    private void Evict()
    {
        lock (_evictionLock)
        {
            if (_entries.Count <= _maxEntries)
            {
                return;
            }

            var now = _clock.UtcNow;
            foreach (var pair in _entries)
            {
                if (pair.Value.ExpiresAt <= now)
                {
                    _entries.TryRemove(pair.Key, out _);
                }
            }

            while (_entries.Count > _maxEntries)
            {
                string? oldestKey = null;
                DateTimeOffset oldest = DateTimeOffset.MaxValue;
                foreach (var pair in _entries)
                {
                    if (pair.Value.FetchedAt < oldest)
                    {
                        oldest = pair.Value.FetchedAt;
                        oldestKey = pair.Key;
                    }
                }

                if (oldestKey is null || !_entries.TryRemove(oldestKey, out _))
                {
                    break;
                }
            }
        }
    }
}

/// <summary>Where a looked-up policy came from.</summary>
public enum MtaStsPolicySource
{
    /// <summary>No policy applies.</summary>
    None,

    /// <summary>The policy was fetched during this lookup.</summary>
    Fetched,

    /// <summary>The policy came from the cache (unchanged id, DNS gone, or a failed refresh).</summary>
    Cache,
}

/// <summary>The outcome of <see cref="MtaStsPolicyStore.GetPolicyAsync"/>.</summary>
/// <param name="Source">Where the policy came from.</param>
/// <param name="Policy">The policy to apply, or <see langword="null"/> when none applies. A policy with mode <see cref="MtaStsMode.None"/> means "no enforcement".</param>
/// <param name="PolicyId">The id of the TXT record the policy belongs to.</param>
/// <param name="Failure">A failure to report to TLS-RPT (fetch or parse error), even when a cached policy is still used.</param>
/// <param name="Detail">Human-readable detail for logs.</param>
public sealed record MtaStsLookupResult(
    MtaStsPolicySource Source,
    MtaStsPolicy? Policy,
    string? PolicyId,
    TlsResultType? Failure,
    string? Detail)
{
    /// <summary>The result for a domain without any MTA-STS policy.</summary>
    public static MtaStsLookupResult NoPolicy(string? detail = null, TlsResultType? failure = null) =>
        new(MtaStsPolicySource.None, null, null, failure, detail);

    /// <summary>True when a policy in <c>enforce</c> or <c>testing</c> mode applies.</summary>
    public bool HasActivePolicy => Policy is { Mode: not MtaStsMode.None };
}

/// <summary>Options for <see cref="MtaStsPolicyStore"/>.</summary>
public sealed class MtaStsStoreOptions
{
    /// <summary>Re-fetch a cached policy this old even if the TXT id is unchanged, to extend its lifetime. Default 24 hours.</summary>
    public TimeSpan RevalidateAfter { get; init; } = TimeSpan.FromHours(24);

    /// <summary>After a failed fetch, do not try that domain again for this long. Default 5 minutes.</summary>
    public TimeSpan FailureBackoff { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Upper bound for the whole lookup (DNS plus fetch). Default 60 seconds.</summary>
    public TimeSpan LookupTimeout { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Maximum number of remembered fetch failures. Default 10,000.</summary>
    public int MaxFailureEntries { get; init; } = 10_000;
}

/// <summary>
/// Resolves the MTA-STS policy of a recipient domain following RFC 8461 section 5.1: look up the TXT id, fetch when
/// it changed (or the cached policy is old), keep the cached policy when the fetch fails, and never drop a cached
/// policy because the TXT record vanished or the lookup failed (it applies until its <c>max_age</c>).
/// </summary>
public sealed class MtaStsPolicyStore
{
    private readonly IDnsResolver _dns;
    private readonly IMtaStsPolicyFetcher _fetcher;
    private readonly IMtaStsCache _cache;
    private readonly IClock _clock;
    private readonly MtaStsStoreOptions _options;
    private readonly ConcurrentDictionary<string, Task<MtaStsLookupResult>> _inFlight = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _failureUntil = new(StringComparer.Ordinal);

    /// <summary>Creates a store.</summary>
    public MtaStsPolicyStore(IDnsResolver dns, IMtaStsPolicyFetcher fetcher, IMtaStsCache? cache = null, IClock? clock = null, MtaStsStoreOptions? options = null)
    {
        _dns = dns ?? throw new ArgumentNullException(nameof(dns));
        _fetcher = fetcher ?? throw new ArgumentNullException(nameof(fetcher));
        _clock = clock ?? SystemClock.Instance;
        _cache = cache ?? new InMemoryMtaStsCache(_clock);
        _options = options ?? new MtaStsStoreOptions();
    }

    /// <summary>Returns the policy that applies to mail for <paramref name="domain"/>. Does not throw on remote or DNS failures.</summary>
    public async ValueTask<MtaStsLookupResult> GetPolicyAsync(string domain, CancellationToken cancellationToken = default)
    {
        if (!DnsNames.TryNormalizeHost(domain, out string name))
        {
            return MtaStsLookupResult.NoPolicy("invalid domain");
        }

        // Concurrent lookups for one domain share the work. The shared task is not tied to any single caller's token.
        Task<MtaStsLookupResult> task = _inFlight.GetOrAdd(name, static (n, self) => self.RunAsync(n), this);
        _ = task.ContinueWith(
            static (t, state) =>
            {
                var (self, key) = ((MtaStsPolicyStore, string))state!;
                self._inFlight.TryRemove(new KeyValuePair<string, Task<MtaStsLookupResult>>(key, t));
            },
            (this, name),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        return await task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<MtaStsLookupResult> RunAsync(string domain)
    {
        await Task.Yield();
        using var cts = new CancellationTokenSource(_options.LookupTimeout);
        try
        {
            return await LookupAsync(domain, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return await FallbackToCacheAsync(domain, "lookup timed out", null).ConfigureAwait(false);
        }
    }

    private async Task<MtaStsLookupResult> LookupAsync(string domain, CancellationToken ct)
    {
        var now = _clock.UtcNow;
        MtaStsCacheEntry? cached = await _cache.GetAsync(domain, ct).ConfigureAwait(false);
        if (cached is not null && cached.ExpiresAt <= now)
        {
            await _cache.RemoveAsync(domain, ct).ConfigureAwait(false);
            cached = null;
        }

        MtaStsTxtRecord? txt = null;
        string? txtProblem = null;
        try
        {
            DnsResponse response = await _dns.QueryAsync("_mta-sts." + domain, DnsRecordType.TXT, ct).ConfigureAwait(false);
            if (response.Rcode is DnsRcode.NoError or DnsRcode.NameError)
            {
                txt = MtaStsTxtParser.Select(response.Get<TxtRecord>());
                if (txt is null)
                {
                    txtProblem = "no valid MTA-STS TXT record";
                }
            }
            else
            {
                txtProblem = $"TXT lookup failed ({response.Rcode})";
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            txtProblem = "TXT lookup failed: " + ex.Message;
        }

        if (txt is null)
        {
            // No (or unreadable) TXT: a cached policy keeps applying until max_age; otherwise there is no policy.
            return cached is not null ? FromCache(cached, txtProblem, null) : MtaStsLookupResult.NoPolicy(txtProblem);
        }

        if (cached is not null
            && cached.PolicyId == txt.Id
            && now - cached.FetchedAt < _options.RevalidateAfter)
        {
            return FromCache(cached, null, null);
        }

        if (_failureUntil.TryGetValue(domain, out var until) && until > now)
        {
            return await FallbackToCacheAsync(domain, "recent fetch failure; backing off", null, cached).ConfigureAwait(false);
        }

        MtaStsFetchResult fetch = await _fetcher.FetchAsync(domain, ct).ConfigureAwait(false);
        if (fetch.Policy is { } policy)
        {
            _failureUntil.TryRemove(domain, out _);
            var entry = new MtaStsCacheEntry(domain, txt.Id, policy, now, now.AddSeconds(policy.MaxAgeSeconds));
            if (policy.MaxAgeSeconds > 0)
            {
                await _cache.SetAsync(entry, ct).ConfigureAwait(false);
            }
            else
            {
                await _cache.RemoveAsync(domain, ct).ConfigureAwait(false);
            }

            return new MtaStsLookupResult(MtaStsPolicySource.Fetched, policy, txt.Id, null, null);
        }

        RememberFailure(domain, now);
        return await FallbackToCacheAsync(domain, fetch.Detail, fetch.ResultType, cached).ConfigureAwait(false);
    }

    private async Task<MtaStsLookupResult> FallbackToCacheAsync(string domain, string? detail, TlsResultType? failure, MtaStsCacheEntry? known = null)
    {
        MtaStsCacheEntry? cached = known;
        if (cached is null)
        {
            cached = await _cache.GetAsync(domain, CancellationToken.None).ConfigureAwait(false);
            if (cached is not null && cached.ExpiresAt <= _clock.UtcNow)
            {
                cached = null;
            }
        }

        return cached is not null ? FromCache(cached, detail, failure) : MtaStsLookupResult.NoPolicy(detail, failure);
    }

    private static MtaStsLookupResult FromCache(MtaStsCacheEntry entry, string? detail, TlsResultType? failure) =>
        new(MtaStsPolicySource.Cache, entry.Policy, entry.PolicyId, failure, detail);

    private void RememberFailure(string domain, DateTimeOffset now)
    {
        if (_failureUntil.Count >= _options.MaxFailureEntries)
        {
            foreach (var pair in _failureUntil)
            {
                if (pair.Value <= now)
                {
                    _failureUntil.TryRemove(pair.Key, out _);
                }
            }

            if (_failureUntil.Count >= _options.MaxFailureEntries)
            {
                return;
            }
        }

        _failureUntil[domain] = now + _options.FailureBackoff;
    }
}
