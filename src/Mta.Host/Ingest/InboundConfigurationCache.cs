using Mta.Core;
using Mta.Storage;
using Mta.Storage.Logic;

namespace Mta.Host.Ingest;

/// <summary>What the receive path knows about one inbound-enabled domain: its configuration and the limits that really apply (settings under the operator's ceilings).</summary>
public sealed class InboundDomainView
{
    internal InboundDomainView(InboundDomainConfiguration configuration, InboundEffectiveLimits limits)
    {
        Configuration = configuration;
        Limits = limits;
        ETag = configuration.ETag;
    }

    public InboundDomainConfiguration Configuration { get; }

    public InboundEffectiveLimits Limits { get; }

    internal string ETag { get; }

    public Guid DomainId => Configuration.DomainId;

    public Guid TenantId => Configuration.TenantId;

    public string DomainName => Configuration.DomainName;

    /// <summary>Whether the domain accepts mail now: verified (or in its grace period, <c>temporary_failure</c>) and the tenant is not suspended. Otherwise the answer is a temporary <c>450</c>.</summary>
    public bool Serving => Configuration.TenantEnabled && Configuration.DomainStatus is DomainStatus.Verified or DomainStatus.TemporaryFailure;
}

/// <summary>
/// Raised by every API path that changes what the receive path decides on (a domain's inbound settings, a route, a domain record: <see cref="Mta.Host.Submission.DomainChangeSignal.Bump"/> raises it
/// too), so the cache of this process reloads at once instead of at the next interval. Another replica sees the change within the interval.
/// </summary>
public static class InboundConfigChangeSignal
{
    // Not a CLR event: the code base has none (a subscriber that forgets to unsubscribe would stay alive for ever); a subscription here is an object that is disposed.
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<long, Action> Subscribers = new();
    private static long s_next;

    public static void Bump()
    {
        foreach (Action subscriber in Subscribers.Values)
        {
            subscriber();
        }
    }

    internal static IDisposable Subscribe(Action onChange)
    {
        long id = Interlocked.Increment(ref s_next);
        Subscribers[id] = onChange;
        return new Subscription(id);
    }

    private sealed class Subscription(long id) : IDisposable
    {
        public void Dispose() => Subscribers.TryRemove(id, out _);
    }
}

/// <summary>
/// The receive path's copy of the enabled domains, their settings and routes (design section 11.4): loaded with one set of queries, refreshed every 30 seconds (with jitter) and at once when the API
/// changes something on this process (<see cref="RequestRefresh"/>); a replica that did not make the change sees it within the interval. A configuration that was never loaded is not "no domains": the
/// receive path answers <c>451</c> (<see cref="IsAvailable"/>). Derived structures are rebuilt only for the domains whose <see cref="InboundDomainConfiguration.ETag"/> changed.
/// </summary>
public sealed class InboundConfigurationCache
{
    private readonly IInboundConfigStore _store;
    private readonly IClock _clock;
    private readonly InboundReceiveOptions _options;
    private readonly IMtaLog _log;
    private readonly SemaphoreSlim _refreshing = new(1, 1);
    private readonly SemaphoreSlim _wake = new(0, 1);
    private volatile Dictionary<string, InboundDomainView> _domains = new(StringComparer.Ordinal);
    private long _loadedAt = long.MinValue;   // clock timestamp of the last successful load
    private volatile bool _loaded;

    public InboundConfigurationCache(IInboundConfigStore store, IClock clock, InboundReceiveOptions options, IMtaLog? log = null)
    {
        _store = store;
        _clock = clock;
        _options = options;
        _log = log ?? NullMtaLog.Instance;
    }

    /// <summary>Whether the configuration was loaded and is not older than <see cref="InboundReceiveOptions.ConfigMaxStaleness"/> (refreshes that keep failing eventually stop the receive path from deciding on stale data).</summary>
    public bool IsAvailable => _loaded && AgeSeconds <= _options.ConfigMaxStaleness.TotalSeconds;

    public double AgeSeconds => _loaded ? _clock.GetElapsedTime(Volatile.Read(ref _loadedAt)).TotalSeconds : double.PositiveInfinity;

    /// <summary>Number of enabled domains in the cache.</summary>
    public int Count => _domains.Count;

    /// <summary>The view of an enabled domain by its name (any case, any form: it is normalized to the lower-case A-label form), or null.</summary>
    public InboundDomainView? Find(string domainName) => _domains.TryGetValue(InboundRules.ALabel(domainName), out InboundDomainView? view) ? view : null;

    /// <summary>Asks the loop to reload now (the API changed settings or routes on this process).</summary>
    public void RequestRefresh()
    {
        try
        {
            _wake.Release();
        }
        catch (SemaphoreFullException)
        {
            // A reload is already requested.
        }
    }

    /// <summary>Loads the configuration. Safe to call from several places; concurrent calls take turns.</summary>
    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        await _refreshing.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            IReadOnlyList<InboundDomainConfiguration> loaded = await _store.LoadEnabledDomainsAsync(cancellationToken).ConfigureAwait(false);
            Dictionary<string, InboundDomainView> previous = _domains;
            var next = new Dictionary<string, InboundDomainView>(loaded.Count, StringComparer.Ordinal);
            foreach (InboundDomainConfiguration configuration in loaded)
            {
                if (!configuration.Settings.Enabled)
                {
                    continue;
                }

                string key = InboundRules.ALabel(configuration.DomainName);
                next[key] = previous.TryGetValue(key, out InboundDomainView? existing) && existing.ETag == configuration.ETag
                    ? existing
                    : new InboundDomainView(configuration, InboundRules.Effective(configuration.Settings, _options.Ceilings, _options.ServerRetentionDays));
            }

            _domains = next;
            Volatile.Write(ref _loadedAt, _clock.Timestamp);
            _loaded = true;
        }
        finally
        {
            _refreshing.Release();
        }
    }

    /// <summary>The refresh loop: reload every interval (up to a tenth longer, so replicas do not all ask at once), or when asked. A failure is logged and tried again at the next interval.</summary>
    public async Task RunAsync(CancellationToken stoppingToken)
    {
        using IDisposable subscription = InboundConfigChangeSignal.Subscribe(RequestRefresh);
        await RunLoopAsync(stoppingToken).ConfigureAwait(false);
    }

    private async Task RunLoopAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RefreshAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _log.Write(MtaLogLevel.Warning, "inbound", "could not load the inbound domains and routes; the cached ones are used until they are too old, then mail is deferred with 451", ex);
            }

            TimeSpan wait = _options.ConfigRefreshInterval + TimeSpan.FromMilliseconds(Random.Shared.NextDouble() * 0.1 * _options.ConfigRefreshInterval.TotalMilliseconds);
            try
            {
                await _wake.WaitAsync(wait, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}
