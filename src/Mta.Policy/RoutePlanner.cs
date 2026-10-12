using Mta.Storage;

namespace Mta.Policy;

/// <summary>How an attempt on one route ended, as far as route selection is concerned.</summary>
public enum RouteAttemptResult : byte
{
    /// <summary>The message was accepted (2xx at end of data).</summary>
    Delivered = 0,

    /// <summary>Could not connect: the connection timed out (typical of a blocked outbound port).</summary>
    ConnectTimeout,

    /// <summary>Could not connect: the connection was refused or the network was unreachable.</summary>
    ConnectRefused,

    /// <summary>The server replied 4xx (including greylisting and throttling): retry later on the same route.</summary>
    TemporaryReply,

    /// <summary>The server replied 5xx (recipient, policy or content rejection): the message is not sent on another route.</summary>
    PermanentReply,

    /// <summary>TLS negotiation or certificate/policy validation failed (for example MTA-STS enforce): retried on the same route, never rerouted.</summary>
    TlsPolicyFailure,

    /// <summary>The connection broke after it was established and before a final reply.</summary>
    ConnectionDropped,
}

/// <summary>What to do after an attempt.</summary>
public enum RouteAction : byte
{
    /// <summary>Delivered; nothing more to do.</summary>
    Done = 0,

    /// <summary>Immediately try <see cref="RouteDecision.NextStepIndex"/>.</summary>
    TryNextRoute,

    /// <summary>Stop this attempt, schedule a retry (see <see cref="RetrySchedule"/>); the next attempt starts with the same route.</summary>
    DeferRetrySameRoute,

    /// <summary>Every route failed to connect: defer and retry later (all routes will be planned again).</summary>
    DeferAllRoutesFailed,

    /// <summary>Permanent failure: bounce. Never tried on another route.</summary>
    FailPermanently,
}

/// <summary>The planner's instruction for the delivery layer.</summary>
/// <param name="Action">The action.</param>
/// <param name="NextStepIndex">For <see cref="RouteAction.TryNextRoute"/>, the index into <see cref="RoutePlan.Steps"/>; otherwise -1.</param>
/// <param name="Reason">A short constant explaining the choice.</param>
public readonly record struct RouteDecision(RouteAction Action, int NextStepIndex, string Reason);

/// <summary>One route to try: direct MX delivery or a configured relay.</summary>
/// <param name="Name">The route name to record on the delivery attempt (<see cref="RoutePlanner.DirectRouteName"/> or the relay's name).</param>
/// <param name="Relay">The relay definition, or null for direct MX delivery.</param>
public sealed record RouteStep(string Name, RelayRouteRecord? Relay)
{
    /// <summary>True for direct MX delivery on port 25.</summary>
    public bool IsDirect => Relay is null;

    /// <summary>The health key of this route.</summary>
    public RouteHealthKey HealthKey => RouteHealthKey.ForRoute(Name);
}

/// <summary>A route that was left out of a plan and why.</summary>
/// <param name="Name">The route name.</param>
/// <param name="Reason">Why it was skipped.</param>
/// <param name="RetryAt">For an open circuit, when it may be tried again.</param>
public sealed record SkippedRoute(string Name, string Reason, DateTimeOffset? RetryAt);

/// <summary>An ordered list of routes for one attempt.</summary>
public sealed class RoutePlan
{
    internal RoutePlan(string domain, IReadOnlyList<RouteStep> steps, IReadOnlyList<SkippedRoute> skipped, DateTimeOffset? retryNotBefore)
    {
        Domain = domain;
        Steps = steps;
        Skipped = skipped;
        RetryNotBefore = retryNotBefore;
    }

    /// <summary>The (normalized) recipient domain the plan is for.</summary>
    public string Domain { get; }

    /// <summary>Routes to try, in order. Empty when every route is unavailable.</summary>
    public IReadOnlyList<RouteStep> Steps { get; }

    /// <summary>Routes that were considered but excluded (open circuit, disabled direct delivery).</summary>
    public IReadOnlyList<SkippedRoute> Skipped { get; }

    /// <summary>When <see cref="Steps"/> is empty because circuits are open: the earliest time a route may be tried again.</summary>
    public DateTimeOffset? RetryNotBefore { get; }

    /// <summary>True when there is nothing to try right now.</summary>
    public bool IsEmpty => Steps.Count == 0;
}

/// <summary>
/// Builds the ordered route list for a delivery attempt (design section 7.2). The default is direct MX only. A relay is only ever used
/// for a domain it explicitly lists (opt-in per domain; exact name, <c>*.suffix</c> or <c>*</c>). Relays are ordered by
/// <see cref="RelayRouteRecord.Priority"/> ascending (lower number first), after direct MX. Rules for what happens after an attempt
/// are in <see cref="Decide"/>: move on at connect timeout or refusal, retry the same route on 4xx, never fall through on 5xx,
/// with <see cref="RouteHealth"/> circuit breakers keeping dead routes out of plans.
/// </summary>
public sealed class RoutePlanner
{
    /// <summary>The route name recorded for direct MX delivery.</summary>
    public const string DirectRouteName = "direct";

    private sealed class CompiledRoute
    {
        public required RelayRouteRecord Record { get; init; }
        public required RouteStep Step { get; init; }
        public required bool MatchesAll { get; init; }
        public required HashSet<string> Exact { get; init; }
        public required string[] WildcardSuffixes { get; init; }

        public bool Matches(string domain)
        {
            if (MatchesAll || Exact.Contains(domain))
            {
                return true;
            }

            foreach (string suffix in WildcardSuffixes)
            {
                if (domain.Length > suffix.Length && domain.EndsWith(suffix, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }

    private readonly RouteHealth _health;
    private volatile CompiledRoute[] _routes = [];
    private volatile bool _directMxAvailable = true;

    /// <summary>Creates a planner.</summary>
    /// <param name="health">Circuit breakers consulted when planning and updated by <see cref="ReportAttempt"/>.</param>
    /// <param name="routes">Initial relay route definitions (may be empty).</param>
    public RoutePlanner(RouteHealth health, IEnumerable<RelayRouteRecord>? routes = null)
    {
        _health = health ?? throw new ArgumentNullException(nameof(health));
        if (routes is not null)
        {
            UpdateRoutes(routes);
        }
    }

    /// <summary>
    /// Whether direct MX delivery is possible at all (for example false when the operator knows outbound port 25 is blocked).
    /// When false, plans contain only opted-in relays. Default true.
    /// </summary>
    public bool DirectMxAvailable
    {
        get => _directMxAvailable;
        set => _directMxAvailable = value;
    }

    /// <summary>Replaces the relay definitions (call after the configuration changes). Disabled routes are ignored.</summary>
    public void UpdateRoutes(IEnumerable<RelayRouteRecord> routes)
    {
        ArgumentNullException.ThrowIfNull(routes);
        var compiled = new List<CompiledRoute>();
        foreach (RelayRouteRecord r in routes)
        {
            if (!r.Enabled)
            {
                continue;
            }

            var exact = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var wildcards = new List<string>();
            bool all = false;
            foreach (string raw in r.Domains ?? [])
            {
                string d = Normalize(raw);
                if (d.Length == 0)
                {
                    continue;
                }

                if (d == "*")
                {
                    all = true;
                }
                else if (d.StartsWith("*.", StringComparison.Ordinal))
                {
                    wildcards.Add(d[1..]);
                }
                else
                {
                    exact.Add(d);
                }
            }

            if (!all && exact.Count == 0 && wildcards.Count == 0)
            {
                continue; // no domain opted in: the route is never used
            }

            compiled.Add(new CompiledRoute
            {
                Record = r,
                Step = new RouteStep(r.Name, r),
                MatchesAll = all,
                Exact = exact,
                WildcardSuffixes = [.. wildcards],
            });
        }

        compiled.Sort(static (a, b) =>
        {
            int c = a.Record.Priority.CompareTo(b.Record.Priority);
            return c != 0 ? c : string.CompareOrdinal(a.Record.Name, b.Record.Name);
        });
        _routes = [.. compiled];
    }

    /// <summary>
    /// Builds the plan for one attempt at delivering to <paramref name="recipientDomain"/>.
    /// </summary>
    /// <param name="recipientDomain">Recipient domain.</param>
    /// <param name="previousRoute">The route recorded on the previous attempt (<c>DeliveryAttempt.Route</c>), if any.</param>
    /// <param name="previousResult">How the previous attempt ended. After a 4xx, TLS failure or dropped connection the previous route goes first.</param>
    public RoutePlan Plan(string recipientDomain, string? previousRoute = null, RouteAttemptResult? previousResult = null)
    {
        string domain = Normalize(recipientDomain);
        var steps = new List<RouteStep>(2);
        List<SkippedRoute>? skipped = null;
        DateTimeOffset? earliest = null;

        if (_directMxAvailable)
        {
            Consider(new RouteStep(DirectRouteName, null));
        }
        else
        {
            (skipped ??= []).Add(new SkippedRoute(DirectRouteName, "direct MX delivery is disabled", null));
        }

        foreach (CompiledRoute route in _routes)
        {
            if (route.Matches(domain))
            {
                Consider(route.Step);
            }
        }

        if (previousRoute is not null && previousResult is RouteAttemptResult.TemporaryReply or RouteAttemptResult.TlsPolicyFailure or RouteAttemptResult.ConnectionDropped)
        {
            int idx = steps.FindIndex(s => string.Equals(s.Name, previousRoute, StringComparison.OrdinalIgnoreCase));
            if (idx > 0)
            {
                RouteStep pinned = steps[idx];
                steps.RemoveAt(idx);
                steps.Insert(0, pinned);
            }
        }

        return new RoutePlan(domain, steps, skipped ?? (IReadOnlyList<SkippedRoute>)[], steps.Count == 0 ? earliest : null);

        void Consider(RouteStep step)
        {
            if (_health.IsAvailable(step.HealthKey, out DateTimeOffset retryAt))
            {
                steps.Add(step);
                return;
            }

            (skipped ??= []).Add(new SkippedRoute(step.Name, "circuit open", retryAt));
            if (earliest is null || retryAt < earliest)
            {
                earliest = retryAt;
            }
        }
    }

    /// <summary>
    /// Claims the right to use a planned step right before connecting. Returns false if its circuit is open (skip to the next step);
    /// when it returns true with <paramref name="isProbe"/> set, the attempt is the half-open probe and its result must be reported.
    /// </summary>
    public bool TryBegin(RouteStep step, out bool isProbe)
    {
        ArgumentNullException.ThrowIfNull(step);
        RouteAdmission admission = _health.TryAdmit(step.HealthKey);
        isProbe = admission == RouteAdmission.Probe;
        return admission != RouteAdmission.Rejected;
    }

    /// <summary>
    /// Decides what to do after an attempt on <c>plan.Steps[stepIndex]</c>: move to the next route on connect timeout or refusal,
    /// retry the same route later on 4xx, TLS failures and dropped connections, and never fall through on a 5xx.
    /// </summary>
    public RouteDecision Decide(RoutePlan plan, int stepIndex, RouteAttemptResult result)
    {
        ArgumentNullException.ThrowIfNull(plan);
        switch (result)
        {
            case RouteAttemptResult.Delivered:
                return new RouteDecision(RouteAction.Done, -1, "delivered");

            case RouteAttemptResult.ConnectTimeout:
            case RouteAttemptResult.ConnectRefused:
                return stepIndex + 1 < plan.Steps.Count
                    ? new RouteDecision(RouteAction.TryNextRoute, stepIndex + 1, "could not connect: trying the next route")
                    : new RouteDecision(RouteAction.DeferAllRoutesFailed, -1, "could not connect on any route");

            case RouteAttemptResult.PermanentReply:
                return new RouteDecision(RouteAction.FailPermanently, -1, "permanent rejection: never rerouted");

            default: // TemporaryReply, TlsPolicyFailure, ConnectionDropped
                return new RouteDecision(RouteAction.DeferRetrySameRoute, -1, "temporary failure: retry on the same route");
        }
    }

    /// <summary>
    /// Feeds the outcome of an attempt on a route into its circuit breaker. A connect timeout or refusal is a failure;
    /// any server reply (even 4xx or 5xx) or a TLS failure proves the route connects and closes the circuit; a dropped connection is ignored.
    /// For the direct route report a connect failure only after every MX host failed to connect (use <see cref="ReportMxHost"/> per host).
    /// </summary>
    public void ReportAttempt(RouteStep step, RouteAttemptResult result)
    {
        ArgumentNullException.ThrowIfNull(step);
        Feed(step.HealthKey, result);
    }

    /// <summary>Feeds the outcome of an attempt on one MX host into that host's circuit breaker.</summary>
    public void ReportMxHost(string mxHost, RouteAttemptResult result) => Feed(RouteHealthKey.ForMxHost(mxHost), result);

    /// <summary>Whether an MX host may be tried (closed breaker, or the single half-open probe).</summary>
    public bool TryBeginMxHost(string mxHost, out bool isProbe)
    {
        RouteAdmission admission = _health.TryAdmit(RouteHealthKey.ForMxHost(mxHost));
        isProbe = admission == RouteAdmission.Probe;
        return admission != RouteAdmission.Rejected;
    }

    private void Feed(RouteHealthKey key, RouteAttemptResult result)
    {
        switch (result)
        {
            case RouteAttemptResult.ConnectTimeout:
                _health.ReportFailure(key, "connect timeout");
                break;
            case RouteAttemptResult.ConnectRefused:
                _health.ReportFailure(key, "connection refused");
                break;
            case RouteAttemptResult.ConnectionDropped:
                break;
            default:
                _health.ReportSuccess(key);
                break;
        }
    }

    private static string Normalize(string? domain) => (domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
}
