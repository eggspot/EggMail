using Mta.Storage;

namespace Mta.Policy.Tests;

public class RoutePlannerTests
{
    private static RelayRouteRecord Relay(string name, int priority, bool enabled = true, params string[] domains) =>
        new(Guid.NewGuid(), name, name + ".relay.example", 587, "starttls", null, null, priority, enabled, domains);

    private static (RoutePlanner Planner, RouteHealth Health, FakeClock Clock) Create(params RelayRouteRecord[] routes)
    {
        var clock = new FakeClock();
        var health = new RouteHealth(clock, new RouteHealthOptions { FailureThreshold = 2, Cooldown = TimeSpan.FromMinutes(5), ProbeTimeout = TimeSpan.FromMinutes(1) });
        return (new RoutePlanner(health, routes), health, clock);
    }

    private static string[] Names(RoutePlan plan) => [.. plan.Steps.Select(s => s.Name)];

    [Fact]
    public void Default_plan_is_direct_mx_only()
    {
        var (p, _, _) = Create();
        var plan = p.Plan("example.com");
        Assert.Equal(["direct"], Names(plan));
        Assert.True(plan.Steps[0].IsDirect);
        Assert.Null(plan.Steps[0].Relay);
        Assert.Equal("direct", RoutePlanner.DirectRouteName);
    }

    [Fact]
    public void Relays_are_not_used_unless_the_domain_opted_in()
    {
        var (p, _, _) = Create(Relay("smtp2go", 1, true, "customer.com"));
        Assert.Equal(["direct"], Names(p.Plan("other.com")));
        Assert.Equal(["direct"], Names(p.Plan("sub.customer.com"))); // exact match only without a wildcard
        Assert.Equal(["direct", "smtp2go"], Names(p.Plan("customer.com")));
        Assert.Equal(["direct", "smtp2go"], Names(p.Plan("CUSTOMER.com.")));
    }

    [Fact]
    public void Relays_follow_priority_order_after_direct()
    {
        var (p, _, _) = Create(
            Relay("slow", 20, true, "example.com"),
            Relay("backup-b", 10, true, "example.com"),
            Relay("backup-a", 10, true, "example.com"),
            Relay("first", 1, true, "example.com"));
        Assert.Equal(["direct", "first", "backup-a", "backup-b", "slow"], Names(p.Plan("example.com")));
    }

    [Fact]
    public void Wildcards_and_star_opt_in_domains()
    {
        var (p, _, _) = Create(Relay("w", 1, true, "*.customer.com"), Relay("all", 2, true, "*"));
        Assert.Equal(["direct", "all"], Names(p.Plan("customer.com")));
        Assert.Equal(["direct", "w", "all"], Names(p.Plan("mail.customer.com")));
        Assert.Equal(["direct", "w", "all"], Names(p.Plan("a.b.customer.com")));
        Assert.Equal(["direct", "all"], Names(p.Plan("notcustomer.com")));
    }

    [Fact]
    public void Disabled_routes_and_routes_without_domains_are_never_planned()
    {
        var (p, _, _) = Create(Relay("off", 1, false, "example.com"), Relay("empty", 2, true), Relay("blank", 3, true, " ", ""));
        Assert.Equal(["direct"], Names(p.Plan("example.com")));
    }

    [Fact]
    public void Direct_can_be_unavailable_for_example_when_port_25_is_blocked()
    {
        var (p, _, _) = Create(Relay("relay", 1, true, "example.com"));
        p.DirectMxAvailable = false;
        var plan = p.Plan("example.com");
        Assert.Equal(["relay"], Names(plan));
        Assert.Contains(plan.Skipped, s => s.Name == "direct");

        var noOptIn = p.Plan("not-opted-in.com");
        Assert.True(noOptIn.IsEmpty);
        Assert.Null(noOptIn.RetryNotBefore);
    }

    [Fact]
    public void Open_circuits_are_left_out_and_reported()
    {
        var (p, health, clock) = Create(Relay("relay", 1, true, "example.com"));
        health.ReportFailure(RouteHealthKey.ForRoute("direct"));
        health.ReportFailure(RouteHealthKey.ForRoute("direct"));

        var plan = p.Plan("example.com");
        Assert.Equal(["relay"], Names(plan));
        var skipped = Assert.Single(plan.Skipped);
        Assert.Equal("direct", skipped.Name);
        Assert.Equal(clock.UtcNow.AddMinutes(5), skipped.RetryAt);
    }

    [Fact]
    public void When_every_route_is_open_the_plan_is_empty_with_the_earliest_retry_time()
    {
        var (p, health, clock) = Create(Relay("relay", 1, true, "example.com"));
        health.ReportFailure(RouteHealthKey.ForRoute("direct"));
        health.ReportFailure(RouteHealthKey.ForRoute("direct"));
        clock.Advance(TimeSpan.FromMinutes(2));
        health.ReportFailure(RouteHealthKey.ForRoute("relay"));
        health.ReportFailure(RouteHealthKey.ForRoute("relay"));

        var plan = p.Plan("example.com");
        Assert.True(plan.IsEmpty);
        Assert.Equal(clock.UtcNow.AddMinutes(3), plan.RetryNotBefore);
    }

    [Fact]
    public void Decision_rules_follow_the_design()
    {
        var (p, _, _) = Create(Relay("relay", 1, true, "example.com"));
        var plan = p.Plan("example.com");
        Assert.Equal(2, plan.Steps.Count);

        // Connect timeout / refusal: move on.
        var d = p.Decide(plan, 0, RouteAttemptResult.ConnectTimeout);
        Assert.Equal(RouteAction.TryNextRoute, d.Action);
        Assert.Equal(1, d.NextStepIndex);
        Assert.Equal(RouteAction.TryNextRoute, p.Decide(plan, 0, RouteAttemptResult.ConnectRefused).Action);

        // ...but not past the last route.
        Assert.Equal(RouteAction.DeferAllRoutesFailed, p.Decide(plan, 1, RouteAttemptResult.ConnectTimeout).Action);

        // 4xx and friends: retry the same route later.
        foreach (var r in new[] { RouteAttemptResult.TemporaryReply, RouteAttemptResult.TlsPolicyFailure, RouteAttemptResult.ConnectionDropped })
        {
            var same = p.Decide(plan, 0, r);
            Assert.Equal(RouteAction.DeferRetrySameRoute, same.Action);
            Assert.Equal(-1, same.NextStepIndex);
        }

        // 5xx: never fall through.
        Assert.Equal(RouteAction.FailPermanently, p.Decide(plan, 0, RouteAttemptResult.PermanentReply).Action);
        Assert.Equal(RouteAction.FailPermanently, p.Decide(plan, 1, RouteAttemptResult.PermanentReply).Action);
        Assert.Equal(RouteAction.Done, p.Decide(plan, 0, RouteAttemptResult.Delivered).Action);
    }

    [Fact]
    public void After_a_temporary_failure_the_previous_route_goes_first()
    {
        var (p, _, _) = Create(Relay("relay", 1, true, "example.com"), Relay("relay2", 2, true, "example.com"));
        Assert.Equal(["relay", "direct", "relay2"], Names(p.Plan("example.com", "relay", RouteAttemptResult.TemporaryReply)));
        Assert.Equal(["relay2", "direct", "relay"], Names(p.Plan("example.com", "relay2", RouteAttemptResult.TlsPolicyFailure)));
        // After a connect failure on the previous route the normal order applies (it is retried only because the plan starts over).
        Assert.Equal(["direct", "relay", "relay2"], Names(p.Plan("example.com", "relay", RouteAttemptResult.ConnectTimeout)));
        // Unknown previous route name: ignored.
        Assert.Equal(["direct", "relay", "relay2"], Names(p.Plan("example.com", "gone", RouteAttemptResult.TemporaryReply)));
    }

    [Fact]
    public void Previous_route_with_an_open_circuit_is_not_forced_back_in()
    {
        var (p, health, _) = Create(Relay("relay", 1, true, "example.com"));
        health.ReportFailure(RouteHealthKey.ForRoute("relay"));
        health.ReportFailure(RouteHealthKey.ForRoute("relay"));
        Assert.Equal(["direct"], Names(p.Plan("example.com", "relay", RouteAttemptResult.TemporaryReply)));
    }

    [Fact]
    public void Connect_failures_feed_the_breaker_and_replies_close_it()
    {
        var (p, health, clock) = Create(Relay("relay", 1, true, "example.com"));
        var direct = p.Plan("example.com").Steps[0];

        p.ReportAttempt(direct, RouteAttemptResult.ConnectTimeout);
        Assert.Equal(["direct", "relay"], Names(p.Plan("example.com")));
        p.ReportAttempt(direct, RouteAttemptResult.ConnectRefused);
        Assert.Equal(["relay"], Names(p.Plan("example.com")));

        clock.Advance(TimeSpan.FromMinutes(5));
        // Cooldown over: direct is planned again and the next attempt is the probe.
        var plan = p.Plan("example.com");
        Assert.Equal(["direct", "relay"], Names(plan));
        Assert.True(p.TryBegin(plan.Steps[0], out bool probe));
        Assert.True(probe);
        Assert.False(p.TryBegin(plan.Steps[0], out _)); // only one probe at a time
        Assert.True(p.TryBegin(plan.Steps[1], out probe));
        Assert.False(probe);

        // A 5xx reply proves the route connects: closes the circuit.
        p.ReportAttempt(direct, RouteAttemptResult.PermanentReply);
        Assert.Equal(CircuitState.Closed, health.GetSnapshot(direct.HealthKey).State);
    }

    [Fact]
    public void Dropped_connections_do_not_count_either_way()
    {
        var (p, health, _) = Create();
        var direct = p.Plan("example.com").Steps[0];
        p.ReportAttempt(direct, RouteAttemptResult.ConnectionDropped);
        p.ReportAttempt(direct, RouteAttemptResult.ConnectionDropped);
        p.ReportAttempt(direct, RouteAttemptResult.ConnectionDropped);
        Assert.Equal(0, health.GetSnapshot(direct.HealthKey).TotalFailures);
        Assert.Equal(["direct"], Names(p.Plan("example.com")));
    }

    [Fact]
    public void Mx_host_breakers_are_fed_separately()
    {
        var (p, _, _) = Create();
        p.ReportMxHost("mx1.example.com", RouteAttemptResult.ConnectTimeout);
        p.ReportMxHost("mx1.example.com", RouteAttemptResult.ConnectTimeout);
        Assert.False(p.TryBeginMxHost("mx1.example.com", out _));
        Assert.True(p.TryBeginMxHost("mx2.example.com", out _));
        Assert.Equal(["direct"], Names(p.Plan("example.com"))); // the route itself is still healthy
    }

    [Fact]
    public void Route_names_on_the_plan_are_the_names_to_record_on_the_attempt()
    {
        var (p, _, _) = Create(Relay("smtp2go", 1, true, "example.com"));
        var plan = p.Plan("example.com");
        Assert.Equal("direct", plan.Steps[0].Name);
        Assert.Equal("smtp2go", plan.Steps[1].Name);
        Assert.Equal(587, plan.Steps[1].Relay!.Port);
        Assert.Equal("example.com", plan.Domain);
    }

    [Fact]
    public void UpdateRoutes_replaces_the_configuration()
    {
        var (p, _, _) = Create(Relay("old", 1, true, "example.com"));
        p.UpdateRoutes([Relay("new", 1, true, "example.com")]);
        Assert.Equal(["direct", "new"], Names(p.Plan("example.com")));
        p.UpdateRoutes([]);
        Assert.Equal(["direct"], Names(p.Plan("example.com")));
    }

    [Fact]
    public void End_to_end_blocked_port_25_scenario()
    {
        var (p, _, clock) = Create(Relay("relay587", 1, true, "example.com"));

        // Attempt 1: direct times out, falls to the relay, which accepts.
        var plan = p.Plan("example.com");
        Assert.Equal(RouteAction.TryNextRoute, p.Decide(plan, 0, RouteAttemptResult.ConnectTimeout).Action);
        p.ReportAttempt(plan.Steps[0], RouteAttemptResult.ConnectTimeout);
        p.ReportAttempt(plan.Steps[1], RouteAttemptResult.Delivered);

        // Attempt 2 for another message: direct times out again, which opens its circuit.
        plan = p.Plan("example.com");
        p.ReportAttempt(plan.Steps[0], RouteAttemptResult.ConnectTimeout);
        Assert.Equal(["relay587"], Names(p.Plan("example.com")));

        // A 4xx on the relay: retry the same route, pinned.
        var next = p.Plan("example.com", "relay587", RouteAttemptResult.TemporaryReply);
        Assert.Equal("relay587", next.Steps[0].Name);

        // Much later direct is probed again.
        clock.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal(["direct", "relay587"], Names(p.Plan("example.com")));
    }
}
