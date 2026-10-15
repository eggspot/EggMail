using Mta.Storage.Logic;

namespace Mta.Storage.Tests;

public class InboundRulesTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 8, 0, 0, TimeSpan.Zero);
    private static readonly Guid Tenant = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private static readonly Guid Domain = Guid.Parse("d0000000-0000-7000-8000-000000000001");

    private static InboundRouteRecord Route(
        InboundMatchKind kind = InboundMatchKind.Address,
        string? local = "support",
        bool plus = false,
        int order = 10,
        bool enabled = true,
        InboundActionKind action = InboundActionKind.Store,
        Guid? endpoint = null,
        string[]? forwardTo = null,
        Guid? id = null,
        string name = "") =>
        new(id ?? Guid.CreateVersion7(), Tenant, Domain, name, order, enabled, kind, local, plus, action, endpoint, InboundWebhookFormat.Json, forwardTo ?? [], Now, Now);

    [Theory]
    [InlineData("support", "support", false, true)]
    [InlineData("support", "SUPPORT", false, true)]
    [InlineData("support", "support+billing", false, false)]
    [InlineData("support", "support+billing", true, true)]
    [InlineData("support", "support+", true, true)]
    [InlineData("support", "+support", true, false)]
    [InlineData("support", "supports", true, false)]
    [InlineData("a+b", "a+b", false, true)]
    [InlineData("a+b", "a+b", true, true)]
    [InlineData("a+b", "a+c", true, false)]
    public void Address_routes_compare_ignoring_case_and_the_plus_tag_only_when_asked(string pattern, string local, bool plus, bool expected)
    {
        Assert.Equal(expected, InboundRules.Matches(Route(InboundMatchKind.Address, pattern, plus), local));
    }

    [Theory]
    [InlineData("billing-*", "billing-eu", true)]
    [InlineData("billing-*", "billing-", true)]
    [InlineData("billing-*", "billing", false)]
    [InlineData("*-bot", "ci-bot", true)]
    [InlineData("*-bot", "BOT", false)]
    [InlineData("a*b*c", "aXXbYYc", true)]
    [InlineData("a*b*c", "abc", true)]
    [InlineData("a*b*c", "acb", false)]
    [InlineData("*a*", "banana", true)]
    [InlineData("a*a*a", "aaaa", true)]
    [InlineData("a*a*a", "aa", false)]
    public void Wildcard_routes_match_any_run_of_characters(string pattern, string local, bool expected)
    {
        Assert.Equal(expected, InboundRules.Matches(Route(InboundMatchKind.Wildcard, pattern), local));
    }

    [Fact]
    public void A_wildcard_route_with_plus_addressing_also_tries_the_base_local_part()
    {
        InboundRouteRecord route = Route(InboundMatchKind.Wildcard, "sales-*", plus: true);
        Assert.True(InboundRules.Matches(route, "sales-eu+campaign"));
        Assert.False(InboundRules.Matches(route, "sales+eu"));
    }

    [Fact]
    public void A_catch_all_matches_everything_and_a_pattern_route_never_matches_an_empty_local_part()
    {
        Assert.True(InboundRules.Matches(Route(InboundMatchKind.CatchAll, null), "anything"));
        Assert.False(InboundRules.Matches(Route(InboundMatchKind.Wildcard, "*x"), ""));
    }

    [Fact]
    public void The_lowest_order_wins_and_ties_go_to_the_lowest_id_and_disabled_routes_are_skipped()
    {
        Guid low = Guid.Parse("00000000-0000-7000-8000-000000000001");
        Guid high = Guid.Parse("00000000-0000-7000-8000-000000000002");
        InboundRouteRecord catchAll = Route(InboundMatchKind.CatchAll, null, order: 100, name: "catch-all");
        InboundRouteRecord exact = Route(InboundMatchKind.Address, "support", order: 20, name: "exact");
        InboundRouteRecord tieB = Route(InboundMatchKind.Wildcard, "sup*", order: 20, id: high, name: "tie-high");
        InboundRouteRecord tieA = Route(InboundMatchKind.Wildcard, "sup*", order: 20, id: low, name: "tie-low");
        InboundRouteRecord disabled = Route(InboundMatchKind.Address, "support", order: 1, enabled: false, name: "disabled");

        InboundRouteRecord[] routes = [catchAll, tieB, exact, disabled, tieA];
        Assert.Equal("tie-low", InboundRules.MatchRoute(routes, "support")!.Name);
        Assert.Equal("catch-all", InboundRules.MatchRoute(routes, "other")!.Name);
        Assert.Null(InboundRules.MatchRoute([exact, disabled], "other"));
        Assert.Null(InboundRules.MatchRoute([], "support"));
    }

    [Fact]
    public void Matching_a_pathological_input_finishes_and_gives_the_right_answer()
    {
        string text = new string('a', 60_000) + "b";
        Assert.False(InboundRules.Matches(Route(InboundMatchKind.Wildcard, "a*a*a*c"), text));
    }

    [Theory]
    [InlineData(InboundActionKind.Webhook, InboundActionState.Pending, true)]
    [InlineData(InboundActionKind.Forward, InboundActionState.Pending, true)]
    [InlineData(InboundActionKind.Store, InboundActionState.Done, true)]
    [InlineData(InboundActionKind.Discard, InboundActionState.Done, false)]
    public void A_new_message_starts_in_the_state_its_action_implies(InboundActionKind kind, InboundActionState state, bool storesBody)
    {
        Assert.Equal(state, InboundRules.InitialActionState(kind));
        Assert.Equal(storesBody, InboundRules.StoresBody(kind));
    }

    [Fact]
    public void Retention_is_the_domains_value_else_the_server_default_and_zero_is_unlimited()
    {
        Assert.Equal(30, InboundRules.ResolveRetentionDays(30, 7));
        Assert.Equal(7, InboundRules.ResolveRetentionDays(null, 7));
        Assert.Equal(0, InboundRules.ResolveRetentionDays(0, 7));
        Assert.Equal(0, InboundRules.ResolveRetentionDays(null, 0));
        Assert.Equal(7, InboundRules.ResolveRetentionDays(null, -1));
        Assert.Null(InboundRules.RetentionCutoff(Now, 0));
        Assert.Equal(Now.AddDays(-7), InboundRules.RetentionCutoff(Now, 7));
    }

    [Fact]
    public void Valid_routes_pass_validation()
    {
        Guid endpoint = Guid.CreateVersion7();
        Assert.Empty(InboundRules.ValidateRoute(Route(InboundMatchKind.CatchAll, null, action: InboundActionKind.Discard)));
        Assert.Empty(InboundRules.ValidateRoute(Route(InboundMatchKind.Address, "first.last+x", plus: true)));
        Assert.Empty(InboundRules.ValidateRoute(Route(InboundMatchKind.Wildcard, "billing-*", action: InboundActionKind.Webhook, endpoint: endpoint)));
        Assert.Empty(InboundRules.ValidateRoute(Route(InboundMatchKind.Address, "info", action: InboundActionKind.Forward, forwardTo: ["a@example.org", "b@example.net"])));
    }

    [Theory]
    [InlineData(InboundMatchKind.CatchAll, "x", "localPart")]
    [InlineData(InboundMatchKind.Address, null, "localPart")]
    [InlineData(InboundMatchKind.Address, "", "localPart")]
    [InlineData(InboundMatchKind.Address, "Upper", "localPart")]
    [InlineData(InboundMatchKind.Address, "a*b", "localPart")]
    [InlineData(InboundMatchKind.Address, "a b", "localPart")]
    [InlineData(InboundMatchKind.Address, "a@b", "localPart")]
    [InlineData(InboundMatchKind.Wildcard, "plain", "localPart")]
    [InlineData(InboundMatchKind.Wildcard, "***", "localPart")]
    [InlineData(InboundMatchKind.Wildcard, "*a*b*c*", "localPart")]
    public void Invalid_matches_are_reported_on_the_local_part(InboundMatchKind kind, string? local, string field)
    {
        Assert.Contains(InboundRules.ValidateRoute(Route(kind, local)), e => e.Field == field);
    }

    [Fact]
    public void A_catch_all_cannot_have_plus_addressing_and_a_local_part_has_a_length_limit()
    {
        Assert.Contains(InboundRules.ValidateRoute(Route(InboundMatchKind.CatchAll, null, plus: true)), e => e.Field == "plusAddressing");
        Assert.Contains(InboundRules.ValidateRoute(Route(InboundMatchKind.Address, new string('a', 65))), e => e.Field == "localPart");
    }

    [Fact]
    public void Actions_must_carry_exactly_their_own_target()
    {
        Guid endpoint = Guid.CreateVersion7();
        Assert.Contains(InboundRules.ValidateRoute(Route(action: InboundActionKind.Webhook)), e => e.Field == "webhookEndpointId");
        Assert.Contains(InboundRules.ValidateRoute(Route(action: InboundActionKind.Webhook, endpoint: endpoint, forwardTo: ["a@example.org"])), e => e.Field == "forwardTo");
        Assert.Contains(InboundRules.ValidateRoute(Route(action: InboundActionKind.Forward)), e => e.Field == "forwardTo");
        Assert.Contains(InboundRules.ValidateRoute(Route(action: InboundActionKind.Forward, forwardTo: ["a@example.org"], endpoint: endpoint)), e => e.Field == "webhookEndpointId");
        Assert.Contains(InboundRules.ValidateRoute(Route(action: InboundActionKind.Store, endpoint: endpoint)), e => e.Field == "webhookEndpointId");
        Assert.Contains(InboundRules.ValidateRoute(Route(action: InboundActionKind.Discard, forwardTo: ["a@example.org"])), e => e.Field == "forwardTo");
    }

    [Fact]
    public void Forward_targets_must_be_distinct_valid_addresses_and_at_most_ten()
    {
        var errors = InboundRules.ValidateRoute(Route(action: InboundActionKind.Forward, forwardTo: ["a@example.org", "A@EXAMPLE.org", "not-an-address"]));
        Assert.Contains(errors, e => e.Field == "forwardTo[1]");
        Assert.Contains(errors, e => e.Field == "forwardTo[2]");

        string[] eleven = Enumerable.Range(0, 11).Select(i => $"u{i}@example.org").ToArray();
        Assert.Contains(InboundRules.ValidateRoute(Route(action: InboundActionKind.Forward, forwardTo: eleven)), e => e.Field == "forwardTo");
    }

    [Fact]
    public void Settings_are_validated_member_by_member()
    {
        var ok = new InboundDomainSettings(Domain, Tenant, true, InboundDmarcAction.Reject, 10_000_000, 60, 10, 1L << 30, 0, Now);
        Assert.Empty(InboundRules.ValidateSettings(ok));
        Assert.Empty(InboundRules.ValidateSettings(InboundDomainSettings.Disabled(Domain, Tenant, Now)));
        Assert.Empty(InboundRules.ValidateSettings(ok with { MaxStoredBytes = 0 }));

        var bad = ok with { MaxMessageBytes = 10, MaxMessagesPerMinute = 0, MaxMessagesPerMinutePerRemote = 20_000, MaxStoredBytes = 5, RetentionDays = -1, DmarcAction = (InboundDmarcAction)9 };
        string[] fields = InboundRules.ValidateSettings(bad).Select(e => e.Field).ToArray();
        Assert.Equal(["dmarcAction", "maxMessageBytes", "maxMessagesPerMinute", "maxMessagesPerMinutePerRemote", "maxStoredBytes", "retentionDays"], fields);
    }

    [Fact]
    public void Wire_names_round_trip()
    {
        foreach (InboundVerdict v in Enum.GetValues<InboundVerdict>())
        {
            Assert.True(InboundNames.TryParse(InboundNames.Of(v), out InboundVerdict back));
            Assert.Equal(v, back);
        }

        foreach (InboundDmarcAction v in Enum.GetValues<InboundDmarcAction>())
        {
            Assert.True(InboundNames.TryParse(InboundNames.Of(v), out InboundDmarcAction back));
            Assert.Equal(v, back);
        }

        foreach (InboundActionKind v in Enum.GetValues<InboundActionKind>())
        {
            Assert.True(InboundNames.TryParse(InboundNames.Of(v), out InboundActionKind back));
            Assert.Equal(v, back);
        }

        foreach (InboundMatchKind v in Enum.GetValues<InboundMatchKind>())
        {
            Assert.True(InboundNames.TryParse(InboundNames.Of(v), out InboundMatchKind back));
            Assert.Equal(v, back);
        }

        foreach (InboundActionState v in Enum.GetValues<InboundActionState>())
        {
            Assert.True(InboundNames.TryParse(InboundNames.Of(v), out InboundActionState back));
            Assert.Equal(v, back);
        }

        foreach (InboundWebhookFormat v in Enum.GetValues<InboundWebhookFormat>())
        {
            Assert.True(InboundNames.TryParse(InboundNames.Of(v), out InboundWebhookFormat back));
            Assert.Equal(v, back);
        }

        Assert.False(InboundNames.TryParse("PASS", out InboundVerdict _));
        Assert.False(InboundNames.TryParse(null, out InboundActionKind _));
    }

    [Fact]
    public void The_stored_numbers_of_the_enums_never_change()
    {
        Assert.Equal([0, 1, 2, 3], Enum.GetValues<InboundActionKind>().Select(v => (int)v));
        Assert.Equal([0, 1, 2], Enum.GetValues<InboundDmarcAction>().Select(v => (int)v));
        Assert.Equal([0, 1, 2], Enum.GetValues<InboundMatchKind>().Select(v => (int)v));
        Assert.Equal([0, 1, 2], Enum.GetValues<InboundActionState>().Select(v => (int)v));
        Assert.Equal([0, 1, 2, 3, 4, 5, 6, 7], Enum.GetValues<InboundVerdict>().Select(v => (int)v));
    }

    [Fact]
    public void The_server_default_retention_follows_the_retention_conventions()
    {
        StorageOptionsValidation.Validate(new StorageOptions());
        StorageOptionsValidation.Validate(new StorageOptions { Inbound = new InboundStorageOptions { RetentionDays = 0 } });
        Assert.Throws<ArgumentException>(() => StorageOptionsValidation.Validate(new StorageOptions { Inbound = new InboundStorageOptions { RetentionDays = -1 } }));
        Assert.Equal(["Inbound:RetentionDays"], StorageOptionsValidation.UnlimitedRetentionKnobs(new StorageOptions { Inbound = new InboundStorageOptions { RetentionDays = 0 } }));
    }
}
