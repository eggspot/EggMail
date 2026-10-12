using System.Security.Authentication;
using Mta.Dns;
using Mta.Tls.Dane;
using Mta.Tls.MtaSts;
using Mta.Tls.Tests.Support;

namespace Mta.Tls.Tests;

public class OutboundTlsPolicyResolverTests
{
    private const string Domain = "example.com";
    private const string Mx = "mail.example.com";

    private static MtaStsPolicy Sts(string mode, params string[] mx)
    {
        string text = $"version: STSv1\nmode: {mode}\n{string.Concat(mx.Select(m => "mx: " + m + "\n"))}max_age: 86400\n";
        Assert.True(MtaStsPolicyParser.TryParse(text, out var p, out string? error), error);
        return p!;
    }

    private static MtaStsLookupResult NoSts() => MtaStsLookupResult.NoPolicy();

    private static MtaStsLookupResult WithSts(MtaStsPolicy p) => new(MtaStsPolicySource.Fetched, p, "id1", null, null);

    private static readonly TlsaRecord EeRecord = new("_25._tcp.mail.example.com", 60, 3, 1, 1, new byte[32]);

    private static DaneLookupResult NoDane() => DaneLookupResult.NotApplicable();

    private static DaneLookupResult UsableDane() =>
        new(DaneStatus.Usable, "_25._tcp.mail.example.com", [EeRecord], [], [Mx], null, []);

    private static DaneLookupResult UnusableDane() =>
        new(DaneStatus.Unusable, "_25._tcp.mail.example.com", [], [new TlsaRecord("n", 1, 1, 1, 1, new byte[32])], [Mx], TlsResultType.TlsaInvalid, ["none usable"]);

    private static DaneLookupResult FailedDane() =>
        new(DaneStatus.LookupFailed, "_25._tcp.mail.example.com", [], [], [], TlsResultType.DnssecInvalid, ["servfail"]);

    private static TlsPolicyDecision Decide(TlsSecurityLevel level, MtaStsLookupResult? sts = null, DaneLookupResult? dane = null, OutboundTlsConfiguration? config = null) =>
        OutboundTlsPolicyResolver.Decide(Domain, Mx, config ?? new OutboundTlsConfiguration { Level = level }, sts ?? NoSts(), dane ?? NoDane());

    // ---- configured level only ----

    [Fact]
    public void Default_is_opportunistic_with_recording_only()
    {
        var d = OutboundTlsPolicyResolver.Decide(Domain, Mx, OutboundTlsConfiguration.Default, NoSts(), NoDane());

        Assert.Equal(TlsSecurityLevel.May, OutboundTlsConfiguration.Default.Level);
        Assert.Equal(TlsPolicyKind.Opportunistic, d.Kind);
        Assert.Equal(TlsPolicyType.NoPolicyFound, d.PolicyType);
        Assert.True(d.AttemptTls);
        Assert.False(d.RequireTls);
        Assert.Equal(TlsValidationMode.None, d.Validation);
        Assert.False(d.EnforceValidation);
        Assert.False(d.FailureMustDefer);
        Assert.True(d.AllowsPlaintextFallback);
        Assert.False(d.IsBlocked);
        Assert.Equal(Mx, d.MxHost);
        Assert.Equal(Mx, d.ExpectedHostname);
    }

    [Fact]
    public void None_disables_tls_and_ignores_sts_and_dane()
    {
        var d = Decide(TlsSecurityLevel.None, WithSts(Sts("enforce", Mx)), UsableDane());
        Assert.Equal(TlsPolicyKind.Disabled, d.Kind);
        Assert.False(d.AttemptTls);
        Assert.False(d.RequireTls);
        Assert.Equal(SslProtocols.None, d.AllowedProtocols);
        Assert.True(d.AllowsPlaintextFallback);
        Assert.Empty(d.TlsaRecords);
        Assert.Null(d.StsPolicy);
    }

    [Fact]
    public void Encrypt_requires_tls_without_validation()
    {
        var d = Decide(TlsSecurityLevel.Encrypt);
        Assert.Equal(TlsPolicyKind.Encrypt, d.Kind);
        Assert.True(d.RequireTls);
        Assert.Equal(TlsValidationMode.None, d.Validation);
        Assert.False(d.EnforceValidation);
        Assert.True(d.FailureMustDefer);
        Assert.False(d.AllowsPlaintextFallback);
        Assert.Equal(SslProtocols.Tls12 | SslProtocols.Tls13, d.AllowedProtocols);
    }

    [Fact]
    public void Verify_requires_tls_and_pkix_validation_for_the_mx_name()
    {
        var d = Decide(TlsSecurityLevel.Verify);
        Assert.Equal(TlsPolicyKind.Verify, d.Kind);
        Assert.True(d.RequireTls);
        Assert.Equal(TlsValidationMode.Pkix, d.Validation);
        Assert.True(d.EnforceValidation);
        Assert.True(d.FailureMustDefer);
        Assert.Equal(Mx, d.ExpectedHostname);
    }

    [Fact]
    public void Opportunistic_protocols_are_configurable_but_enforcing_policies_are_pinned_to_1_2_plus()
    {
        var options = new OutboundTlsOptions { OpportunisticProtocols = SslProtocols.Tls13 };
        var may = OutboundTlsPolicyResolver.Decide(Domain, Mx, OutboundTlsConfiguration.Default, NoSts(), NoDane(), options);
        var verify = OutboundTlsPolicyResolver.Decide(Domain, Mx, new OutboundTlsConfiguration { Level = TlsSecurityLevel.Verify }, NoSts(), NoDane(), options);
        Assert.Equal(SslProtocols.Tls13, may.AllowedProtocols);
        Assert.Equal(SslProtocols.Tls12 | SslProtocols.Tls13, verify.AllowedProtocols);
    }

    // ---- MTA-STS ----

    [Fact]
    public void Sts_enforce_with_allowed_mx_requires_validated_tls_and_defers_on_failure()
    {
        var policy = Sts("enforce", "*.example.com");
        var d = Decide(TlsSecurityLevel.May, WithSts(policy));

        Assert.Equal(TlsPolicyKind.MtaStsEnforce, d.Kind);
        Assert.Equal(TlsPolicyType.Sts, d.PolicyType);
        Assert.True(d.RequireTls);
        Assert.Equal(TlsValidationMode.Pkix, d.Validation);
        Assert.True(d.EnforceValidation);
        Assert.True(d.FailureMustDefer);
        Assert.False(d.AllowsPlaintextFallback);
        Assert.False(d.IsBlocked);
        Assert.Equal(["*.example.com"], d.AllowedMxPatterns);
        Assert.Same(policy, d.StsPolicy);
        Assert.Equal(SslProtocols.Tls12 | SslProtocols.Tls13, d.AllowedProtocols);
        Assert.Equal(TlsPolicyType.Sts, d.TlsRptPolicy.Type);
    }

    [Fact]
    public void Sts_enforce_blocks_an_mx_that_is_not_listed()
    {
        var d = Decide(TlsSecurityLevel.May, WithSts(Sts("enforce", "other.example.org")));

        Assert.True(d.IsBlocked);
        Assert.True(d.FailureMustDefer);
        Assert.Equal(TlsResultType.ValidationFailure, d.BlockedFailure);
        Assert.Contains("not listed", d.BlockedReason);
        Assert.Contains(d.Reasons, r => r.PolicyType == TlsPolicyType.Sts && r.Failure == TlsResultType.ValidationFailure);
    }

    [Fact]
    public void Sts_testing_validates_but_does_not_enforce()
    {
        var d = Decide(TlsSecurityLevel.May, WithSts(Sts("testing", Mx)));

        Assert.Equal(TlsPolicyKind.MtaStsTesting, d.Kind);
        Assert.Equal(TlsPolicyType.Sts, d.PolicyType);
        Assert.False(d.RequireTls);
        Assert.Equal(TlsValidationMode.Pkix, d.Validation);
        Assert.False(d.EnforceValidation);
        Assert.False(d.FailureMustDefer);
        Assert.True(d.AllowsPlaintextFallback);
        Assert.False(d.IsBlocked);
    }

    [Fact]
    public void Sts_testing_with_an_unlisted_mx_still_delivers_but_reports()
    {
        var d = Decide(TlsSecurityLevel.May, WithSts(Sts("testing", "other.example.org")));
        Assert.False(d.IsBlocked);
        Assert.Contains(d.Reasons, r => r.Failure == TlsResultType.ValidationFailure && r.Message.Contains("testing"));
    }

    [Fact]
    public void Sts_testing_never_lowers_a_stricter_configured_level()
    {
        var encrypt = Decide(TlsSecurityLevel.Encrypt, WithSts(Sts("testing", Mx)));
        Assert.True(encrypt.RequireTls);
        Assert.False(encrypt.EnforceValidation);
        Assert.True(encrypt.FailureMustDefer);

        var verify = Decide(TlsSecurityLevel.Verify, WithSts(Sts("testing", Mx)));
        Assert.True(verify.RequireTls);
        Assert.True(verify.EnforceValidation);
        Assert.Equal(TlsValidationMode.Pkix, verify.Validation);
    }

    [Fact]
    public void Sts_mode_none_is_treated_as_no_policy()
    {
        var d = Decide(TlsSecurityLevel.May, WithSts(Sts("none")));
        Assert.Equal(TlsPolicyKind.Opportunistic, d.Kind);
        Assert.Equal(TlsPolicyType.NoPolicyFound, d.PolicyType);
    }

    [Fact]
    public void Sts_fetch_problems_are_carried_as_reasons_even_when_nothing_is_enforced()
    {
        var sts = MtaStsLookupResult.NoPolicy("HTTP 500", TlsResultType.StsPolicyFetchError);
        var d = Decide(TlsSecurityLevel.May, sts);

        Assert.Equal(TlsPolicyKind.Opportunistic, d.Kind);
        var reason = Assert.Single(d.Reasons);
        Assert.Equal(TlsResultType.StsPolicyFetchError, reason.Failure);
        Assert.Equal(TlsPolicyType.Sts, reason.PolicyType);
    }

    [Fact]
    public void A_cached_enforce_policy_with_a_refresh_error_still_enforces_and_reports()
    {
        var sts = new MtaStsLookupResult(MtaStsPolicySource.Cache, Sts("enforce", Mx), "id1", TlsResultType.StsWebpkiInvalid, "refresh failed");
        var d = Decide(TlsSecurityLevel.May, sts);
        Assert.Equal(TlsPolicyKind.MtaStsEnforce, d.Kind);
        Assert.Contains(d.Reasons, r => r.Failure == TlsResultType.StsWebpkiInvalid);
    }

    // ---- DANE ----

    [Fact]
    public void Usable_dane_requires_dane_validation_and_defers_on_failure()
    {
        var d = Decide(TlsSecurityLevel.May, dane: UsableDane());

        Assert.Equal(TlsPolicyKind.Dane, d.Kind);
        Assert.Equal(TlsPolicyType.Tlsa, d.PolicyType);
        Assert.True(d.RequireTls);
        Assert.Equal(TlsValidationMode.Dane, d.Validation);
        Assert.True(d.EnforceValidation);
        Assert.True(d.FailureMustDefer);
        Assert.False(d.AllowsPlaintextFallback);
        Assert.Single(d.TlsaRecords);
        Assert.Empty(d.DaneReferenceNames);
        Assert.Equal(TlsPolicyType.Tlsa, d.TlsRptPolicy.Type);
    }

    [Fact]
    public void Dane_reference_names_exclude_the_mx_itself()
    {
        var dane = new DaneLookupResult(DaneStatus.Usable, "n", [EeRecord], [], ["real.example.net", Mx], null, []);
        var d = Decide(TlsSecurityLevel.May, dane: dane);
        Assert.Equal(["real.example.net"], d.DaneReferenceNames);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("testing")]
    [InlineData("enforce-allowed")]
    [InlineData("enforce-denied")]
    public void Dane_takes_precedence_over_every_sts_state(string stsState)
    {
        MtaStsLookupResult sts = stsState switch
        {
            "testing" => WithSts(Sts("testing", Mx)),
            "enforce-allowed" => WithSts(Sts("enforce", Mx)),
            "enforce-denied" => WithSts(Sts("enforce", "other.example.org")),
            _ => NoSts(),
        };

        var d = Decide(TlsSecurityLevel.May, sts, UsableDane());
        Assert.Equal(TlsPolicyKind.Dane, d.Kind);
        Assert.False(d.IsBlocked); // an STS mx mismatch does not override or block a valid DANE policy
        Assert.Equal(TlsValidationMode.Dane, d.Validation);
        Assert.Null(d.StsPolicy);
    }

    [Theory]
    [InlineData(false, "unusable")]
    [InlineData(true, "unusable")]
    [InlineData(false, "failed")]
    [InlineData(true, "failed")]
    public void A_failing_dane_result_is_not_overridden_by_a_permissive_sts_policy(bool stsAllows, string daneState)
    {
        var sts = WithSts(Sts("testing", stsAllows ? Mx : "other.example.org"));
        var dane = daneState == "unusable" ? UnusableDane() : FailedDane();

        var d = Decide(TlsSecurityLevel.May, sts, dane);
        Assert.True(d.IsBlocked);
        Assert.True(d.FailureMustDefer);
        Assert.False(d.AllowsPlaintextFallback);
        Assert.Equal(TlsPolicyType.Tlsa, d.PolicyType);
        Assert.Equal(daneState == "unusable" ? TlsResultType.TlsaInvalid : TlsResultType.DnssecInvalid, d.BlockedFailure);
        Assert.Contains(d.Reasons, r => r.PolicyType == TlsPolicyType.Tlsa && r.Failure == d.BlockedFailure);
    }

    [Fact]
    public void Require_dane_blocks_mx_hosts_without_a_usable_policy()
    {
        var config = new OutboundTlsConfiguration { RequireDane = true };
        var blocked = Decide(TlsSecurityLevel.May, WithSts(Sts("enforce", Mx)), config: config);
        Assert.True(blocked.IsBlocked);
        Assert.Equal(TlsResultType.DaneRequired, blocked.BlockedFailure);

        var ok = Decide(TlsSecurityLevel.May, dane: UsableDane(), config: config);
        Assert.False(ok.IsBlocked);
        Assert.Equal(TlsPolicyKind.Dane, ok.Kind);
    }

    // ---- full matrix invariants ----

    public static IEnumerable<object[]> Matrix() =>
        from level in Enum.GetValues<TlsSecurityLevel>()
        from sts in new[] { "none", "none-mode", "testing", "enforce", "enforce-denied", "fetch-error" }
        from dane in new[] { "none", "usable", "unusable", "failed" }
        select new object[] { level, sts, dane };

    [Theory]
    [MemberData(nameof(Matrix))]
    public void Matrix_invariants(TlsSecurityLevel level, string stsState, string daneState)
    {
        MtaStsLookupResult sts = stsState switch
        {
            "none-mode" => WithSts(Sts("none")),
            "testing" => WithSts(Sts("testing", Mx)),
            "enforce" => WithSts(Sts("enforce", Mx)),
            "enforce-denied" => WithSts(Sts("enforce", "other.example.org")),
            "fetch-error" => MtaStsLookupResult.NoPolicy("x", TlsResultType.StsPolicyFetchError),
            _ => NoSts(),
        };
        DaneLookupResult dane = daneState switch
        {
            "usable" => UsableDane(),
            "unusable" => UnusableDane(),
            "failed" => FailedDane(),
            _ => NoDane(),
        };

        var d = Decide(level, sts, dane);

        if (level == TlsSecurityLevel.None)
        {
            Assert.Equal(TlsPolicyKind.Disabled, d.Kind);
            Assert.False(d.AttemptTls);
            return;
        }

        Assert.True(d.AttemptTls);
        switch (daneState)
        {
            case "usable":
                Assert.Equal(TlsPolicyKind.Dane, d.Kind);
                Assert.False(d.IsBlocked);
                break;
            case "unusable":
            case "failed":
                Assert.True(d.IsBlocked);
                Assert.Equal(TlsPolicyType.Tlsa, d.PolicyType);
                break;
            default:
                Assert.NotEqual(TlsPolicyKind.Dane, d.Kind);
                if (stsState == "enforce")
                {
                    Assert.Equal(TlsPolicyKind.MtaStsEnforce, d.Kind);
                }

                if (stsState == "enforce-denied")
                {
                    Assert.True(d.IsBlocked);
                }

                break;
        }

        // Requirement monotonicity: nothing in the matrix may weaken the configured floor.
        if (level >= TlsSecurityLevel.Encrypt)
        {
            Assert.True(d.RequireTls);
        }

        if (level == TlsSecurityLevel.Verify)
        {
            Assert.True(d.EnforceValidation);
            Assert.NotEqual(TlsValidationMode.None, d.Validation);
        }

        // Structural invariants.
        if (d.IsBlocked)
        {
            Assert.True(d.FailureMustDefer);
            Assert.NotNull(d.BlockedReason);
            Assert.NotNull(d.BlockedFailure);
        }

        if (d.RequireTls)
        {
            Assert.True(d.FailureMustDefer);
            Assert.Equal(SslProtocols.Tls12 | SslProtocols.Tls13, d.AllowedProtocols);
        }

        Assert.Equal(!d.RequireTls && !d.IsBlocked, d.AllowsPlaintextFallback);
        if (d.Validation == TlsValidationMode.Dane)
        {
            Assert.True(d.EnforceValidation);
        }

    }

    // ---- wiring through real lookups ----

    private sealed class Wiring
    {
        public TestClock Clock { get; } = new();
        public ScriptedDnsResolver Dns { get; } = new();
        public FakePolicyFetcher Fetcher { get; } = new();
        public OutboundTlsPolicyResolver Resolver { get; }

        public Wiring()
        {
            var store = new MtaStsPolicyStore(Dns, Fetcher, new InMemoryMtaStsCache(Clock), Clock);
            Resolver = new OutboundTlsPolicyResolver(store, new DaneTlsaLookup(Dns));
            Dns.SetTxt("_mta-sts.example.com", "v=STSv1; id=1");
            Fetcher.OnFetch = _ => FakePolicyFetcher.Ok("version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 3600\n");
        }
    }

    [Fact]
    public async Task Resolves_sts_enforce_through_the_store()
    {
        var w = new Wiring();
        var d = await w.Resolver.ResolveAsync(Domain, Mx, null, mxRrsetAuthenticated: false);
        Assert.Equal(TlsPolicyKind.MtaStsEnforce, d.Kind);
        Assert.Equal(1, w.Fetcher.Calls);
    }

    [Fact]
    public async Task Domain_context_is_reused_for_several_mx_hosts_with_one_sts_fetch()
    {
        var w = new Wiring();
        var context = await w.Resolver.ResolveDomainAsync(Domain);
        var a = await w.Resolver.ResolveForMxAsync(context, "mx1.example.com", false);
        var b = await w.Resolver.ResolveForMxAsync(context, "mx2.example.com", false);
        var c = await w.Resolver.ResolveForMxAsync(context, "mx.other.org", false);

        Assert.Equal(TlsPolicyKind.MtaStsEnforce, a.Kind);
        Assert.Equal(TlsPolicyKind.MtaStsEnforce, b.Kind);
        Assert.True(c.IsBlocked);
        Assert.Equal(1, w.Fetcher.Calls);
    }

    [Fact]
    public async Task Dane_found_through_dns_wins_over_the_sts_policy()
    {
        var w = new Wiring();
        w.Dns.Set("_25._tcp.mail.example.com", DnsRecordType.TLSA, new DnsResponse { AuthenticatedData = true, Answers = [EeRecord] });
        var d = await w.Resolver.ResolveAsync(Domain, Mx, null, mxRrsetAuthenticated: true);
        Assert.Equal(TlsPolicyKind.Dane, d.Kind);
    }

    [Fact]
    public async Task Dane_is_skipped_when_the_mx_rrset_was_not_authenticated()
    {
        var w = new Wiring();
        w.Dns.Set("_25._tcp.mail.example.com", DnsRecordType.TLSA, new DnsResponse { AuthenticatedData = true, Answers = [EeRecord] });
        var d = await w.Resolver.ResolveAsync(Domain, Mx, null, mxRrsetAuthenticated: false);
        Assert.Equal(TlsPolicyKind.MtaStsEnforce, d.Kind);
    }

    [Fact]
    public async Task Disabling_sts_and_dane_per_domain_skips_the_lookups()
    {
        var w = new Wiring();
        w.Dns.Set("_25._tcp.mail.example.com", DnsRecordType.TLSA, new DnsResponse { AuthenticatedData = true, Answers = [EeRecord] });
        var config = new OutboundTlsConfiguration { EnableMtaSts = false, EnableDane = false };
        var d = await w.Resolver.ResolveAsync(Domain, Mx, config, mxRrsetAuthenticated: true);

        Assert.Equal(TlsPolicyKind.Opportunistic, d.Kind);
        Assert.Equal(0, w.Dns.Queries);
        Assert.Equal(0, w.Fetcher.Calls);
    }

    [Fact]
    public async Task Level_none_does_no_lookups_at_all()
    {
        var w = new Wiring();
        var d = await w.Resolver.ResolveAsync(Domain, Mx, new OutboundTlsConfiguration { Level = TlsSecurityLevel.None }, mxRrsetAuthenticated: true);
        Assert.Equal(TlsPolicyKind.Disabled, d.Kind);
        Assert.Equal(0, w.Dns.Queries);
    }

    [Fact]
    public async Task Resolver_without_sources_falls_back_to_the_configured_level()
    {
        var resolver = new OutboundTlsPolicyResolver(null, null);
        var d = await resolver.ResolveAsync(Domain, Mx, new OutboundTlsConfiguration { Level = TlsSecurityLevel.Verify }, mxRrsetAuthenticated: true);
        Assert.Equal(TlsPolicyKind.Verify, d.Kind);
    }

    [Fact]
    public async Task Invalid_domain_still_yields_a_decision()
    {
        var resolver = new OutboundTlsPolicyResolver(null, null);
        var d = await resolver.ResolveAsync("not a domain", Mx, null, mxRrsetAuthenticated: false);
        Assert.Equal(TlsPolicyKind.Opportunistic, d.Kind);
    }

    [Fact]
    public void Tls_rpt_descriptor_for_no_policy()
    {
        var d = Decide(TlsSecurityLevel.May);
        Assert.Equal(TlsPolicyType.NoPolicyFound, d.TlsRptPolicy.Type);
        Assert.Empty(d.TlsRptPolicy.PolicyString);
    }
}
