using System.Net;
using Mta.Auth.Spf;
using Mta.Dns;
using static Mta.Auth.Tests.TestZone;

namespace Mta.Auth.Tests.Spf;

public class SpfEvaluatorTests
{
    private const string Helo = "helo.example.net";

    [Theory]
    [MemberData(nameof(SpfCases.All), MemberType = typeof(SpfCases))]
    public async Task Check_host_matches_expected_result(string id, string zone, string ip, string domain, string sender, SpfResult expected, string? matched, string? explanation)
    {
        var evaluator = new SpfEvaluator(Build(zone));
        var result = await evaluator.CheckHostAsync(new SpfCheckRequest(Ip(ip), domain, sender, Helo));

        Assert.True(expected == result.Result, $"{id}: expected {expected} but got {result.Result} ({result.Reason}, matched {result.MatchedMechanism})");
        if (matched is not null)
        {
            Assert.Equal(matched, result.MatchedMechanism);
        }

        if (explanation is not null)
        {
            Assert.Equal(explanation, result.Explanation);
        }
    }

    [Fact]
    public void Case_table_has_at_least_one_hundred_cases()
    {
        var rows = SpfCases.All().ToList();
        Assert.True(rows.Count >= 100, "only " + rows.Count + " cases");
        Assert.Equal(rows.Count, rows.Select(r => (string)r[0]!).Distinct().Count());
    }

    [Fact]
    public async Task Result_reports_lookup_and_void_counts()
    {
        var zone = Build(Z("example.com TXT v=spf1 a:v1.example.org include:i.example.org -all", "i.example.org TXT v=spf1 -all"));
        var result = await new SpfEvaluator(zone).CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", "u@example.com", Helo));
        Assert.Equal(SpfResult.Fail, result.Result);
        Assert.Equal(2, result.DnsLookupCount);
        Assert.Equal(1, result.VoidLookupCount);
        Assert.Equal("example.com", result.Domain);
        Assert.Equal("fail", result.ResultKeyword);
    }

    [Fact]
    public async Task Receiving_host_and_time_macros_come_from_options()
    {
        var zone = Build(Z("example.com TXT v=spf1 -all exp=why.example.org", "why.example.org TXT %{r} at %{t} for %{h}"));
        var options = new SpfOptions { ReceivingHostName = "mx.test", Clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(1700000000)) };
        var result = await new SpfEvaluator(zone, options).CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", "u@example.com", Helo));
        Assert.Equal("mx.test at 1700000000 for helo.example.net", result.Explanation);
    }

    [Fact]
    public async Task Default_explanation_can_be_disabled()
    {
        var zone = Build(Z("example.com TXT v=spf1 -all"));
        var options = new SpfOptions { DefaultExplanation = null };
        var result = await new SpfEvaluator(zone, options).CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", "u@example.com", Helo));
        Assert.Equal(SpfResult.Fail, result.Result);
        Assert.Null(result.Explanation);
    }

    [Fact]
    public async Task Explanations_can_be_disabled()
    {
        var zone = Build(Z("example.com TXT v=spf1 -all exp=why.example.org", "why.example.org TXT nope"));
        var options = new SpfOptions { EvaluateExplanations = false };
        var result = await new SpfEvaluator(zone, options).CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", "u@example.com", Helo));
        Assert.Null(result.Explanation);
    }

    [Fact]
    public async Task Lower_limits_from_options_are_enforced()
    {
        var zone = Build(Z("example.com TXT v=spf1 a:h1.example.org a:h2.example.org a:h3.example.org -all", "h1.example.org A 198.51.100.1", "h2.example.org A 198.51.100.2", "h3.example.org A 198.51.100.3"));
        var result = await new SpfEvaluator(zone, new SpfOptions { MaxDnsLookups = 2 }).CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", "u@example.com", Helo));
        Assert.Equal(SpfResult.PermError, result.Result);
    }

    [Fact]
    public async Task Null_sender_checks_helo_identity_with_postmaster()
    {
        var zone = Build(Z("helo.example.net TXT v=spf1 exists:%{l}.%{o}.example.org -all", "postmaster.helo.example.net.example.org A 127.0.0.2"));
        var session = await new SpfEvaluator(zone).CheckSessionAsync(Ip("192.0.2.3"), Helo, null);
        Assert.Null(session.MailFrom);
        Assert.Equal(SpfResult.Pass, session.Helo.Result);
        Assert.Same(session.Helo, session.Effective);
        Assert.Equal(Helo, session.Effective.Domain);
    }

    [Fact]
    public async Task Session_checks_helo_and_mail_from_separately()
    {
        var zone = Build(Z("helo.example.net TXT v=spf1 -all", "example.com TXT v=spf1 ip4:192.0.2.3 -all"));
        var session = await new SpfEvaluator(zone).CheckSessionAsync(Ip("192.0.2.3"), Helo, "bounce@example.com");
        Assert.Equal(SpfResult.Fail, session.Helo.Result);
        Assert.Equal(SpfResult.Pass, session.MailFrom!.Result);
        Assert.Same(session.MailFrom, session.Effective);
        Assert.Equal("example.com", session.Effective.Domain);
    }

    [Fact]
    public void For_mail_from_without_at_sign_uses_postmaster()
    {
        var request = SpfCheckRequest.ForMailFrom(Ip("192.0.2.3"), Helo, "example.com");
        Assert.Equal("example.com", request.Domain);
        Assert.Equal("postmaster@example.com", request.Sender);
    }

    [Fact]
    public async Task Resolver_exceptions_become_temperror()
    {
        foreach (Exception ex in new Exception[] { new DnsException("timeout"), new InvalidOperationException("boom"), new IOException("io") })
        {
            var evaluator = new SpfEvaluator(new ThrowingResolver(ex));
            var result = await evaluator.CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", "u@example.com", Helo));
            Assert.Equal(SpfResult.TempError, result.Result);
            Assert.DoesNotContain("internal error", result.Reason);
        }
    }

    [Fact]
    public async Task Resolver_exception_deep_in_evaluation_becomes_temperror()
    {
        var inner = Build(Z("example.com TXT v=spf1 a:mail.example.org -all"));
        var resolver = new SelectiveThrowingResolver(inner, DnsRecordType.A);
        var result = await new SpfEvaluator(resolver).CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", "u@example.com", Helo));
        Assert.Equal(SpfResult.TempError, result.Result);
    }

    [Fact]
    public async Task Format_error_rcode_is_temperror()
    {
        var resolver = new FixedRcodeResolver(DnsRcode.FormatError);
        var result = await new SpfEvaluator(resolver).CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", "u@example.com", Helo));
        Assert.Equal(SpfResult.TempError, result.Result);
    }

    [Fact]
    public async Task Slow_dns_hits_the_overall_timeout_and_gives_temperror()
    {
        var evaluator = new SpfEvaluator(new HangingResolver(), new SpfOptions { Timeout = TimeSpan.FromMilliseconds(50) });
        var result = await evaluator.CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", "u@example.com", Helo));
        Assert.Equal(SpfResult.TempError, result.Result);
        Assert.Contains("timed out", result.Reason);
    }

    [Fact]
    public async Task Caller_cancellation_propagates()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var evaluator = new SpfEvaluator(new HangingResolver());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await evaluator.CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", "u@example.com", Helo), cts.Token));
    }

    [Fact]
    public async Task Concurrent_checks_do_not_share_state()
    {
        var zone = Build(Z("example.com TXT v=spf1 a:h1.example.org a:h2.example.org a:h3.example.org a:h4.example.org a:h5.example.org -all",
            "h1.example.org A 198.51.100.1", "h2.example.org A 198.51.100.2", "h3.example.org A 198.51.100.3", "h4.example.org A 198.51.100.4", "h5.example.org A 192.0.2.3"));
        var evaluator = new SpfEvaluator(zone);
        var tasks = Enumerable.Range(0, 200).Select(_ => evaluator.CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", "u@example.com", Helo)).AsTask());
        var results = await Task.WhenAll(tasks);
        Assert.All(results, r =>
        {
            Assert.Equal(SpfResult.Pass, r.Result);
            Assert.Equal(5, r.DnsLookupCount);
        });
    }

    [Fact]
    public async Task Deep_include_chain_cannot_recurse_beyond_the_nesting_limit()
    {
        var lines = new List<string>();
        for (int i = 0; i < 50; i++)
        {
            lines.Add($"n{i}.example.org TXT v=spf1 include:n{i + 1}.example.org -all");
        }

        lines.Add("example.com TXT v=spf1 include:n0.example.org -all");
        var result = await new SpfEvaluator(Build(Z(lines.ToArray())), new SpfOptions { MaxDnsLookups = 1000 })
            .CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", "u@example.com", Helo));
        Assert.Equal(SpfResult.PermError, result.Result);
        Assert.Contains("nesting", result.Reason);
    }

    [Fact]
    public async Task Hostile_record_with_many_terms_and_huge_macro_is_bounded()
    {
        string macros = string.Concat(Enumerable.Repeat("%{s}", 900));
        var zone = Build(Z($"example.com TXT v=spf1 exists:{macros}.example.org -all"));
        var result = await new SpfEvaluator(zone).CheckHostAsync(new SpfCheckRequest(Ip("192.0.2.3"), "example.com", new string('x', 200) + "@example.com", Helo));
        Assert.Equal(SpfResult.PermError, result.Result);
    }

    private sealed class FixedClock(DateTimeOffset now) : Mta.Core.IClock
    {
        public DateTimeOffset UtcNow => now;

        public long Timestamp => 0;
    }

    private sealed class ThrowingResolver(Exception exception) : IDnsResolver
    {
        public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default) => throw exception;
    }

    private sealed class SelectiveThrowingResolver(IDnsResolver inner, DnsRecordType failing) : IDnsResolver
    {
        public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default) =>
            type == failing ? throw new DnsException("timeout") : inner.QueryAsync(name, type, cancellationToken);
    }

    private sealed class FixedRcodeResolver(DnsRcode rcode) : IDnsResolver
    {
        public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(new DnsResponse { Rcode = rcode });
    }

    private sealed class HangingResolver : IDnsResolver
    {
        public async ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return new DnsResponse();
        }
    }
}
