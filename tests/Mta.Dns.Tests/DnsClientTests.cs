using System.Collections.Concurrent;
using System.Net;

namespace Mta.Dns.Tests;

internal sealed class FakeQuery
{
    public required byte[] Bytes { get; init; }

    public required string Name { get; init; }

    public required DnsRecordType Type { get; init; }

    public required int Index { get; init; }

    public CancellationToken Token { get; init; }

    public bool HasEdns => DnsMessageReader.Parse(Bytes).AdditionalCount > 0;

    public PacketBuilder Reply(int rcode = 0) => PacketBuilder.ReplyTo(Bytes, rcode);
}

internal sealed class FakeTransport : IDnsTransport
{
    private readonly Func<FakeQuery, Task<byte[]>> _handler;
    private int _calls;

    public FakeTransport(Func<FakeQuery, byte[]> handler) => _handler = q => Task.FromResult(handler(q));

    public FakeTransport(Func<FakeQuery, Task<byte[]>> handler) => _handler = handler;

    public static FakeTransport Throwing(Exception exception) => new((Func<FakeQuery, byte[]>)(_ => throw exception));

    public int Calls => Volatile.Read(ref _calls);

    public ConcurrentQueue<FakeQuery> Queries { get; } = new();

    public async ValueTask<ReadOnlyMemory<byte>> ExchangeAsync(ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
    {
        // The caller reuses its buffer after this returns, so copy.
        byte[] copy = query.ToArray();
        var parsed = DnsMessageReader.Parse(copy);
        var q = new FakeQuery { Bytes = copy, Name = parsed.QuestionName!, Type = parsed.QuestionType, Index = Interlocked.Increment(ref _calls), Token = cancellationToken };
        Queries.Enqueue(q);
        return await _handler(q);
    }
}

public class DnsClientTests
{
    private static readonly TimeSpan Second = TimeSpan.FromSeconds(1);

    private static DnsResolverOptions Opts(Func<DnsResolverOptions, DnsResolverOptions>? tweak = null)
    {
        var o = new DnsResolverOptions { MinCacheTtl = TimeSpan.Zero, EdnsUdpPayloadSize = 1232 };
        return tweak is null ? o : tweak(o);
    }

    private static byte[] Echo(FakeQuery q) => q.Reply().A(q.Name, "192.0.2.1", 300).Build();

    [Fact]
    public async Task Resolves_and_serves_the_second_query_from_cache_with_decayed_ttls()
    {
        var clock = new FakeClock();
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(), clock);

        var first = await client.QueryAsync("Example.COM", DnsRecordType.A);
        Assert.True(first.IsSuccess);
        Assert.Equal(300u, first.Ttl);
        Assert.Equal(IPAddress.Parse("192.0.2.1"), Assert.IsType<ARecord>(Assert.Single(first.Answers)).Address);

        clock.Advance(TimeSpan.FromSeconds(100));
        var second = await client.QueryAsync("example.com.", DnsRecordType.A);
        Assert.Equal(1, transport.Calls);
        Assert.Equal(200u, second.Ttl);
        Assert.Equal(200u, second.Answers[0].Ttl);
        Assert.Equal(1, client.CachedEntryCount);
    }

    [Fact]
    public async Task Entries_expire_exactly_at_their_ttl()
    {
        var clock = new FakeClock();
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(), clock);
        await client.QueryAsync("example.com", DnsRecordType.A);
        clock.Advance(TimeSpan.FromSeconds(299));
        await client.QueryAsync("example.com", DnsRecordType.A);
        Assert.Equal(1, transport.Calls);
        clock.Advance(Second);
        await client.QueryAsync("example.com", DnsRecordType.A);
        Assert.Equal(2, transport.Calls);
    }

    [Fact]
    public async Task A_clock_that_goes_backwards_does_not_extend_entries()
    {
        var clock = new FakeClock();
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(), clock);
        await client.QueryAsync("example.com", DnsRecordType.A);
        clock.Advance(TimeSpan.FromHours(-1));
        await client.QueryAsync("example.com", DnsRecordType.A);
        Assert.Equal(2, transport.Calls);
    }

    [Fact]
    public async Task Nxdomain_is_cached_for_the_soa_minimum_but_no_longer_than_the_cap()
    {
        var clock = new FakeClock();
        var transport = new FakeTransport(q => q.Reply(rcode: 3).Soa("example.com", 3600, 60).Build());
        var client = new DnsClient(transport, Opts(), clock);

        var r = await client.QueryAsync("nope.example.com", DnsRecordType.A);
        Assert.True(r.IsNxDomain);
        Assert.False(r.IsSuccess);
        Assert.Empty(r.Answers);
        Assert.Equal(60u, r.Ttl);

        clock.Advance(TimeSpan.FromSeconds(59));
        Assert.True((await client.QueryAsync("nope.example.com", DnsRecordType.A)).IsNxDomain);
        Assert.Equal(1, transport.Calls);
        clock.Advance(TimeSpan.FromSeconds(2));
        await client.QueryAsync("nope.example.com", DnsRecordType.A);
        Assert.Equal(2, transport.Calls);

        var huge = new FakeTransport(q => q.Reply(rcode: 3).Soa("example.com", 86400, 86400).Build());
        var capped = new DnsClient(huge, Opts(), clock);
        Assert.Equal(300u, (await capped.QueryAsync("nope.example.com", DnsRecordType.A)).Ttl);
    }

    [Fact]
    public async Task Nodata_is_a_cached_success_with_no_answers_and_uses_the_default_when_there_is_no_soa()
    {
        var clock = new FakeClock();
        var transport = new FakeTransport(q => q.Reply().Build());
        var client = new DnsClient(transport, Opts(), clock);
        var r = await client.QueryAsync("example.com", DnsRecordType.MX);
        Assert.True(r.IsSuccess);
        Assert.False(r.IsNxDomain);
        Assert.Empty(r.Answers);
        Assert.Equal(30u, r.Ttl);
        await client.QueryAsync("example.com", DnsRecordType.MX);
        Assert.Equal(1, transport.Calls);
    }

    [Fact]
    public async Task Positive_ttls_are_clamped_to_the_configured_range()
    {
        var clock = new FakeClock();
        var low = new FakeTransport(q => q.Reply().A(q.Name, "192.0.2.1", 1).Build());
        var clientLow = new DnsClient(low, Opts(o => o with { MinCacheTtl = TimeSpan.FromSeconds(30) }), clock);
        Assert.Equal(30u, (await clientLow.QueryAsync("a.example", DnsRecordType.A)).Ttl);
        clock.Advance(TimeSpan.FromSeconds(29));
        await clientLow.QueryAsync("a.example", DnsRecordType.A);
        Assert.Equal(1, low.Calls);

        var high = new FakeTransport(q => q.Reply().A(q.Name, "192.0.2.1", 4_000_000).Build());
        var clientHigh = new DnsClient(high, Opts(o => o with { MaxCacheTtl = TimeSpan.FromMinutes(10) }), clock);
        Assert.Equal(600u, (await clientHigh.QueryAsync("a.example", DnsRecordType.A)).Ttl);
    }

    [Fact]
    public async Task Ttl_zero_is_not_cached_when_the_minimum_is_zero()
    {
        var transport = new FakeTransport(q => q.Reply().A(q.Name, "192.0.2.1", 0).Build());
        var client = new DnsClient(transport, Opts(), new FakeClock());
        await client.QueryAsync("a.example", DnsRecordType.A);
        await client.QueryAsync("a.example", DnsRecordType.A);
        Assert.Equal(2, transport.Calls);
    }

    [Fact]
    public async Task Servfail_is_returned_as_a_response_and_never_cached()
    {
        var transport = new FakeTransport(q => q.Reply(rcode: 2).Build());
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var r = await client.QueryAsync("example.com", DnsRecordType.TXT);
        Assert.Equal(DnsRcode.ServerFailure, r.Rcode);
        Assert.False(r.IsSuccess);
        Assert.False(r.IsNxDomain);
        Assert.Empty(r.Answers);
        await client.QueryAsync("example.com", DnsRecordType.TXT);
        Assert.Equal(2, transport.Calls);
    }

    [Theory]
    [InlineData(1, DnsRcode.FormatError)]
    [InlineData(4, DnsRcode.NotImplemented)]
    [InlineData(5, DnsRcode.Refused)]
    public async Task Other_error_rcodes_are_surfaced(int rcode, DnsRcode expected)
    {
        var transport = new FakeTransport(q => q.Reply(rcode).Build());
        var client = new DnsClient(transport, Opts(o => o with { EdnsUdpPayloadSize = 0 }), new FakeClock());
        Assert.Equal(expected, (await client.QueryAsync("example.com", DnsRecordType.A)).Rcode);
    }

    [Fact]
    public async Task Transport_failures_become_DnsException_and_are_not_cached()
    {
        bool fail = true;
        var transport = new FakeTransport(q => fail ? throw new DnsException("boom", DnsFailureReason.Timeout) : Echo(q));
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var ex = await Assert.ThrowsAsync<DnsException>(async () => await client.QueryAsync("example.com", DnsRecordType.A));
        Assert.Equal(DnsFailureReason.Timeout, ex.Reason);
        fail = false;
        Assert.True((await client.QueryAsync("example.com", DnsRecordType.A)).IsSuccess);
    }

    [Fact]
    public async Task Unexpected_transport_exceptions_are_wrapped()
    {
        var client = new DnsClient(FakeTransport.Throwing(new InvalidOperationException("bug")), Opts(), new FakeClock());
        var ex = await Assert.ThrowsAsync<DnsException>(async () => await client.QueryAsync("example.com", DnsRecordType.A));
        Assert.IsType<InvalidOperationException>(ex.InnerException?.InnerException ?? ex.InnerException);
        var cancelling = new DnsClient(FakeTransport.Throwing(new OperationCanceledException()), Opts(), new FakeClock());
        var timeout = await Assert.ThrowsAsync<DnsException>(async () => await cancelling.QueryAsync("example.com", DnsRecordType.A));
        Assert.Equal(DnsFailureReason.Timeout, timeout.Reason);
    }

    [Fact]
    public async Task A_transport_that_never_answers_is_cut_off_by_the_query_timeout()
    {
        var transport = new FakeTransport(async q =>
        {
            await Task.Delay(Timeout.Infinite, q.Token);
            return [];
        });
        var client = new DnsClient(transport, Opts(o => o with { QueryTimeout = TimeSpan.FromMilliseconds(200) }), new FakeClock());
        var ex = await Assert.ThrowsAsync<DnsException>(async () => await client.QueryAsync("example.com", DnsRecordType.A));
        Assert.Equal(DnsFailureReason.Timeout, ex.Reason);
    }

    /// <summary>Polls a condition with a deadline far above any plausible load (the deadline only matters when the test is about to fail).</summary>
    private static async Task UntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "condition not met within 60 s");
            await Task.Delay(5);
        }
    }

    [Fact]
    public async Task Concurrent_identical_queries_share_one_network_query()
    {
        var gate = new TaskCompletionSource();
        var transport = new FakeTransport(async q =>
        {
            await gate.Task;
            return Echo(q);
        });
        var client = new DnsClient(transport, Opts(), new FakeClock());

        // QueryAsync joins or starts the shared query synchronously, so when the next line runs all 50 callers have joined.
        var tasks = Enumerable.Range(0, 50).Select(_ => client.QueryAsync("example.com", DnsRecordType.A).AsTask()).ToArray();
        var other = client.QueryAsync("example.com", DnsRecordType.AAAA).AsTask();   // different question: its own query
        await UntilAsync(() => transport.Calls == 2);
        gate.SetResult();
        var results = await Task.WhenAll(tasks);
        await other;

        Assert.Equal(2, transport.Calls);
        Assert.All(results, r => Assert.True(r.IsSuccess));
        Assert.Single(results.Select(r => r.Answers[0]).Distinct());
    }

    [Fact]
    public async Task Coalesced_callers_all_see_the_same_failure()
    {
        var gate = new TaskCompletionSource();
        var transport = new FakeTransport(async q =>
        {
            await gate.Task;
            throw new DnsException("down", DnsFailureReason.Network);
        });
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var tasks = Enumerable.Range(0, 10).Select(async _ =>
        {
            var ex = await Assert.ThrowsAsync<DnsException>(async () => await client.QueryAsync("example.com", DnsRecordType.A));
            return ex.Reason;
        }).ToArray();   // each caller has joined the shared query by the time Select returns (the call is made before the first await)
        gate.SetResult();
        Assert.All(await Task.WhenAll(tasks), reason => Assert.Equal(DnsFailureReason.Network, reason));
        Assert.Equal(1, transport.Calls);
    }

    [Fact]
    public async Task Cancelling_one_caller_does_not_disturb_the_shared_query()
    {
        var gate = new TaskCompletionSource();
        var transport = new FakeTransport(async q =>
        {
            await gate.Task;
            return Echo(q);
        });
        var client = new DnsClient(transport, Opts(), new FakeClock());
        using var cts = new CancellationTokenSource();
        var cancelled = client.QueryAsync("example.com", DnsRecordType.A, cts.Token).AsTask();
        var patient = client.QueryAsync("example.com", DnsRecordType.A).AsTask();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await cancelled);
        gate.SetResult();
        Assert.True((await patient).IsSuccess);
        Assert.Equal(1, transport.Calls);
        // and the answer was cached
        await client.QueryAsync("example.com", DnsRecordType.A);
        Assert.Equal(1, transport.Calls);
    }

    [Fact]
    public async Task A_token_that_is_already_cancelled_throws_before_any_work()
    {
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(), new FakeClock());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await client.QueryAsync("example.com", DnsRecordType.A, new CancellationToken(true)));
        Assert.Equal(0, transport.Calls);
    }

    [Fact]
    public async Task Parallel_mixed_load_queries_each_name_once()
    {
        var transport = new FakeTransport(async q =>
        {
            await Task.Yield();
            return Echo(q);
        });
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var tasks = Enumerable.Range(0, 2000).Select(i => Task.Run(async () =>
        {
            var r = await client.QueryAsync($"host{i % 20}.example.com", DnsRecordType.A);
            Assert.True(r.IsSuccess);
        }));
        await Task.WhenAll(tasks);
        Assert.Equal(20, transport.Calls);
    }

    [Fact]
    public async Task Cname_chain_inside_one_response_is_included_in_answers()
    {
        var transport = new FakeTransport(q => q.Reply()
            .Cname("www.example.com", "a.cdn.example.net", 100)
            .Cname("a.cdn.example.net", "b.cdn.example.net", 50)
            .A("b.cdn.example.net", "198.51.100.1", 200).Build());
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var r = await client.QueryAsync("www.example.com", DnsRecordType.A);
        Assert.Equal(3, r.Answers.Count);
        Assert.IsType<CnameRecord>(r.Answers[0]);
        Assert.IsType<CnameRecord>(r.Answers[1]);
        Assert.IsType<ARecord>(r.Answers[2]);
        Assert.Equal(50u, r.Ttl);
        Assert.Equal(1, transport.Calls);
    }

    [Fact]
    public async Task Cname_not_followed_by_the_server_is_chased_with_further_queries()
    {
        var transport = new FakeTransport(q => q.Name switch
        {
            "www.example.com" => q.Reply().Cname("www.example.com", "edge.example.net", 100).Build(),
            "edge.example.net" => q.Reply().A("edge.example.net", "198.51.100.1", 200).Build(),
            _ => q.Reply(rcode: 3).Build(),
        });
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var r = await client.QueryAsync("www.example.com", DnsRecordType.A);
        Assert.True(r.IsSuccess);
        Assert.Equal(2, r.Answers.Count);
        Assert.Equal(["www.example.com", "edge.example.net"], r.Answers.Select(a => a.Name));
        Assert.Equal(2, transport.Calls);
        Assert.Equal(100u, r.Ttl);
    }

    [Fact]
    public async Task Cname_to_a_missing_name_is_nxdomain_with_the_cname_in_the_answers()
    {
        var transport = new FakeTransport(q => q.Name == "www.example.com"
            ? q.Reply().Cname("www.example.com", "gone.example.net").Build()
            : q.Reply(rcode: 3).Soa("example.net", 100, 20).Build());
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var r = await client.QueryAsync("www.example.com", DnsRecordType.A);
        Assert.True(r.IsNxDomain);
        Assert.IsType<CnameRecord>(Assert.Single(r.Answers));
    }

    [Fact]
    public async Task Cname_to_a_name_without_data_is_nodata_and_is_not_chased_again_when_the_server_sent_an_soa()
    {
        var transport = new FakeTransport(q => q.Reply().Cname("www.example.com", "edge.example.net").Soa("example.net", 100, 20).Build());
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var r = await client.QueryAsync("www.example.com", DnsRecordType.MX);
        Assert.True(r.IsSuccess);
        Assert.IsType<CnameRecord>(Assert.Single(r.Answers));
        Assert.Equal(20u, r.Ttl);
        Assert.Equal(1, transport.Calls);
    }

    [Fact]
    public async Task Cname_loop_inside_a_response_is_an_error()
    {
        var transport = new FakeTransport(q => q.Reply().Cname("a.example", "b.example").Cname("b.example", "a.example").Build());
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var ex = await Assert.ThrowsAsync<DnsException>(async () => await client.QueryAsync("a.example", DnsRecordType.A));
        Assert.Equal(DnsFailureReason.ResolutionLimit, ex.Reason);
    }

    [Fact]
    public async Task Cname_loop_across_queries_is_an_error()
    {
        var transport = new FakeTransport(q => q.Name == "a.example"
            ? q.Reply().Cname("a.example", "b.example").Build()
            : q.Reply().Cname("b.example", "a.example").Build());
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var ex = await Assert.ThrowsAsync<DnsException>(async () => await client.QueryAsync("a.example", DnsRecordType.A));
        Assert.Equal(DnsFailureReason.ResolutionLimit, ex.Reason);
        Assert.Equal(2, transport.Calls);
    }

    [Fact]
    public async Task Self_referencing_cname_is_an_error()
    {
        var transport = new FakeTransport(q => q.Reply().Cname("a.example", "a.example").Build());
        var client = new DnsClient(transport, Opts(), new FakeClock());
        await Assert.ThrowsAsync<DnsException>(async () => await client.QueryAsync("a.example", DnsRecordType.A));
    }

    [Theory]
    [InlineData(8, true)]
    [InlineData(9, false)]
    public async Task Cname_chain_depth_is_limited(int length, bool allowed)
    {
        var transport = new FakeTransport(q =>
        {
            var b = q.Reply();
            for (int i = 0; i < length; i++)
            {
                b.Cname($"n{i}.example", $"n{i + 1}.example");
            }

            return b.A($"n{length}.example", "192.0.2.1").Build();
        });
        var client = new DnsClient(transport, Opts(), new FakeClock());
        if (allowed)
        {
            Assert.Equal(length + 1, (await client.QueryAsync("n0.example", DnsRecordType.A)).Answers.Count);
        }
        else
        {
            var ex = await Assert.ThrowsAsync<DnsException>(async () => await client.QueryAsync("n0.example", DnsRecordType.A));
            Assert.Equal(DnsFailureReason.ResolutionLimit, ex.Reason);
        }
    }

    [Fact]
    public async Task Cname_chain_that_is_chased_across_queries_is_also_depth_limited()
    {
        var transport = new FakeTransport(q =>
        {
            int n = int.Parse(q.Name[1..q.Name.IndexOf('.')]);
            return q.Reply().Cname(q.Name, $"n{n + 1}.example").Build();
        });
        var client = new DnsClient(transport, Opts(), new FakeClock());
        await Assert.ThrowsAsync<DnsException>(async () => await client.QueryAsync("n0.example", DnsRecordType.A));
        Assert.Equal(9, transport.Calls);
    }

    [Fact]
    public async Task Cname_and_any_queries_are_not_chased()
    {
        var transport = new FakeTransport(q => q.Reply().Cname("www.example.com", "edge.example.net").A("www.example.com", "192.0.2.1").Build());
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var cname = await client.QueryAsync("www.example.com", DnsRecordType.CNAME);
        Assert.IsType<CnameRecord>(Assert.Single(cname.Answers));
        var any = await client.QueryAsync("www.example.com", DnsRecordType.ANY);
        Assert.Equal(2, any.Answers.Count);
        Assert.Equal(2, transport.Calls);
    }

    [Fact]
    public async Task Records_that_do_not_belong_to_the_question_are_dropped()
    {
        var transport = new FakeTransport(q => q.Reply()
            .A("example.com", "192.0.2.1")
            .A("bank.example", "203.0.113.66")          // unrelated owner: cache-poisoning attempt
            .Aaaa("example.com", "2001:db8::1")          // wrong type
            .Cname("other.example", "example.com")       // not on our chain
            .Build());
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var r = await client.QueryAsync("example.com", DnsRecordType.A);
        Assert.Equal("192.0.2.1", Assert.IsType<ARecord>(Assert.Single(r.Answers)).Address.ToString());
        var poisoned = await client.QueryAsync("bank.example", DnsRecordType.A);   // must still go to the network
        Assert.Equal(2, transport.Calls);
        Assert.Equal("203.0.113.66", Assert.IsType<ARecord>(Assert.Single(poisoned.Answers)).Address.ToString());
    }

    [Fact]
    public async Task Responses_with_the_wrong_id_question_or_flags_are_rejected()
    {
        async Task Expect(Func<FakeQuery, byte[]> make, DnsFailureReason reason)
        {
            var client = new DnsClient(new FakeTransport(make), Opts(), new FakeClock());
            var ex = await Assert.ThrowsAsync<DnsException>(async () => await client.QueryAsync("example.com", DnsRecordType.A));
            Assert.Equal(reason, ex.Reason);
        }

        await Expect(q =>
        {
            var b = q.Reply().A(q.Name, "192.0.2.1");
            b.Id ^= 0x1000;
            return b.Build();
        }, DnsFailureReason.ResponseMismatch);
        await Expect(q => PacketBuilder.Response(BitConverter.ToUInt16([q.Bytes[1], q.Bytes[0]]), "evil.example", DnsRecordType.A).A("evil.example", "203.0.113.1").Build(), DnsFailureReason.ResponseMismatch);
        await Expect(q => PacketBuilder.Response(BitConverter.ToUInt16([q.Bytes[1], q.Bytes[0]]), q.Name, DnsRecordType.MX).Build(), DnsFailureReason.ResponseMismatch);
        await Expect(q =>
        {
            var b = q.Reply().A(q.Name, "192.0.2.1");
            b.Flags = 0x0100; // QR clear: this is a query, not a response
            return b.Build();
        }, DnsFailureReason.ResponseMismatch);
        await Expect(q => q.Reply().A(q.Name, "192.0.2.1").Truncated().Build(), DnsFailureReason.ResponseMismatch);
        await Expect(q => q.Reply().NoQuestion().Build(), DnsFailureReason.ResponseMismatch);
        await Expect(_ => [1, 2, 3], DnsFailureReason.ResponseMismatch);
        await Expect(q => q.Reply().Raw(q.Name, 1, [1, 2, 3]).Build(), DnsFailureReason.MalformedResponse);
    }

    [Fact]
    public async Task Ad_bit_is_ignored_unless_trusted()
    {
        var transport = new FakeTransport(q => q.Reply().AuthenticData().A(q.Name, "192.0.2.1").Build());
        var untrusting = new DnsClient(transport, Opts(), new FakeClock());
        Assert.False((await untrusting.QueryAsync("example.com", DnsRecordType.A)).AuthenticatedData);

        var trusting = new DnsClient(transport, Opts(o => o with { TrustAuthenticatedData = true, RequestDnssecOk = true }), new FakeClock());
        Assert.True((await trusting.QueryAsync("example.com", DnsRecordType.A)).AuthenticatedData);

        var plain = new DnsClient(new FakeTransport(Echo), Opts(o => o with { TrustAuthenticatedData = true }), new FakeClock());
        Assert.False((await plain.QueryAsync("example.com", DnsRecordType.A)).AuthenticatedData);
    }

    [Fact]
    public async Task Ad_must_hold_for_every_hop_of_a_chased_cname()
    {
        var transport = new FakeTransport(q => q.Name == "www.example.com"
            ? q.Reply().AuthenticData().Cname(q.Name, "edge.example.net").Build()
            : q.Reply().A(q.Name, "192.0.2.1").Build());
        var client = new DnsClient(transport, Opts(o => o with { TrustAuthenticatedData = true }), new FakeClock());
        Assert.False((await client.QueryAsync("www.example.com", DnsRecordType.A)).AuthenticatedData);
    }

    [Fact]
    public async Task Query_flags_follow_the_dnssec_options()
    {
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(o => o with { RequestDnssecOk = true, TrustAuthenticatedData = true, CheckingDisabled = false }), new FakeClock());
        await client.QueryAsync("example.com", DnsRecordType.A);
        var q = transport.Queries.Single().Bytes;
        Assert.True(DnsWire.TryReadHeader(q, out var h));
        Assert.True(h.RecursionDesired);
        Assert.True(h.AuthenticData);
        Assert.Equal(0x8000, (q[^4] << 8) | q[^3]);   // DO bit in the OPT TTL flags

        var plainTransport = new FakeTransport(Echo);
        var plain = new DnsClient(plainTransport, Opts(), new FakeClock());
        await plain.QueryAsync("example.com", DnsRecordType.A);
        var pq = plainTransport.Queries.Single().Bytes;
        DnsWire.TryReadHeader(pq, out var ph);
        Assert.False(ph.AuthenticData);
        Assert.Equal(0, (pq[^4] << 8) | pq[^3]);
    }

    [Fact]
    public async Task Formerr_to_an_edns_query_is_retried_without_edns()
    {
        var transport = new FakeTransport(q => q.HasEdns ? q.Reply(rcode: 1).Build() : Echo(q));
        var client = new DnsClient(transport, Opts(), new FakeClock());
        var r = await client.QueryAsync("example.com", DnsRecordType.A);
        Assert.True(r.IsSuccess);
        Assert.Equal(2, transport.Calls);
        Assert.False(transport.Queries.Last().HasEdns);
    }

    [Fact]
    public async Task Edns_can_be_switched_off()
    {
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(o => o with { EdnsUdpPayloadSize = 0, RequestDnssecOk = true }), new FakeClock());
        await client.QueryAsync("example.com", DnsRecordType.A);
        Assert.False(transport.Queries.Single().HasEdns);
    }

    [Fact]
    public async Task Invalid_names_are_nxdomain_without_touching_the_network()
    {
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(), new FakeClock());
        foreach (var name in new[] { "a..b", "bad name.example", new string('a', 70) + ".example", "x\\y.example", "\ud800.example" })
        {
            Assert.True((await client.QueryAsync(name, DnsRecordType.A)).IsNxDomain, name);
        }

        Assert.Equal(0, transport.Calls);
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await client.QueryAsync(null!, DnsRecordType.A));
    }

    [Fact]
    public async Task Internationalized_names_are_sent_as_punycode()
    {
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(), new FakeClock());
        await client.QueryAsync("Bücher.Example", DnsRecordType.A);
        Assert.Equal("xn--bcher-kva.example", transport.Queries.Single().Name);
    }

    [Fact]
    public async Task Cache_is_bounded_and_evicts_least_recently_used()
    {
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(o => o with { MaxCacheEntries = 4 }), new FakeClock());
        foreach (var n in new[] { "a", "b", "c", "d" })
        {
            await client.QueryAsync(n + ".example", DnsRecordType.A);
        }

        await client.QueryAsync("a.example", DnsRecordType.A);   // touch a: b is now the oldest
        await client.QueryAsync("e.example", DnsRecordType.A);   // evicts b
        Assert.Equal(4, client.CachedEntryCount);
        Assert.Equal(5, transport.Calls);
        await client.QueryAsync("a.example", DnsRecordType.A);
        Assert.Equal(5, transport.Calls);
        await client.QueryAsync("b.example", DnsRecordType.A);
        Assert.Equal(6, transport.Calls);
    }

    [Fact]
    public async Task Large_workloads_never_exceed_the_cache_capacity()
    {
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(o => o with { MaxCacheEntries = 64 }), new FakeClock());
        for (int i = 0; i < 2000; i++)
        {
            await client.QueryAsync($"h{i}.example", DnsRecordType.A);
            Assert.True(client.CachedEntryCount <= 64);
        }

        Assert.True(client.CachedEntryCount > 0);
    }

    [Fact]
    public async Task A_disabled_cache_still_coalesces_but_does_not_remember()
    {
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(o => o with { MaxCacheEntries = 0 }), new FakeClock());
        await client.QueryAsync("example.com", DnsRecordType.A);
        await client.QueryAsync("example.com", DnsRecordType.A);
        Assert.Equal(2, transport.Calls);
        Assert.Equal(0, client.CachedEntryCount);
    }

    [Fact]
    public async Task Zero_x_20_randomizes_the_case_and_requires_the_echo()
    {
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(o => o with { Use0x20 = true, MaxCacheEntries = 0 }), new FakeClock());
        bool sawUpper = false;
        for (int i = 0; i < 20; i++)
        {
            Assert.True((await client.QueryAsync("mail.example.com", DnsRecordType.A)).IsSuccess);
        }

        foreach (var q in transport.Queries)
        {
            sawUpper |= System.Text.Encoding.ASCII.GetString(q.Bytes).Any(char.IsUpper);
        }

        Assert.True(sawUpper, "no uppercase letter in 20 randomized queries");

        var lowering = new DnsClient(
            new FakeTransport(q => PacketBuilder.Response(BitConverter.ToUInt16([q.Bytes[1], q.Bytes[0]]), "mail.example.com", DnsRecordType.A).A("mail.example.com", "192.0.2.1").Build()),
            Opts(o => o with { Use0x20 = true }), new FakeClock());
        // With 20 tries at least one is mixed-case, and the lowered echo is then refused (all-lower by chance is 2^-14 per try; retry a few names).
        int rejected = 0;
        for (int i = 0; i < 10; i++)
        {
            try
            {
                await lowering.QueryAsync("mail.example.com", DnsRecordType.A);
                await Task.Delay(0);
            }
            catch (DnsException ex) when (ex.Reason == DnsFailureReason.ResponseMismatch)
            {
                rejected++;
            }
        }

        Assert.True(rejected >= 1);
    }

    [Fact]
    public async Task Cache_keys_ignore_case_and_trailing_dot_but_not_type()
    {
        var transport = new FakeTransport(Echo);
        var client = new DnsClient(transport, Opts(), new FakeClock());
        await client.QueryAsync("Mail.Example.COM.", DnsRecordType.A);
        await client.QueryAsync("mail.example.com", DnsRecordType.A);
        Assert.Equal(1, transport.Calls);
        await client.QueryAsync("mail.example.com", DnsRecordType.TXT);
        Assert.Equal(2, transport.Calls);
    }

    [Fact]
    public async Task Create_wires_a_working_stack_against_a_loopback_server()
    {
        using var server = new LoopbackDnsServer(q => LoopbackDnsServer.Reply(PacketBuilder.ReplyTo(q.Bytes).Mx("example.com", 10, "mx.example.com").Build()));
        var client = DnsClient.Create(new DnsResolverOptions { Servers = [server.Endpoint], AttemptTimeout = TimeSpan.FromSeconds(2) });
        var mx = await client.GetMxAsync("example.com");
        Assert.Equal("mx.example.com", Assert.Single(mx).Exchange);
    }

    [Fact]
    public void Constructor_validates_its_arguments()
    {
        Assert.Throws<ArgumentNullException>(() => new DnsClient(null!));
        Assert.Throws<ArgumentException>(() => new DnsClient(new FakeTransport(Echo), new DnsResolverOptions { Attempts = 0 }));
    }
}
