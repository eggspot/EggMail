using System.Net;
using Mta.Dns;
using Mta.Host.Ingest;
using Mta.Storage;
using Mta.Storage.Logic;

namespace Mta.Host.Tests.Inbound;

/// <summary>Sizes, recipient counts, the transaction budget, rate limits, verification slots, quotas and the optional blocklist (design sections 11.4 and 11.5).</summary>
public class InboundLimitsTests
{
    private static string Padded(int bytes) => InboundFixture.Message(body: new string('x', bytes));

    // ------------------------------------------------------------------ sizes

    [Fact]
    public async Task The_declared_size_is_checked_against_the_ceiling_at_mail_and_against_each_domains_limit_at_rcpt()
    {
        var options = new InboundReceiveOptions { Enabled = true, Ceilings = new InboundCeilings(10_000, 600, 60, 0, 0, 0) };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, change: s => s with { MaxMessageBytes = 4000 });
        await f.RefreshConfigAsync();
        await using FakeMta mta = await f.ConnectedAsync();

        var overCeiling = await mta.MailFromAsync("bob@sender.test", "SIZE=20000");
        Assert.Equal((552, "5.3.4"), (overCeiling.Code, overCeiling.Enhanced));

        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test", "SIZE=6000")).Code);
        var overDomain = await mta.RcptAsync("support@example.org");   // example.org takes 4000 at most
        Assert.Equal((552, "5.3.4"), (overDomain.Code, overDomain.Enhanced));
        Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);   // example.net takes the ceiling: the refusal was for that recipient only
        Assert.Equal(250, (await mta.DataAsync(Padded(5000))).Code);
        Assert.Empty(await f.StoredAsync(InboundFixture.Acme));
        Assert.Single(await f.StoredAsync(InboundFixture.Globex));
    }

    [Fact]
    public async Task The_actual_size_is_checked_against_the_lowest_limit_among_the_accepted_recipients_for_the_whole_transaction()
    {
        var options = new InboundReceiveOptions { Enabled = true, Ceilings = new InboundCeilings(10_000, 600, 60, 0, 0, 0) };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, change: s => s with { MaxMessageBytes = 4000 });
        await f.RefreshConfigAsync();
        await using FakeMta mta = await f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);   // no SIZE declared
        Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);

        var reply = await mta.DataAsync(Padded(5000));

        Assert.Equal((552, "5.3.4"), (reply.Code, reply.Enhanced));
        Assert.Empty(await f.StoredAsync(InboundFixture.Globex));   // all or nothing

        // The connection is usable afterwards and a small message goes through to both.
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(250, (await mta.DataAsync(Padded(1000))).Code);
        Assert.Single(await f.StoredAsync(InboundFixture.Acme));
    }

    [Fact]
    public async Task A_domain_limit_above_a_ceiling_the_operator_lowered_later_is_cut_to_the_ceiling()
    {
        var options = new InboundReceiveOptions { Enabled = true, Ceilings = new InboundCeilings(3000, 600, 60, 0, 0, 0) };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, change: s => s with { MaxMessageBytes = 100_000 });   // stored before the operator lowered the ceiling
        await f.RefreshConfigAsync();
        await using FakeMta mta = await f.ConnectedAsync();

        Assert.Equal(552, (await mta.SendAsync("bob@sender.test", "support@example.org", Padded(4000))).Code);
    }

    // ------------------------------------------------------------------ recipients and the transaction budget

    [Fact]
    public async Task The_recipient_cap_is_452_4_5_3_and_the_accepted_recipients_are_unaffected()
    {
        var options = new InboundReceiveOptions { Enabled = true, MaxRecipients = 2 };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);
        await using FakeMta mta = await f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);

        var third = await mta.RcptAsync("other@example.net");

        Assert.Equal((452, "4.5.3"), (third.Code, third.Enhanced));
        Assert.Equal(250, (await mta.DataAsync(InboundFixture.Message())).Code);
        Assert.Single(await f.StoredAsync(InboundFixture.Acme));
        Assert.Single(await f.StoredAsync(InboundFixture.Globex));
    }

    [Fact]
    public async Task The_transaction_budget_counts_the_declared_size_times_the_recipients_and_assumes_one_mebibyte_when_none_is_declared()
    {
        var options = new InboundReceiveOptions { Enabled = true, MaxTransactionBytes = 2_000_000 };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);

        await using (FakeMta declared = await f.ConnectedAsync())
        {
            Assert.Equal(250, (await declared.MailFromAsync("bob@sender.test", "SIZE=1000000")).Code);
            Assert.Equal(250, (await declared.RcptAsync("support@example.org")).Code);
            Assert.Equal(250, (await declared.RcptAsync("anyone@example.net")).Code);
            var third = await declared.RcptAsync("other@example.net");   // three times 1,000,000 is over 2,000,000
            Assert.Equal((452, "4.5.3"), (third.Code, third.Enhanced));
            Assert.Contains("Too many recipients for this size", third.Text);
        }

        await using (FakeMta undeclared = await f.ConnectedAsync())
        {
            Assert.Equal(250, (await undeclared.MailFromAsync("bob@sender.test")).Code);
            Assert.Equal(250, (await undeclared.RcptAsync("support@example.org")).Code);   // 1 MiB assumed
            Assert.Equal(452, (await undeclared.RcptAsync("anyone@example.net")).Code);   // two times 1 MiB is over 2,000,000
        }
    }

    [Fact]
    public async Task A_client_that_declares_a_small_size_and_sends_a_large_body_is_refused_at_the_end_of_data_with_the_actual_size()
    {
        var options = new InboundReceiveOptions { Enabled = true, MaxTransactionBytes = 2_000_000 };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);
        await using FakeMta mta = await f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test", "SIZE=100")).Code);   // a lie
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);

        var reply = await mta.DataAsync(Padded(1_500_000));   // two copies of 1.5 MB are over the budget

        Assert.Equal((452, "4.5.3"), (reply.Code, reply.Enhanced));
        Assert.Empty(await f.StoredAsync(InboundFixture.Acme));
        Assert.Empty(await f.StoredAsync(InboundFixture.Globex));
    }

    // ------------------------------------------------------------------ rate limits

    private static InboundReceiveOptions Rates(int perDomain, int perRemote) =>
        new() { Enabled = true, Ceilings = new InboundCeilings(25 << 20, perDomain, perRemote, 0, 0, 0) };

    [Fact]
    public async Task The_per_domain_limit_answers_450_4_7_1_and_the_next_minute_lifts_it()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync(Rates(perDomain: 3, perRemote: 100));
        await using FakeMta mta = await f.ConnectedAsync();
        for (int i = 0; i < 3; i++)
        {
            Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);
        }

        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        var limited = await mta.RcptAsync("support@example.org");
        Assert.Equal((450, "4.7.1"), (limited.Code, limited.Enhanced));
        Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);   // another domain has its own counter
        await mta.CommandAsync("RSET");

        f.Clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);
    }

    [Fact]
    public async Task The_per_remote_limit_is_per_client_address_and_an_ipv6_client_is_limited_by_its_64_bit_prefix()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync(Rates(perDomain: 100, perRemote: 2));

        async Task<int> SendFromAsync(string address)
        {
            f.ClientIp = IPAddress.Parse(address);
            await using FakeMta mta = await f.ConnectedAsync();
            return (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code;
        }

        Assert.Equal(250, await SendFromAsync("203.0.113.9"));
        Assert.Equal(250, await SendFromAsync("::ffff:203.0.113.9"));   // the mapped form is the same client
        Assert.Equal(450, await SendFromAsync("203.0.113.9"));
        Assert.Equal(250, await SendFromAsync("203.0.113.10"));   // another address has its own budget

        Assert.Equal(250, await SendFromAsync("2001:db8:1:2::1"));
        Assert.Equal(250, await SendFromAsync("2001:db8:1:2:ffff::7"));   // the same /64
        Assert.Equal(450, await SendFromAsync("2001:db8:1:2:abcd::9"));
        Assert.Equal(250, await SendFromAsync("2001:db8:1:3::1"));   // the next /64
    }

    [Fact]
    public async Task A_flood_from_many_addresses_cannot_evict_a_domains_counter()
    {
        var limiter = new InboundRateLimiter(maxEntries: 50);
        Guid domain = Guid.NewGuid();
        DateTimeOffset now = new(2026, 10, 16, 12, 0, 30, TimeSpan.Zero);
        limiter.Count(domain, IPAddress.Parse("198.51.100.1"), now);
        limiter.Count(domain, IPAddress.Parse("198.51.100.1"), now);

        Guid busyDomain = Guid.NewGuid();
        for (int i = 0; i < 500; i++)
        {
            limiter.Count(busyDomain, IPAddress.Parse($"10.1.{i / 250}.{i % 250 + 1}"), now);   // 500 different client addresses, all writing to one other domain
        }

        // The remote dictionary stayed within its bound by forgetting remote addresses; the domain dictionary is separate and still holds our two messages.
        Assert.True(limiter.RemoteEntries <= 50);
        Assert.False(limiter.Allows(domain, IPAddress.Parse("198.51.100.200"), perMinuteForDomain: 2, perMinuteForRemote: 100, now));
        await Task.CompletedTask;
    }

    // ------------------------------------------------------------------ verification slots

    [Fact]
    public async Task With_no_free_slot_data_is_refused_at_its_start_with_451_and_the_message_is_not_read()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync(new InboundReceiveOptions { Enabled = true, VerificationMaxConcurrency = 1, VerificationMaxConcurrencyPerRemote = 1 });
        using VerificationSlots.Lease held = f.Slots.TryAcquire(IPAddress.Parse("198.51.100.50"))!;
        await using FakeMta mta = await f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);

        var reply = await mta.CommandAsync("DATA");

        Assert.Equal((451, "4.7.0"), (reply.Code, reply.Enhanced));
        Assert.Contains("Server busy", reply.Text);

        held.Dispose();
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);   // the slot is free again
    }

    [Fact]
    public async Task One_network_cannot_take_all_the_slots_and_another_network_is_not_affected()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync(new InboundReceiveOptions { Enabled = true, VerificationMaxConcurrency = 8, VerificationMaxConcurrencyPerRemote = 1 });
        using VerificationSlots.Lease held = f.Slots.TryAcquire(IPAddress.Parse("203.0.113.77"))!;   // the same /24 as the client below

        await using (FakeMta sameNetwork = await f.ConnectedAsync())
        {
            Assert.Equal(250, (await sameNetwork.MailFromAsync("bob@sender.test")).Code);
            Assert.Equal(250, (await sameNetwork.RcptAsync("support@example.org")).Code);
            Assert.Equal(451, (await sameNetwork.CommandAsync("DATA")).Code);
        }

        f.ClientIp = IPAddress.Parse("198.51.100.4");
        await using FakeMta other = await f.ConnectedAsync();
        Assert.Equal(250, (await other.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);
    }

    [Fact]
    public async Task A_client_that_is_still_sending_the_body_holds_no_verification_slot()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        await using FakeMta mta = await f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
        Assert.Equal(354, (await mta.CommandAsync("DATA")).Code);

        await mta.SendRawAsync("Subject: slow\r\n\r\nhalf a body");   // and then nothing, for now

        Assert.Equal(0, f.Slots.InUse);   // the slot is taken after the end of DATA, for the verification only
        await mta.SendRawAsync("\r\n.\r\n");
        Assert.Equal(250, (await mta.ReadReplyAsync()).Code);
        Assert.Equal(0, f.Slots.InUse);   // and given back
    }

    // ------------------------------------------------------------------ quotas

    [Fact]
    public async Task A_domain_at_its_stored_bytes_limit_answers_452_4_2_2_until_space_is_freed()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, change: s => s with { MaxStoredBytes = 1L << 20 });
        await f.RefreshConfigAsync();
        await using FakeMta mta = await f.ConnectedAsync();
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", Padded(700_000))).Code);
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", Padded(700_000))).Code);   // 700 KB stored is under 1 MiB: still room at RCPT time

        f.Clock.Advance(TimeSpan.FromSeconds(6));   // the usage figure is cached for a few seconds
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        var full = await mta.RcptAsync("support@example.org");
        Assert.Equal((452, "4.2.2"), (full.Code, full.Enhanced));
        Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);   // another domain is not affected
        await mta.CommandAsync("RSET");

        foreach (InboundMessage m in await f.StoredAsync(InboundFixture.Acme))
        {
            await f.Storage.Inbound.DeleteAsync(InboundFixture.Acme, m.Id, default);
        }

        f.Clock.Advance(TimeSpan.FromSeconds(6));
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);
    }

    [Fact]
    public async Task The_tenant_wide_limit_covers_all_of_a_tenants_domains()
    {
        var options = new InboundReceiveOptions { Enabled = true, Ceilings = new InboundCeilings(25 << 20, 600, 60, 0, 1L << 20, 0) };
        await using InboundFixture f = await InboundFixture.CreateAsync(options);
        await using FakeMta mta = await f.ConnectedAsync();
        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", Padded(1_100_000))).Code);

        f.Clock.Advance(TimeSpan.FromSeconds(6));
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(452, (await mta.RcptAsync("old@example.org")).Code);
        Assert.Equal(250, (await mta.RcptAsync("anyone@example.net")).Code);   // Globex is another tenant
    }

    // ------------------------------------------------------------------ the optional blocklist

    private static InboundReceiveOptions Dnsbl(bool reject, params string[] zones) => new() { Enabled = true, DnsblZones = zones, DnsblReject = reject, DnsblTimeout = TimeSpan.FromSeconds(5) };

    [Fact]
    public async Task A_listed_client_is_refused_at_its_first_inbound_recipient_and_bounce_recipients_of_the_connection_are_left_alone()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync(Dnsbl(reject: true, "bl.example"), beforeStart: x => x.Dns.AddA("9.113.0.203.bl.example", "127.0.0.2"));
        string bounce = $"{f.Verp.CreateLocalPart(InboundFixture.Acme, f.ExampleOrg, f.Clock.Now, "dest.example")}@{InboundFixture.BounceDomain}";
        await using FakeMta mta = await f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        Assert.Equal(250, (await mta.RcptAsync(bounce)).Code);   // not queried, not refused
        Assert.Equal(0, f.Dns.GetQueryCount("9.113.0.203.bl.example", DnsRecordType.A));
        await mta.CommandAsync("RSET");

        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        var listed = await mta.RcptAsync("support@example.org");
        Assert.Equal((554, "5.7.1"), (listed.Code, listed.Enhanced));
        Assert.Contains("Listed by bl.example", listed.Text);
        Assert.Equal(554, (await mta.RcptAsync("anyone@example.net")).Code);
        Assert.Equal(1, f.Dns.GetQueryCount("9.113.0.203.bl.example", DnsRecordType.A));   // once per connection
    }

    [Fact]
    public async Task Under_flag_a_listed_client_is_accepted_and_the_message_carries_the_reputation_header()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync(Dnsbl(reject: false, "bl.example", "other.example"), beforeStart: x => x.Dns.AddA("9.113.0.203.other.example", "127.0.0.4"));
        await using FakeMta mta = await f.ConnectedAsync();

        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);

        string headers = (await f.RawAsync(Assert.Single(await f.StoredAsync(InboundFixture.Acme)))).Split("\r\n\r\n")[0];
        Assert.Contains("X-EggMail-Reputation: dnsbl=other.example\r\n", headers, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_resolver_blocked_answer_a_failure_and_a_clean_client_are_never_a_hit()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync(Dnsbl(reject: true, "blocked.example", "broken.example", "clean.example"), beforeStart: x =>
        {
            x.Dns.AddA("9.113.0.203.blocked.example", "127.255.255.254");   // "your resolver is over quota"
            x.Dns.Fail("9.113.0.203.broken.example", DnsRecordType.A);
            x.Dns.AddTxt("something.clean.example", "x");
        });
        using var capture = new MeterCapture("Mta.Inbound");
        await using FakeMta mta = await f.ConnectedAsync();

        Assert.Equal(250, (await mta.SendAsync("bob@sender.test", "support@example.org", InboundFixture.Message())).Code);

        Assert.True(capture.Sum("mta.inbound.dnsbl", ("result", "error")) >= 2);
        Assert.True(capture.Sum("mta.inbound.dnsbl", ("result", "miss")) >= 1);
    }

    [Fact]
    public void Blocklist_queries_use_the_reversed_octets_for_ipv4_and_the_32_reversed_nibbles_for_ipv6()
    {
        Assert.Equal("9.113.0.203", DnsblChecker.ReversedAddress(IPAddress.Parse("203.0.113.9")));
        Assert.Equal("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2", DnsblChecker.ReversedAddress(IPAddress.Parse("2001:db8::1")));
        Assert.Equal(63, DnsblChecker.ReversedAddress(IPAddress.IPv6Loopback).Length);
        Assert.Equal("f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0", DnsblChecker.ReversedAddress(IPAddress.Parse("0123:4567:89ab:cdef:0123:4567:89ab:cdef")));
    }

    // ------------------------------------------------------------------ the dialog is not a way to exhaust the server

    [Fact]
    public async Task Too_many_refused_recipients_end_the_session()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        await using FakeMta mta = await f.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        FakeMta.Reply? last = null;
        for (int i = 0; i < 12 && !(last is { Code: 421 }); i++)
        {
            last = await mta.RcptAsync($"user{i}@nowhere.example");
        }

        Assert.Equal(421, last!.Code);   // harvesting is slowed down by the errors-per-session limit
        Assert.True(await mta.IsClosedByServerAsync());
    }
}
