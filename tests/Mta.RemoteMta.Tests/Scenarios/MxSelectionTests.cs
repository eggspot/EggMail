using System.Net;
using System.Net.Sockets;
using Mta.Dns;
using Mta.RemoteMta.Tests.Harness;
using Mta.Storage;

namespace Mta.RemoteMta.Tests.Scenarios;

/// <summary>Which host receives the mail: MX preference, failover, null MX, implicit MX, aliases and the two address families.</summary>
public class MxSelectionTests
{
    private static MtaPersonality Tracking(string name, List<string> order, MtaPersonality? inner = null)
    {
        var peer = inner ?? Personalities.Plain(name);
        peer.Greeting = _ =>
        {
            lock (order)
            {
                order.Add(name);
            }

            return null!;
        };
        return peer;
    }

    // -------------------------------------------------------------------------------------------- failover

    [Fact]
    public async Task A_refused_connection_to_the_primary_falls_over_to_the_secondary_which_takes_the_message()
    {
        await using var lab = new MtaLab();
        lab.AddRefusingHost("mx1.dest.example");
        var secondary = lab.AddMta("mx2.dest.example", Personalities.Plain("mx2.dest.example"));
        lab.Mx("dest.example", 10, "mx1.dest.example").Mx("dest.example", 20, "mx2.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal("mx2.dest.example", events.Single(e => e.Type == MessageEventType.Delivered).MxHost);
        Assert.Single(secondary.Messages);
        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Deferred);
    }

    [Fact]
    public async Task Mx_hosts_are_tried_in_order_of_preference_and_not_all_at_once()
    {
        await using var lab = new MtaLab();
        var order = new List<string>();
        lab.AddRefusingHost("mx10.dest.example");
        var closing = Tracking("mx20.dest.example", order);
        closing.Greeting = _ => { lock (order) { order.Add("mx20.dest.example"); } return Step.Close(); };
        lab.AddMta("mx20.dest.example", closing);
        var last = lab.AddMta("mx30.dest.example", Tracking("mx30.dest.example", order));
        lab.Mx("dest.example", 30, "mx30.dest.example").Mx("dest.example", 10, "mx10.dest.example").Mx("dest.example", 20, "mx20.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal(["mx20.dest.example", "mx30.dest.example"], order);   // mx10 refuses at TCP level (no greeting), then 20 closes, then 30 is used
        Assert.Single(last.Messages);
    }

    [Fact]
    public async Task A_healthy_primary_gets_everything_and_the_secondary_is_never_contacted()
    {
        await using var lab = new MtaLab();
        var primary = lab.AddMta("mx1.dest.example", Personalities.Plain("mx1.dest.example"));
        var secondary = lab.AddMta("mx2.dest.example", Personalities.Plain("mx2.dest.example"));
        lab.Mx("dest.example", 10, "mx1.dest.example").Mx("dest.example", 20, "mx2.dest.example");

        for (int i = 0; i < 5; i++)
        {
            var id = await lab.SendAsync([$"r{i}@dest.example"]);
            await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        }

        Assert.Equal(5, primary.Messages.Count);
        Assert.Equal(0, secondary.ConnectionCount);
    }

    [Fact]
    public async Task A_greylisting_primary_is_not_bypassed_through_the_secondary_the_temporary_answer_is_the_answer()
    {
        await using var lab = new MtaLab();
        var primary = Personalities.Postfix();
        primary.OnRcpt = (_, rcpt) => Personalities.PostfixReplies.Greylisted(rcpt, "dest.example");
        lab.AddMta("mx1.dest.example", primary);
        var secondary = lab.AddMta("mx2.dest.example", Personalities.Plain("mx2.dest.example"));
        lab.Mx("dest.example", 10, "mx1.dest.example").Mx("dest.example", 20, "mx2.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Deferred);

        Assert.Equal(0, secondary.ConnectionCount);
    }

    [Fact]
    public async Task When_every_mx_is_unreachable_the_message_waits_and_goes_through_when_one_comes_back()
    {
        await using var lab = new MtaLab();
        lab.AddRefusingHost("mx1.dest.example");
        lab.AddRefusingHost("mx2.dest.example");
        var revived = new FakeMta(Personalities.Plain("mx1.dest.example"));
        lab.Mx("dest.example", 10, "mx1.dest.example").Mx("dest.example", 20, "mx2.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var due = await lab.WaitForRetryScheduleAsync(id);
        var deferred = (await lab.EventsAsync(id)).Single(e => e.Type == MessageEventType.Deferred);

        Assert.Equal(421, deferred.SmtpCode);   // the engine's own words for "could not connect"
        Assert.Equal(TimeSpan.FromMinutes(1), due - lab.Clock.UtcNow);   // a connection problem is retried early, once
        lab.MapPort("mx1.dest.example", revived.Port);
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Single(revived.Messages);
        await revived.DisposeAsync();
    }

    [Fact]
    public async Task Equal_preference_hosts_share_the_load_in_a_random_but_reproducible_order()
    {
        await using var lab = new MtaLab(new LabSettings { MxSeed = 42 });
        var a = lab.AddMta("mx-a.dest.example", Personalities.Plain("mx-a.dest.example"));
        var b = lab.AddMta("mx-b.dest.example", Personalities.Plain("mx-b.dest.example"));
        lab.Mx("dest.example", 10, "mx-a.dest.example").Mx("dest.example", 10, "mx-b.dest.example");

        for (int i = 0; i < 30; i++)
        {
            var id = await lab.SendAsync([$"r{i}@dest.example"]);
            // After the burst allowance of the destination's token bucket (20 messages) each message waits for the fake clock to refill it.
            await lab.AdvanceUntilAsync(() => lab.EventsAsync(id).Result.Any(e => e.Type == MessageEventType.Delivered), TimeSpan.FromSeconds(2), $"message {i} to be delivered");
        }

        Assert.Equal(30, a.Messages.Count + b.Messages.Count);
        Assert.InRange(a.Messages.Count, 5, 25);   // neither host is starved or favoured; with the fixed seed the split is the same on every run
        Assert.InRange(b.Messages.Count, 5, 25);
    }

    // ------------------------------------------------------------------------------------ DNS shapes

    [Fact]
    public async Task A_null_mx_is_a_permanent_failure_without_a_single_connection_and_the_sender_is_told()
    {
        await using var lab = new MtaLab();
        var sender = lab.AddSenderSide();
        lab.Dns.NullMx("nomail.example");

        var id = await lab.SendAsync(["rcpt@nomail.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Bounced);

        var bounced = events.Single(e => e.Type == MessageEventType.Bounced);
        Assert.Equal(556, bounced.SmtpCode);
        Assert.Equal("5.1.10", bounced.EnhancedCode);
        await sender.WaitForMessagesAsync(1);
        Assert.Contains("556", sender.Messages.Single().Text);
        Assert.True(await lab.Storage.Config.IsSuppressedAsync(MtaLab.Tenant, "rcpt@nomail.example", default));   // a domain that takes no mail will take none tomorrow either
    }

    [Fact]
    public async Task A_domain_without_mx_records_is_mailed_at_its_own_address_record()
    {
        await using var lab = new MtaLab();
        var host = lab.AddMta("plain.example", Personalities.Plain("plain.example"));

        var id = await lab.SendAsync(["rcpt@plain.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(host.Messages);
        Assert.Equal("plain.example", events.Single(e => e.Type == MessageEventType.Delivered).MxHost);
    }

    [Fact]
    public async Task A_domain_that_exists_but_has_no_mx_and_no_address_is_a_permanent_failure()
    {
        await using var lab = new MtaLab();
        lab.AddSenderSide();
        lab.Dns.Txt("emptydomain.example", "v=spf1 -all");

        var id = await lab.SendAsync(["rcpt@emptydomain.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Bounced);

        Assert.Equal("5.1.2", events.Single(e => e.Type == MessageEventType.Bounced).EnhancedCode);
    }

    [Fact]
    public async Task A_domain_that_does_not_exist_is_a_permanent_failure_and_a_servfail_is_only_a_delay()
    {
        await using var lab = new MtaLab();
        lab.AddSenderSide();
        var mx = lab.AddMta("mx.flaky.example", Personalities.Plain("mx.flaky.example"));
        lab.Mx("flaky.example", 10, "mx.flaky.example");
        lab.Dns.Servfail("flaky.example", DnsRecordType.MX);

        var gone = await lab.SendAsync(["rcpt@no-such-domain.example"]);
        await lab.WaitForEventAsync(gone, MessageEventType.Bounced);

        var flaky = await lab.SendAsync(["rcpt@flaky.example"]);
        var due = await lab.WaitForRetryScheduleAsync(flaky);
        Assert.Equal(451, (await lab.EventsAsync(flaky)).Single(e => e.Type == MessageEventType.Deferred).SmtpCode);
        Assert.Empty(mx.Messages);

        lab.Dns.Heal("flaky.example", DnsRecordType.MX);
        lab.Advance(due - lab.Clock.UtcNow);
        await lab.WaitForEventAsync(flaky, MessageEventType.Delivered);
        Assert.Single(mx.Messages);
    }

    [Fact]
    public async Task An_mx_that_is_an_alias_for_another_name_is_followed_to_the_target_address()
    {
        await using var lab = new MtaLab();
        var real = lab.AddMta("real.provider.example", Personalities.Plain("real.provider.example"));
        lab.Dns.Cname("mx.dest.example", "real.provider.example");
        lab.MapPort("mx.dest.example", real.Port);
        lab.Mx("dest.example", 10, "mx.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(real.Messages);
        Assert.Equal("mx.dest.example", events.Single(e => e.Type == MessageEventType.Delivered).MxHost);
    }

    [Fact]
    public async Task An_mx_target_that_has_no_address_is_skipped_for_one_that_has()
    {
        await using var lab = new MtaLab();
        var good = lab.AddMta("mx2.dest.example", Personalities.Plain("mx2.dest.example"));
        lab.Mx("dest.example", 10, "mx1.dest.example").Mx("dest.example", 20, "mx2.dest.example");   // mx1 has no A record at all

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(good.Messages);
    }

    // ---------------------------------------------------------------------------------------- IPv6 / IPv4

    [Ipv6Fact]
    public async Task A_host_with_only_an_ipv6_address_is_delivered_to_over_ipv6()
    {
        await using var lab = new MtaLab();
        var mx = lab.AddMta("mx.dest.example", Personalities.Plain("mx.dest.example"), "::1");
        lab.Mx("dest.example", 10, "mx.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Equal(IPAddress.IPv6Loopback, mx.Address);
        Assert.Single(mx.Messages);
    }

    [Ipv6Fact]
    public async Task With_ipv4_first_a_dead_ipv4_address_falls_back_to_the_ipv6_address_of_the_same_host()
    {
        await using var lab = new MtaLab(new LabSettings { AddressPreference = MxAddressPreference.Ipv4First });
        var v6 = lab.AddMta("mx.dest.example", Personalities.Plain("mx.dest.example"), "::1");
        if (!Ipv4PortIsFree(v6.Port))
        {
            return;   // another process holds that port on IPv4 loopback right now; the scenario needs it free
        }

        lab.Dns.A("mx.dest.example", "127.0.0.1");   // the IPv4 address answers nothing on this port
        lab.Mx("dest.example", 10, "mx.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(v6.Messages);
    }

    [Ipv6Fact]
    public async Task With_ipv6_first_a_dead_ipv6_address_falls_back_to_ipv4()
    {
        await using var lab = new MtaLab(new LabSettings { AddressPreference = MxAddressPreference.Ipv6First });
        var v4 = lab.AddMta("mx.dest.example", Personalities.Plain("mx.dest.example"));
        if (!Ipv6PortIsFree(v4.Port))
        {
            return;
        }

        lab.Dns.Aaaa("mx.dest.example", "::1");
        lab.Mx("dest.example", 10, "mx.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(v4.Messages);
    }

    [Ipv6Fact]
    public async Task The_address_family_that_works_is_used_first_when_both_are_up_and_the_other_sees_no_connection()
    {
        await using var lab = new MtaLab(new LabSettings { AddressPreference = MxAddressPreference.Ipv4First });
        var v4 = lab.AddMta("mx.dest.example", Personalities.Plain("mx.dest.example"));
        lab.Dns.Aaaa("mx.dest.example", "::1");
        lab.Mx("dest.example", 10, "mx.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.Single(v4.Messages);
    }

    private static bool Ipv4PortIsFree(int port) => PortIsFree(IPAddress.Loopback, port);

    private static bool Ipv6PortIsFree(int port) => PortIsFree(IPAddress.IPv6Loopback, port);

    private static bool PortIsFree(IPAddress address, int port)
    {
        try
        {
            using var probe = new TcpListener(address, port);
            probe.Start();
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
