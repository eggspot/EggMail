using System.Net;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Tests.Inbound;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>
/// The limits that protect the anonymous port, through a real runtime and real stores: recipients, messages per minute (per domain and per sending network, IPv6 by /64), connections, session age,
/// verification slots, stored bytes (the aggregate the real store computes) and the DNS blocklist. The windows are read off the clock the test moves; nothing here waits for real time.
/// </summary>
public abstract class InboundLimitTests(LabBackend backend)
{
    private static InboundSection Section(Action<InboundSettings>? change = null)
    {
        var s = new InboundSettings();
        change?.Invoke(s);
        return s.Build();
    }

    /// <summary>The init-only <see cref="InboundSection"/> members a test changes, collected so a test names only what it needs.</summary>
    private sealed class InboundSettings
    {
        public int MaxRecipients = 20;
        public int MaxMessagesPerMinute = 600;
        public int MaxMessagesPerMinutePerRemote = 60;
        public long MaxStoredBytesPerDomain = 2L << 30;
        public long MaxStoredBytesPerTenant = 10L << 30;
        public TimeSpan MaxSessionDuration = TimeSpan.FromMinutes(10);
        public InboundVerificationSection Verification = new();
        public List<string> DnsblZones = [];
        public InboundDnsblAction DnsblAction = InboundDnsblAction.Flag;

        public InboundSection Build() => new()
        {
            Enabled = true,
            CheckSpfForInternalClients = true,
            MaxRecipients = MaxRecipients,
            MaxMessagesPerMinute = MaxMessagesPerMinute,
            MaxMessagesPerMinutePerRemote = MaxMessagesPerMinutePerRemote,
            MaxStoredBytesPerDomain = MaxStoredBytesPerDomain,
            MaxStoredBytesPerTenant = MaxStoredBytesPerTenant,
            MaxSessionDuration = MaxSessionDuration,
            Verification = Verification,
            Dnsbl = new InboundDnsblSection { Zones = DnsblZones, Action = DnsblAction },
        };
    }

    // ------------------------------------------------------------------ recipients

    [Fact]
    public async Task The_recipient_cap_refuses_the_next_recipient_with_452_and_the_accepted_ones_get_their_copies()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Inbound = Section(s => s.MaxRecipients = 3) });
        if (lab is null)
        {
            return;
        }

        await using FakeMta mta = await lab.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
        // Refused recipients (unknown mailboxes) do not use up the cap: a sender with a stale address book still gets its valid recipients through.
        Assert.Equal(550, (await mta.RcptAsync("nobody1@example.org")).Code);
        Assert.Equal(550, (await mta.RcptAsync("nobody2@example.org")).Code);
        foreach (string r in new[] { "support@example.org", "old@example.org", "postmaster@example.org" })
        {
            Assert.Equal(250, (await mta.RcptAsync(r)).Code);
        }

        FakeMta.Reply fourth = await mta.RcptAsync("billing-1@example.org");
        Assert.Equal((452, "4.5.3"), (fourth.Code, fourth.Enhanced));
        Assert.Equal(250, (await mta.DataAsync(InboundLab.Message())).Code);

        Assert.Equal(["old@example.org", "postmaster@example.org", "support@example.org"], (await lab.MessagesAsync(InboundLab.Acme)).Select(m => m.EnvelopeTo).Order(StringComparer.Ordinal).ToArray());
    }

    // ------------------------------------------------------------------ rates

    [Fact]
    public async Task The_per_sender_and_per_domain_rate_limits_answer_450_and_the_next_minute_lifts_them()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Inbound = Section(s => { s.MaxMessagesPerMinute = 5; s.MaxMessagesPerMinutePerRemote = 2; }) });
        if (lab is null)
        {
            return;
        }

        async Task<FakeMta.Reply> SendFromAsync(string address, string to = "support@example.org")
        {
            lab.ClientIp = IPAddress.Parse(address);
            return await lab.SendAsync("bob@sender.test", to, InboundLab.Message());
        }

        Assert.Equal(250, (await SendFromAsync("203.0.113.9")).Code);
        Assert.Equal(250, (await SendFromAsync("203.0.113.9")).Code);
        FakeMta.Reply limited = await SendFromAsync("203.0.113.9");
        Assert.Equal((450, "4.7.1"), (limited.Code, limited.Enhanced));
        // Another sender is not affected by the first one's budget; the domain's own limit (5) counts all senders together.
        Assert.Equal(250, (await SendFromAsync("203.0.113.10")).Code);
        Assert.Equal(250, (await SendFromAsync("203.0.113.10")).Code);
        Assert.Equal(250, (await SendFromAsync("203.0.113.11")).Code);
        Assert.Equal(450, (await SendFromAsync("203.0.113.12")).Code);   // the domain is at 5
        Assert.Equal(250, (await SendFromAsync("203.0.113.12", "anyone@example.net")).Code);   // another domain has its own budget
        Assert.Equal(5, (await lab.MessagesAsync(InboundLab.Acme)).Count);

        await lab.AdvanceAsync(TimeSpan.FromSeconds(61));
        Assert.Equal(250, (await SendFromAsync("203.0.113.9")).Code);
        Assert.Equal(250, (await SendFromAsync("203.0.113.12")).Code);
        await lab.AssertNothingWasSentAsync();
    }

    [Fact]
    public async Task An_ipv6_sender_is_limited_by_its_64_bit_prefix_and_a_mapped_ipv4_address_is_the_ipv4_address()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Inbound = Section(s => s.MaxMessagesPerMinutePerRemote = 2) });
        if (lab is null)
        {
            return;
        }

        async Task<int> SendFromAsync(string address)
        {
            lab.ClientIp = IPAddress.Parse(address);
            return (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message())).Code;
        }

        // Two hosts of one /64 share a budget of two; the next /64 has its own.
        Assert.Equal(250, await SendFromAsync("2001:db8:1:1::1"));
        Assert.Equal(250, await SendFromAsync("2001:db8:1:1:aaaa::2"));
        Assert.Equal(450, await SendFromAsync("2001:db8:1:1:ffff:ffff:ffff:ffff"));
        Assert.Equal(250, await SendFromAsync("2001:db8:1:2::1"));

        // 203.0.113.9 and ::ffff:203.0.113.9 are one sender.
        Assert.Equal(250, await SendFromAsync("203.0.113.9"));
        Assert.Equal(250, await SendFromAsync("::ffff:203.0.113.9"));
        Assert.Equal(450, await SendFromAsync("203.0.113.9"));
        Assert.Equal("203.0.113.9", (await lab.MessagesAsync(InboundLab.Acme)).Last(m => m.RemoteAddress.Contains("203.0.113.9", StringComparison.Ordinal)).RemoteAddress);
    }

    [Fact]
    public async Task Connections_that_ask_at_the_same_moment_cannot_all_pass_a_rate_limit_that_only_one_or_two_of_them_fit_under()
    {
        GatedResolver? gate = null;
        var options = new LabOptions
        {
            // A blocklist is configured so that the receive path has to wait for DNS between its look at the limit and its count: that is the window in which every connection used to see an empty counter.
            Inbound = Section(s => { s.MaxMessagesPerMinutePerRemote = 2; s.MaxMessagesPerMinute = 3; s.DnsblZones = ["bl.test"]; }),
            WrapDns = dns => gate = new GatedResolver(dns, name => name.EndsWith(".bl.test", StringComparison.Ordinal)),
        };
        await using InboundLab? lab = await InboundLab.StartAsync(backend, options);
        if (lab is null)
        {
            return;
        }

        lab.ClientIp = IPAddress.Parse("203.0.113.9");
        var connections = new List<FakeMta>();
        try
        {
            for (int i = 0; i < 8; i++)
            {
                FakeMta mta = await lab.ConnectedAsync();
                Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
                await mta.SendRawAsync("RCPT TO:<support@example.org>\r\n");   // not awaited: the reply waits for the blocklist
                connections.Add(mta);
            }

            // Every connection has had its look at the counters (nothing is counted yet: they are all waiting for the blocklist); let them all through together.
            await gate!.WaitForArrivalsAsync(8);
            gate.Release();

            int accepted = 0, limited = 0;
            foreach (FakeMta mta in connections)
            {
                FakeMta.Reply reply = await mta.ReadReplyAsync();
                if (reply.Code == 250)
                {
                    accepted++;
                }
                else
                {
                    Assert.Equal((450, "4.7.1"), (reply.Code, reply.Enhanced));
                    limited++;
                }
            }

            Assert.Equal((2, 6), (accepted, limited));   // the sender's own limit (2) holds, however the connections interleave
        }
        finally
        {
            foreach (FakeMta mta in connections)
            {
                await mta.DisposeAsync();
            }
        }
    }

    // ------------------------------------------------------------------ connections and sessions

    [Fact]
    public async Task The_connection_limit_per_address_turns_the_next_connection_away_with_421_and_a_closed_connection_gives_its_place_back()
    {
        var smtp = new SmtpSection { MaxConnectionsPerIp = 2, Listeners = [] };
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Smtp = smtp });
        if (lab is null)
        {
            return;
        }

        FakeMta first = await lab.ConnectedAsync();
        FakeMta second = await lab.ConnectedAsync();
        await using (FakeMta third = await FakeMta.ConnectAsync(lab.Port, expectGreeting: false))
        {
            FakeMta.Reply turnedAway = await third.ReadReplyAsync();
            Assert.Equal(421, turnedAway.Code);
            Assert.True(await third.IsClosedByServerAsync());
        }

        await first.QuitAsync();
        await first.DisposeAsync();
        // The place is given back when the server has seen the close: try until it has (a connection that is turned away is closed at once, so nothing waits long).
        FakeMta? again = null;
        for (int attempt = 0; attempt < 200 && again is null; attempt++)
        {
            FakeMta candidate = await FakeMta.ConnectAsync(lab.Port, expectGreeting: false);
            FakeMta.Reply greeting = await candidate.ReadReplyAsync();
            if (greeting.Code == 220)
            {
                again = candidate;
            }
            else
            {
                await candidate.DisposeAsync();
                await Task.Delay(10);
            }
        }

        Assert.NotNull(again);
        await again.DisposeAsync();
        await second.DisposeAsync();
    }

    [Fact]
    public async Task An_anonymous_session_is_closed_after_its_age_limit_when_the_next_command_arrives()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Inbound = Section(s => s.MaxSessionDuration = TimeSpan.FromMinutes(2)) });
        if (lab is null)
        {
            return;
        }

        await using FakeMta mta = await lab.ConnectedAsync();
        Assert.Equal(250, (await mta.CommandAsync("NOOP")).Code);
        await lab.AdvanceAsync(TimeSpan.FromMinutes(3));

        // The age is checked between commands: the command that arrives is answered, then the server closes the session at the top of its loop without waiting for another.
        Assert.Equal(250, (await mta.CommandAsync("NOOP")).Code);
        FakeMta.Reply closing = await mta.ReadReplyAsync();

        Assert.Equal((421, "4.4.2"), (closing.Code, closing.Enhanced));
        Assert.True(await mta.IsClosedByServerAsync());
        await using FakeMta fresh = await lab.ConnectedAsync();   // a new session is a new age
        Assert.Equal(250, (await fresh.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message())).Code);
    }

    [Fact]
    public async Task A_client_that_keeps_a_connection_busy_with_noop_cannot_hold_it_past_the_error_limit_for_unknown_mailboxes()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        // Harvesting: every unknown mailbox is an error of the session, and a session ends after ten.
        await using FakeMta mta = await lab.ConnectedAsync();
        Assert.Equal(250, (await mta.MailFromAsync("spammer@sender.test")).Code);
        int refused = 0;
        FakeMta.Reply last;
        do
        {
            last = await mta.RcptAsync($"guess{refused}@example.org");
            refused++;
        }
        while (last.Code == 550 && refused < 30);

        Assert.Equal(421, last.Code);
        Assert.InRange(refused, 2, 12);
        Assert.True(await mta.IsClosedByServerAsync());
    }

    // ------------------------------------------------------------------ verification slots

    [Fact]
    public async Task With_every_verification_slot_taken_the_next_message_is_told_to_come_back_at_once_and_is_not_queued()
    {
        GatedResolver? gate = null;
        var options = new LabOptions
        {
            Inbound = Section(s => s.Verification = new InboundVerificationSection { MaxConcurrency = 1, MaxConcurrencyPerRemote = 1, Timeout = TimeSpan.FromSeconds(30) }),
            WrapDns = dns => gate = new GatedResolver(dns, name => name == "slow.test"),
        };
        await using InboundLab? lab = await InboundLab.StartAsync(backend, options);
        if (lab is null)
        {
            return;
        }

        // The first message is in its verification, held by the resolver.
        await using FakeMta first = await lab.ConnectedAsync();
        Assert.Equal(250, (await first.MailFromAsync("bob@slow.test")).Code);
        Assert.Equal(250, (await first.RcptAsync("support@example.org")).Code);
        Assert.Equal(354, (await first.CommandAsync("DATA")).Code);
        await first.SendRawAsync(InboundLab.Message(from: "bob@slow.test") + ".\r\n");
        await gate!.Entered.WaitAsync(TimeSpan.FromSeconds(30));

        // The second one is refused at the start of DATA (a look at the free count): it is not even read.
        await using (FakeMta second = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await second.MailFromAsync("carol@sender.test")).Code);
            Assert.Equal(250, (await second.RcptAsync("support@example.org")).Code);
            FakeMta.Reply busy = await second.CommandAsync("DATA");
            Assert.Equal((451, "4.7.0"), (busy.Code, busy.Enhanced));
        }

        gate.Release();
        Assert.Equal(250, (await first.ReadReplyAsync()).Code);

        // With the slot free again the same sender gets through, and only the two accepted messages exist.
        Assert.Equal(250, (await lab.SendAsync("carol@sender.test", "support@example.org", InboundLab.Message(subject: "retry"))).Code);
        Assert.Equal(2, (await lab.MessagesAsync(InboundLab.Acme)).Count);
    }

    // ------------------------------------------------------------------ stored bytes

    [Fact]
    public async Task A_domain_at_its_stored_bytes_limit_is_refused_with_452_until_mail_is_deleted()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend);
        if (lab is null)
        {
            return;
        }

        string big = InboundLab.Message(body: new string('b', 1_400) + "\r\n");
        // How big one stored copy is (the stamped message, as the store counts it): measured, so the limit below is a multiple of it.
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "anyone@example.net", big)).Code);
        long copy = Assert.Single(await lab.MessagesAsync(InboundLab.Globex)).Size;

        await lab.SetSettingsAsync(lab.ExampleOrg, InboundLab.Acme, s => s with { MaxStoredBytes = copy * 3 / 2 });

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", big)).Code);
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", big)).Code);   // the figure is cached for a few seconds: the limit may be overshot by what is in the window
        await lab.AdvanceAsync(TimeSpan.FromSeconds(6));
        FakeMta.Reply full = await lab.SendAsync("bob@sender.test", "support@example.org", big);
        Assert.Equal((452, "4.2.2"), (full.Code, full.Enhanced));
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "anyone@example.net", big)).Code);   // another domain is not affected

        // Freeing space is seen after the cache has expired.
        InboundMessage oldest = (await lab.MessagesAsync(InboundLab.Acme)).Last();
        Assert.True(await lab.Storage.Inbound.DeleteAsync(InboundLab.Acme, oldest.Id, default));
        await lab.AdvanceAsync(TimeSpan.FromSeconds(6));
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", big)).Code);
        Assert.InRange((await lab.Storage.Inbound.GetUsageAsync(null, lab.ExampleOrg, default)).BodyBytes, 2 * copy - 64, 2 * copy + 64);   // two copies of about one size
        await lab.AssertNothingWasSentAsync();
    }

    [Fact]
    public async Task The_tenant_wide_limit_covers_every_domain_of_the_tenant_and_not_another_tenants()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { Inbound = Section(s => s.MaxStoredBytesPerTenant = 6_000) });
        if (lab is null)
        {
            return;
        }

        Guid second = await lab.AddDomainAsync(InboundLab.Acme, "second.example");
        await lab.AddRouteAsync(second, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        await lab.RefreshAsync();
        string big = InboundLab.Message(body: new string('b', 1_400) + "\r\n");

        // Fill the tenant's allowance across its two domains, one message per cache window so each check sees the true figure.
        int accepted = 0;
        FakeMta.Reply reply;
        do
        {
            await lab.AdvanceAsync(TimeSpan.FromSeconds(6));
            reply = await lab.SendAsync("bob@sender.test", accepted % 2 == 0 ? "support@example.org" : "x@second.example", big);
            if (reply.Code == 250)
            {
                accepted++;
            }
        }
        while (reply.Code == 250 && accepted < 20);

        Assert.Equal((452, "4.2.2"), (reply.Code, reply.Enhanced));
        Assert.InRange(accepted, 3, 4);   // about 6,000 bytes of 1,700-2,000 byte copies; both domains counted together
        Assert.NotEmpty(await lab.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, Recipient: "x@second.example")));
        await lab.AdvanceAsync(TimeSpan.FromSeconds(6));
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "anyone@example.net", big)).Code);   // another tenant has its own allowance
        InboundUsage usage = await lab.Storage.Inbound.GetUsageAsync(InboundLab.Acme, null, default);
        Assert.True(usage.BodyBytes >= 6_000, $"usage {usage.BodyBytes}");
        await lab.AssertNothingWasSentAsync();
    }

    // ------------------------------------------------------------------ DNS blocklist

    private static readonly IPAddress Listed = IPAddress.Parse("203.0.113.9");

    [Fact]
    public async Task A_listed_address_is_refused_at_its_first_inbound_recipient_an_unlisted_one_or_a_failing_list_is_not_and_an_internal_address_is_never_asked_about()
    {
        var options = new LabOptions { Inbound = Section(s => { s.DnsblZones = ["bl.test"]; s.DnsblAction = InboundDnsblAction.Reject; }) };
        await using InboundLab? lab = await InboundLab.StartAsync(backend, options);
        if (lab is null)
        {
            return;
        }

        lab.Dns.AddA("9.113.0.203.bl.test", "127.0.0.2");                 // listed
        lab.Dns.AddA("10.113.0.203.bl.test", "127.255.255.254");          // "your resolver is blocked": an error, never a hit
        lab.Dns.Fail("11.113.0.203.bl.test", DnsRecordType.A);            // SERVFAIL: never blocks
        lab.Dns.AddA("12.113.0.203.bl.test", "8.8.8.8");                  // not in 127.0.0.0/8: an error
        // 13.113.0.203: no record, not listed.

        async Task<FakeMta.Reply> TryAsync(string address)
        {
            lab.ClientIp = IPAddress.Parse(address);
            await using FakeMta mta = await lab.ConnectedAsync();
            return await mta.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: address));
        }

        FakeMta.Reply listed = await TryAsync("203.0.113.9");
        Assert.Equal((554, "5.7.1"), (listed.Code, listed.Enhanced));
        Assert.Contains("bl.test", listed.Text, StringComparison.Ordinal);
        foreach (string address in new[] { "203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13" })
        {
            Assert.Equal(250, (await TryAsync(address)).Code);
        }

        // The internal (loopback, private) address of a test or of a NAT says nothing to a list and is not disclosed to it.
        int queries = lab.Dns.GetQueryCount("1.0.0.127.bl.test", DnsRecordType.A);
        lab.ClientIp = IPAddress.Loopback;
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "internal"))).Code);
        Assert.Equal(queries, lab.Dns.GetQueryCount("1.0.0.127.bl.test", DnsRecordType.A));

        // A bounce on the same port from a listed address is not refused: the list applies to inbound recipients only.
        lab.ClientIp = Listed;
        string bounce = lab.BounceLocalPart();
        Assert.Equal(250, (await lab.SendAsync("", $"{bounce}@{InboundLab.BounceDomain}", InboundLab.Dsn($"{bounce}@{InboundLab.BounceDomain}", "gone@dest.example"))).Code);
        Assert.DoesNotContain(await lab.MessagesAsync(InboundLab.Acme), m => m.RemoteAddress == "203.0.113.9");
    }

    [Fact]
    public async Task Under_flag_a_listed_address_is_accepted_and_the_stored_message_says_which_list()
    {
        var options = new LabOptions { Inbound = Section(s => s.DnsblZones = ["bl.test", "other.test"]) };
        await using InboundLab? lab = await InboundLab.StartAsync(backend, options);
        if (lab is null)
        {
            return;
        }

        lab.Dns.AddA("9.113.0.203.other.test", "127.0.0.4");
        lab.ClientIp = Listed;

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message())).Code);

        string raw = await lab.RawAsync(Assert.Single(await lab.MessagesAsync(InboundLab.Acme)));
        Assert.Contains("\r\nX-EggMail-Reputation: dnsbl=other.test\r\n", raw, StringComparison.Ordinal);
        Assert.Single(raw.Split("X-EggMail-Reputation:").Skip(1));
    }
}

public sealed class SqliteInboundLimitTests() : InboundLimitTests(LabBackend.Sqlite);

public sealed class PostgresInboundLimitTests() : InboundLimitTests(LabBackend.Postgres);
