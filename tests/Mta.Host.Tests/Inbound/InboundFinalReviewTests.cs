using System.Text;
using Microsoft.Extensions.Configuration;
using Mta.Core;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Ingest;
using Mta.Storage;

namespace Mta.Host.Tests.Inbound;

/// <summary>The last findings of the review of the receive path (probes of the final verification, as tests).</summary>
public class InboundFinalReviewTests
{
    /// <summary>A resolver that honours cancellation and never answers for the names it is told to hang on.</summary>
    private sealed class HangNames(StaticDnsResolver inner, Func<string, bool> hang) : IDnsResolver
    {
        public async ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (hang(name))
            {
                await Task.Delay(Timeout.Infinite, cancellationToken);
            }

            return await inner.QueryAsync(name, type, cancellationToken);
        }
    }

    private static EmailAddress Address(string text)
    {
        Assert.True(EmailAddress.TryParse(text, allowUtf8: true, out EmailAddress address), text);
        return address;
    }

    // ------------------------------------------------------------------ the policy lookups have deadlines of their own

    [Theory]
    [InlineData("x@attacker.test, ceo@victim.test")]
    [InlineData("ceo@victim.test, x@attacker.test")]
    public async Task A_from_domain_whose_policy_lookup_never_answers_cannot_use_up_the_time_of_another(string from)
    {
        var options = new InboundReceiveOptions { Enabled = true, VerificationTimeout = TimeSpan.FromMilliseconds(500) };
        await using InboundFixture f = await InboundFixture.CreateAsync(options, wrapDns: dns => new HangNames(dns, n => n == "_dmarc.attacker.test"));
        f.PublishDmarc("victim.test", "reject");
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Flag);
        await f.RefreshConfigAsync();
        await using (FakeMta mta = await f.ConnectedAsync("mail.attacker.test"))
        {
            Assert.Equal(250, (await mta.SendAsync("x@attacker.test", "support@example.org", InboundFixture.Message(from: from))).Code);
        }

        Assert.Equal(InboundDmarcDisposition.Flagged, Assert.Single(await f.StoredAsync(InboundFixture.Acme)).Disposition);   // the victim's policy was read and decided

        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();
        await using (FakeMta mta = await f.ConnectedAsync("mail.attacker.test"))
        {
            var reply = await mta.SendAsync("x@attacker.test", "support@example.org", InboundFixture.Message(from: from));
            Assert.Equal((550, "5.7.1"), (reply.Code, reply.Enhanced));   // not deferred with 451: the settled failure needs nothing from the other domain
        }
    }

    // ------------------------------------------------------------------ a refused mailbox with several "@" is not guessed at

    [Theory]
    [InlineData("ceo@victim.test x@evil.test")]
    [InlineData("ceo@victim.test\r\n x@evil.test")]
    [InlineData("ceo@victim.test, x..y@evil.test")]
    public async Task A_from_the_strict_parser_refuses_and_that_names_two_domains_is_not_evaluated_as_the_last_one(string from)
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        f.PublishDmarc("victim.test", "reject");
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();
        await using FakeMta mta = await f.ConnectedAsync();

        var reply = await mta.SendAsync("x@evil.test", "support@example.org", $"From: {from}\r\nTo: support@example.org\r\nSubject: s\r\nMessage-ID: <{Guid.NewGuid():N}@sender.test>\r\n\r\nbody\r\n");

        Assert.NotEqual(250, reply.Code);   // refused (an unusable From, or the failure of victim.test): never accepted as evil.test's
    }

    [Theory]
    [InlineData("\"a@victim.test\"@evil.test")]
    [InlineData("<a@evil.test> (x@victim.test)")]
    public async Task A_valid_mailbox_is_evaluated_as_the_domain_after_its_address_and_not_the_one_in_a_quoted_part_or_a_comment(string from)
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        f.PublishDmarc("victim.test", "reject");   // evil.test has no policy
        await f.EnableAsync(f.ExampleOrg, InboundFixture.Acme, InboundDmarcAction.Reject);
        await f.RefreshConfigAsync();
        await using FakeMta mta = await f.ConnectedAsync();

        var reply = await mta.SendAsync("x@evil.test", "support@example.org", $"From: {from}\r\nTo: support@example.org\r\nSubject: s\r\nMessage-ID: <{Guid.NewGuid():N}@sender.test>\r\n\r\nbody\r\n");

        Assert.Equal(250, reply.Code);
        Assert.Equal(InboundVerdict.None, Assert.Single(await f.StoredAsync(InboundFixture.Acme)).Auth.Dmarc);
    }

    [Theory]
    [InlineData("From: ceo@victim.test x@evil.test", false, true)]
    [InlineData("From: ceo@victim.test@evil.test", false, true)]
    [InlineData("From: ceo@victim.test <a@b@evil.test>", false, true)]
    [InlineData("From: john.@victim.test", true, false)]
    [InlineData("From: jo..hn@victim.test", true, false)]
    public void The_domain_of_a_refused_mailbox_is_recovered_only_when_there_is_exactly_one_at_sign(string line, bool recovered, bool unusable)
    {
        InboundHeaderAnalysis analysis = InboundHeaderAnalysis.Analyze(Encoding.UTF8.GetBytes(line + "\r\nTo: x@y.test\r\n\r\nbody\r\n"), ["mx.egg.test"], null);

        Assert.Equal(unusable, analysis.FromUnusable);
        Assert.Equal(recovered ? ["victim.test"] : [], analysis.FromDomains);
    }

    // ------------------------------------------------------------------ one client cannot use up the lookups of the others

    [Fact]
    public async Task A_client_past_its_own_lookup_budget_does_not_use_up_the_process_wide_one()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        IBounceNamespace bounces = f.Handler;
        EmailAddress Rcpt(string host) => Address($"{f.Verp.CreateLocalPart(InboundFixture.Acme, f.ExampleOrg, f.Clock.Now, "dest.example")}@{host}");

        // The process-wide budget is per second: try again when the attack and the probe did not fall into the same second.
        for (int attempt = 0; attempt < 5; attempt++)
        {
            long before = Environment.TickCount64 / 1000;
            for (int i = 0; i < 400; i++)
            {
                try
                {
                    await bounces.ClassifyAsync(Rcpt($"bounce.n{attempt}x{i}.example"), "198.51.100.1", default);
                }
                catch (StorageUnavailableException)
                {
                }
            }

            bool otherClientServed;
            try
            {
                await bounces.ClassifyAsync(Rcpt($"bounce.legit{attempt}.example"), "203.0.113.77", default);
                otherClientServed = true;
            }
            catch (StorageUnavailableException)
            {
                otherClientServed = false;
            }

            if (before == Environment.TickCount64 / 1000)
            {
                Assert.True(otherClientServed, "one client used up the process-wide lookup budget");
                return;
            }

            await Task.Delay(1100);
        }
    }

    // ------------------------------------------------------------------ a report is read far enough

    [Fact]
    public async Task A_report_with_a_long_human_readable_part_before_the_status_part_is_still_read()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        string to = $"{f.Verp.CreateLocalPart(InboundFixture.Acme, f.ExampleOrg, f.Clock.Now, "dest.example")}@{InboundFixture.BounceDomain}";
        string dsn = $"From: MAILER-DAEMON@remote.example\r\nTo: {to}\r\nSubject: Undelivered\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=\"BB\"\r\n\r\n" +
                     "--BB\r\nContent-Type: text/plain\r\n\r\nCould not deliver.\r\n" + new string('h', 70_000) + "\r\n" +
                     "--BB\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; remote.example\r\n\r\nFinal-Recipient: rfc822; gone@dest.example\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
                     "--BB\r\nContent-Type: message/rfc822\r\n\r\nSubject: x\r\n\r\n" + new string('o', 1_000_000) + "\r\n--BB--\r\n";
        await using FakeMta mta = await f.ConnectedAsync();

        Assert.Equal(250, (await mta.SendAsync("", to, dsn)).Code);

        Assert.True(await f.Storage.Config.IsSuppressedAsync(InboundFixture.Acme, "gone@dest.example", default));
    }

    [Fact]
    public async Task A_message_to_a_bounce_address_from_a_real_sender_is_limited_to_one_mebibyte_in_data_and_in_bdat_and_the_next_transaction_is_not_affected()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        string bounce = $"{f.Verp.CreateLocalPart(InboundFixture.Acme, f.ExampleOrg, f.Clock.Now, "dest.example")}@{InboundFixture.BounceDomain}";
        string body = "Subject: x\r\n\r\n" + new string('x', 1_500_000) + "\r\n";
        await using FakeMta mta = await f.ConnectedAsync();

        Assert.Equal(552, (await mta.SendAsync("MAILER-DAEMON@remote.example", bounce, body)).Code);
        Assert.Equal(250, (await mta.MailFromAsync("MAILER-DAEMON@remote.example")).Code);
        Assert.Equal(250, (await mta.RcptAsync(bounce)).Code);
        await mta.SendRawAsync($"BDAT {body.Length} LAST\r\n{body}");
        Assert.Equal(552, (await mta.ReadReplyAsync()).Code);
        Assert.Equal(250, (await mta.SendAsync("", bounce, "Subject: x\r\n\r\n" + new string('x', 3_000_000) + "\r\n")).Code);   // the limit did not stay behind
        Assert.Equal(552, (await mta.SendAsync("MAILER-DAEMON@remote.example", bounce, body)).Code);
    }

    // ------------------------------------------------------------------ the sizing check is for servers that receive

    private static MtaConfig Load(params (string Key, string Value)[] values) =>
        ConfigLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build()).Config;

    [Theory]
    [InlineData("Smtp:MaxMessageSize", "104857600")]
    [InlineData("Smtp:MaxInFlightBytes", "134217728")]
    [InlineData("Smtp:MaxInFlightBytes", "0")]
    public void A_server_that_does_not_receive_mail_is_not_refused_for_the_inbound_sizing_rule_and_one_that_does_is(string key, string value)
    {
        var off = new List<string>();
        ConfigLoader.Validate(Load((key, value)), off);
        Assert.DoesNotContain(off, e => e.Contains("Inbound:", StringComparison.Ordinal));

        var on = new List<string>();
        ConfigLoader.Validate(Load((key, value), ("Inbound:Enabled", "true")), on);
        Assert.Contains(on, e => e.Contains("Inbound:", StringComparison.Ordinal) || e.Contains("Smtp:MaxInFlightBytes", StringComparison.Ordinal));
    }

    // ------------------------------------------------------------------ the change signal is not a CLR event

    [Fact]
    public async Task The_change_signal_reaches_a_running_cache_and_a_stopped_one_is_no_longer_called()
    {
        await using InboundFixture f = await InboundFixture.CreateAsync();
        using var stop = new CancellationTokenSource();
        Task running = f.Config.RunAsync(stop.Token);
        Guid route = await f.AddRouteAsync(f.ExampleOrg, InboundFixture.Acme, 60, InboundMatchKind.Address, "signalled", InboundActionKind.Store);
        Assert.NotEqual(Guid.Empty, route);

        InboundDomainView? view = null;
        for (int i = 0; i < 300 && view?.Configuration.Routes.Any(r => r.Id == route) != true; i++)
        {
            InboundConfigChangeSignal.Bump();
            await Task.Delay(20);
            view = f.Config.Find("example.org");
        }

        Assert.Contains(view!.Configuration.Routes, r => r.Id == route);
        await stop.CancelAsync();
        await Task.WhenAny(running, Task.Delay(5000));
        InboundConfigChangeSignal.Bump();   // nothing subscribed any more: harmless
    }
}
