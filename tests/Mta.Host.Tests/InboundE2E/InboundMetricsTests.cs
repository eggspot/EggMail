using System.Diagnostics.Metrics;
using System.Net;
using Mta.Dns;
using Mta.Host.Configuration;
using Mta.Host.Ingest;
using Mta.Host.Tests.Inbound;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

public abstract class InboundMetricsTests(LabBackend backend)
{
    private sealed class Counts : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly Dictionary<string, long> _sums = [];

        public Counts()
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == InboundMetrics.Meter.Name)
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>(Record);
            _listener.Start();
        }

        private void Record(Instrument instrument, long value, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
        {
            string key = instrument.Name + string.Concat(tags.ToArray().OrderBy(t => t.Key, StringComparer.Ordinal).Select(t => $"|{t.Key}={t.Value}"));
            lock (_sums)
            {
                _sums[key] = _sums.GetValueOrDefault(key) + value;
            }
        }

        public long Of(string instrument, params (string Key, string Value)[] tags)
        {
            string key = instrument + string.Concat(tags.OrderBy(t => t.Key, StringComparer.Ordinal).Select(t => $"|{t.Key}={t.Value}"));
            lock (_sums)
            {
                return _sums.GetValueOrDefault(key);
            }
        }

        public void Observe() => _listener.RecordObservableInstruments();

        public void Dispose() => _listener.Dispose();
    }

    [Fact]
    public async Task Every_documented_outcome_of_a_recipient_a_message_and_a_refused_transaction_is_counted_under_its_name()
    {
        var options = new LabOptions
        {
            Inbound = new InboundSection
            {
                Enabled = true, CheckSpfForInternalClients = true, MaxRecipients = 3, MaxMessageSize = 40_000, MaxMessagesPerMinute = 1_000_000, MaxMessagesPerMinutePerRemote = 4, MaxStoredBytesPerDomain = 0,
                Dnsbl = new InboundDnsblSection { Zones = ["bl.test"] },
            },
        };
        await using InboundLab? lab = await InboundLab.StartAsync(backend, options);
        if (lab is null)
        {
            return;
        }

        using var counts = new Counts();
        lab.Dns.AddTxt("sender.test", "v=spf1 ip4:203.0.113.0/24 ip4:127.0.0.1 -all");
        lab.PublishDmarc("sender.test", "none");
        lab.PublishSpf("eve.test", authorize: false);
        lab.PublishDmarc("eve.test", "reject");
        await lab.SetSettingsAsync(lab.ExampleNet, InboundLab.Globex, s => s with { DmarcAction = InboundDmarcAction.Reject });
        Guid pending = await lab.AddDomainAsync(InboundLab.Acme, "pending.example", status: DomainStatus.Pending);
        await lab.AddRouteAsync(pending, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        Guid small = await lab.AddDomainAsync(InboundLab.Acme, "small.example", change: s => s with { MaxStoredBytes = 100 });
        await lab.AddRouteAsync(small, InboundLab.Acme, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        Guid tiny = await lab.AddDomainAsync(InboundLab.Globex, "tiny.example", change: s => s with { MaxMessageBytes = 2_048 });
        await lab.AddRouteAsync(tiny, InboundLab.Globex, 10, InboundMatchKind.CatchAll, null, InboundActionKind.Store);
        await lab.RefreshAsync();
        lab.Dns.AddA("9.113.0.203.bl.test", "127.0.0.2");
        lab.Dns.Fail("10.113.0.203.bl.test", DnsRecordType.A);

        lab.ClientIp = IPAddress.Parse("203.0.113.11");
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message())).Code);
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "postmaster@example.org", InboundLab.Message())).Code);
        await using (FakeMta mta = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await mta.MailFromAsync("bob@sender.test")).Code);
            Assert.Equal(550, (await mta.RcptAsync("x@gmail.test")).Code);
            Assert.Equal(550, (await mta.RcptAsync("nobody@example.org")).Code);
            Assert.Equal(450, (await mta.RcptAsync("x@pending.example")).Code);
            Assert.Equal(250, (await mta.RcptAsync("support@example.org")).Code);
            Assert.Equal(452, (await mta.RcptAsync($"{lab.BounceLocalPart()}@{InboundLab.BounceDomain}")).Code);
            Assert.Equal(250, (await mta.RcptAsync("old@example.org")).Code);
            Assert.Equal(250, (await mta.RcptAsync("billing-1@example.org")).Code);
            Assert.Equal(452, (await mta.RcptAsync("anyone@example.net")).Code);
        }

        Assert.Equal(552, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(body: new string('x', 50_000) + "\r\n"))).Code);
        await using (FakeMta big = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await big.MailFromAsync("bob@sender.test", "SIZE=5000")).Code);
            Assert.Equal(552, (await big.RcptAsync("x@tiny.example")).Code);
        }

        Assert.Equal(550, (await lab.SendAsync("eve@eve.test", "anyone@example.net", InboundLab.Message(from: "eve@eve.test"))).Code);

        await using (FakeMta mixed = await lab.ConnectedAsync())
        {
            Assert.Equal(250, (await mixed.MailFromAsync("")).Code);
            Assert.Equal(250, (await mixed.RcptAsync($"{lab.Srs.CreateLocalPart("sender.test", "bob", lab.Clock.UtcNow)}@example.org")).Code);
            Assert.Equal(452, (await mixed.RcptAsync("support@example.org")).Code);
        }

        string token = lab.BounceLocalPart();
        Assert.Equal(250, (await lab.SendAsync("", $"{token}@{InboundLab.BounceDomain}", InboundLab.Dsn($"{token}@{InboundLab.BounceDomain}", "gone@dest.example"))).Code);

        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "x@small.example", InboundLab.Message())).Code);
        await lab.AdvanceAsync(TimeSpan.FromSeconds(6));
        Assert.Equal(452, (await lab.SendAsync("bob@sender.test", "x@small.example", InboundLab.Message())).Code);

        for (int i = 0; i < 6; i++)
        {
            await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "burst " + i));
        }

        lab.ClientIp = IPAddress.Parse("203.0.113.9");
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "anyone@example.net", InboundLab.Message())).Code);
        lab.ClientIp = IPAddress.Parse("203.0.113.10");
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "anyone@example.net", InboundLab.Message())).Code);

        counts.Observe();
        foreach (string outcome in new[] { "accepted", "postmaster", "relay_denied", "unknown_mailbox", "domain_unverified", "mixed_kinds", "too_many", "message_too_large", "srs_bounce", "bounce", "mailbox_full", "rate_limited" })
        {
            Assert.True(counts.Of("mta.inbound.recipients", ("outcome", outcome)) >= 1, $"recipient outcome '{outcome}' was never counted");
        }

        foreach (string outcome in new[] { "accepted", "rejected_size", "rejected_dmarc" })
        {
            Assert.True(counts.Of("mta.inbound.messages", ("outcome", outcome)) >= 1, $"message outcome '{outcome}' was never counted");
        }

        foreach (string reason in new[] { "mixed_kinds", "dmarc" })
        {
            Assert.True(counts.Of("mta.inbound.transactions.refused", ("reason", reason)) >= 1, $"refusal reason '{reason}' was never counted");
        }

        foreach ((string mechanism, string result) in new[] { ("spf", "pass"), ("spf", "fail"), ("spf_helo", "none"), ("dkim", "none"), ("dmarc", "pass"), ("dmarc", "fail"), ("arc", "none") })
        {
            Assert.True(counts.Of("mta.inbound.auth", ("mechanism", mechanism), ("result", result)) >= 1, $"{mechanism}={result} was never counted");
        }

        foreach (string result in new[] { "hit", "miss", "error" })
        {
            Assert.True(counts.Of("mta.inbound.dnsbl", ("result", result)) >= 1, $"blocklist result '{result}' was never counted");
        }

        Assert.True(counts.Of("mta.inbound.bytes") > 0);
        Assert.True(counts.Of("mta.inbound.limiter.entries", ("limiter", "domain")) >= 0);
    }
}

public sealed class SqliteInboundMetricsTests() : InboundMetricsTests(LabBackend.Sqlite);

public sealed class PostgresInboundMetricsTests() : InboundMetricsTests(LabBackend.Postgres);
