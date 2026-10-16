using System.Net;
using System.Text;
using Mta.Auth.Dmarc;
using Mta.Dsn;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Ingest;
using Mta.Smtp.Server;
using Mta.Storage;
using Microsoft.Extensions.Configuration;

namespace Mta.Host.Tests.Inbound;

/// <summary>The pure parts of the receive path: the DMARC decision table, header analysis, limiters, slots, the listener mapping and the configuration keys.</summary>
public class InboundUnitTests
{
    // ------------------------------------------------------------------ the decision table

    private static DmarcEvaluation Evaluation(DmarcResult result, DmarcDisposition disposition) =>
        new(result, disposition, null, "sender.test", "sender.test", "sender.test", false, false, false, null, null, null, null);

    private static InboundVerification Verification(DmarcResult result, DmarcDisposition disposition, bool unsettled = false, bool arc = false) => new()
    {
        Auth = InboundAuthResults.NotChecked,
        Dmarc = Evaluation(result, disposition),
        Unsettled = unsettled,
        ArcOverridesDmarc = arc,
        AuthenticationResultsHeader = "Authentication-Results: x\r\n",
    };

    private const InboundDmarcAction Rec = InboundDmarcAction.RecordOnly, Flag = InboundDmarcAction.Flag, Rej = InboundDmarcAction.Reject;

    [Theory]
    // result, disposition (after pct sampling), unsettled, arc override, actions -> refusal, flagged per recipient
    [InlineData(DmarcResult.Pass, DmarcDisposition.None, false, false, new[] { Rej }, InboundDmarcRefusal.None, new[] { false })]
    [InlineData(DmarcResult.Fail, DmarcDisposition.Reject, false, false, new[] { Rec }, InboundDmarcRefusal.None, new[] { false })]
    [InlineData(DmarcResult.Fail, DmarcDisposition.Reject, false, false, new[] { Flag }, InboundDmarcRefusal.None, new[] { true })]
    [InlineData(DmarcResult.Fail, DmarcDisposition.Quarantine, false, false, new[] { Flag }, InboundDmarcRefusal.None, new[] { true })]
    [InlineData(DmarcResult.Fail, DmarcDisposition.None, false, false, new[] { Flag }, InboundDmarcRefusal.None, new[] { false })]
    [InlineData(DmarcResult.Fail, DmarcDisposition.Reject, false, false, new[] { Rej }, InboundDmarcRefusal.Reject, new[] { false })]
    [InlineData(DmarcResult.Fail, DmarcDisposition.Quarantine, false, false, new[] { Rej }, InboundDmarcRefusal.None, new[] { true })]
    [InlineData(DmarcResult.Fail, DmarcDisposition.Reject, false, false, new[] { Rej, Rej }, InboundDmarcRefusal.Reject, new[] { false, false })]
    [InlineData(DmarcResult.Fail, DmarcDisposition.Reject, false, false, new[] { Rej, Rec }, InboundDmarcRefusal.None, new[] { true, false })]
    [InlineData(DmarcResult.Fail, DmarcDisposition.Reject, false, false, new[] { Rej, Flag }, InboundDmarcRefusal.None, new[] { true, true })]
    [InlineData(DmarcResult.TempError, DmarcDisposition.None, true, false, new[] { Rej }, InboundDmarcRefusal.TryLater, new[] { false })]
    [InlineData(DmarcResult.TempError, DmarcDisposition.None, true, false, new[] { Rej, Rej }, InboundDmarcRefusal.TryLater, new[] { false, false })]
    [InlineData(DmarcResult.TempError, DmarcDisposition.None, true, false, new[] { Rej, Rec }, InboundDmarcRefusal.None, new[] { false, false })]
    [InlineData(DmarcResult.TempError, DmarcDisposition.None, true, false, new[] { Flag }, InboundDmarcRefusal.None, new[] { false })]
    [InlineData(DmarcResult.Fail, DmarcDisposition.Reject, true, false, new[] { Rej }, InboundDmarcRefusal.TryLater, new[] { false })]
    [InlineData(DmarcResult.Fail, DmarcDisposition.Reject, false, true, new[] { Rej }, InboundDmarcRefusal.None, new[] { false })]
    [InlineData(DmarcResult.None, DmarcDisposition.None, false, false, new[] { Rej }, InboundDmarcRefusal.None, new[] { false })]
    [InlineData(DmarcResult.PermError, DmarcDisposition.None, false, false, new[] { Rej }, InboundDmarcRefusal.None, new[] { false })]
    public void The_dmarc_decision_follows_the_table_of_the_design(DmarcResult result, DmarcDisposition disposition, bool unsettled, bool arc, InboundDmarcAction[] actions, InboundDmarcRefusal refusal, bool[] flagged)
    {
        InboundDmarcOutcome outcome = InboundDmarcDecision.Decide(Verification(result, disposition, unsettled, arc), actions);

        Assert.Equal(refusal, outcome.Refusal);
        Assert.Equal(flagged, outcome.Flagged);
    }

    // ------------------------------------------------------------------ header analysis

    private static InboundHeaderAnalysis Analyze(string message, ForwardHopMarker? hops = null) =>
        InboundHeaderAnalysis.Analyze(Encoding.UTF8.GetBytes(message), ["mx.egg.test"], hops);

    [Fact]
    public void Folded_fields_are_removed_with_their_continuation_lines_and_the_rest_is_kept_byte_for_byte()
    {
        const string message = "Authentication-Results: mx.egg.test;\r\n dkim=pass\r\n\theader.d=evil.test\r\nX-EggMail-Dmarc: flagged\r\nSubject: kept\r\n folded subject\r\nFrom: a@sender.test\r\n\r\nbody\r\n";

        InboundHeaderAnalysis analysis = Analyze(message);
        string stored = Encoding.UTF8.GetString(analysis.Compose("Received: x\r\n"u8));

        Assert.Equal("Received: x\r\nSubject: kept\r\n folded subject\r\nFrom: a@sender.test\r\n\r\nbody\r\n", stored);
        Assert.Equal(2, analysis.RemovedCount);
        Assert.Equal("kept folded subject", analysis.Subject);
        Assert.Equal(["sender.test"], analysis.FromDomains);
    }

    [Fact]
    public void A_message_with_nothing_to_remove_is_the_prefix_and_the_received_bytes()
    {
        const string message = "From: a@sender.test\r\nSubject: s\r\n\r\nbody\r\n";

        InboundHeaderAnalysis analysis = Analyze(message);

        Assert.False(analysis.HasRemovals);
        Assert.Equal("P: 1\r\n" + message, Encoding.UTF8.GetString(analysis.Compose("P: 1\r\n"u8)));
    }

    [Fact]
    public void The_subject_loses_control_characters_is_cut_to_256_characters_and_decodes_encoded_words()
    {
        InboundHeaderAnalysis analysis = Analyze("Subject: =?utf-8?B?" + Convert.ToBase64String(Encoding.UTF8.GetBytes("café\u0001 \u0007" + new string('x', 400))) + "?=\r\n\r\n");

        Assert.NotNull(analysis.Subject);
        Assert.True(analysis.Subject!.Length <= 256);
        Assert.StartsWith("café", analysis.Subject, StringComparison.Ordinal);
        Assert.DoesNotContain(analysis.Subject, char.IsControl);
    }

    [Fact]
    public void Several_from_domains_are_collected_and_a_fourth_marks_the_message()
    {
        InboundHeaderAnalysis three = Analyze("From: a@one.test, b@two.test\r\nFrom: c@three.test\r\nFrom: d@ONE.test\r\n\r\n");
        Assert.Equal(["one.test", "two.test", "three.test"], three.FromDomains);
        Assert.False(three.TooManyFromDomains);

        Assert.True(Analyze("From: a@one.test, b@two.test, c@three.test, d@four.test\r\n\r\n").TooManyFromDomains);
    }

    [Fact]
    public void A_name_with_white_space_before_the_colon_is_still_our_namespace()
    {
        InboundHeaderAnalysis analysis = Analyze("X-EggMail-Dmarc : flagged\r\nX-EggMail-Hops\t: 9; 0123456789abcdef\r\n\r\n");

        Assert.Equal(2, analysis.RemovedCount);
    }

    // ------------------------------------------------------------------ network keys

    [Theory]
    [InlineData("203.0.113.9", "203.0.113.9", "4:CB0071")]
    [InlineData("::ffff:203.0.113.9", "203.0.113.9", "4:CB0071")]
    [InlineData("2001:db8:1:2:3:4:5:6", "6:20010DB800010002", "6:20010DB800010002")]
    public void Clients_are_keyed_by_address_or_prefix_with_a_mapped_address_normalized(string address, string remoteKey, string slotKey)
    {
        var ip = IPAddress.Parse(address);

        Assert.Equal(remoteKey, NetworkKey.Remote(ip));
        Assert.Equal(slotKey, NetworkKey.Slot(ip));
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.17.0.1", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.1.1", true)]
    [InlineData("169.254.1.1", true)]
    [InlineData("100.64.0.1", true)]
    [InlineData("::ffff:10.0.0.1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("fd00::1", true)]
    [InlineData("203.0.113.9", false)]
    [InlineData("2001:db8::1", false)]
    public void Internal_addresses_are_the_ones_a_public_sender_cannot_have(string address, bool expected) =>
        Assert.Equal(expected, NetworkKey.IsInternal(IPAddress.Parse(address)));

    // ------------------------------------------------------------------ slots and counters

    [Fact]
    public void Slots_are_bounded_globally_and_per_network_and_released_by_the_lease()
    {
        var slots = new VerificationSlots(maxConcurrency: 3, maxPerNetwork: 2);
        var a = IPAddress.Parse("203.0.113.1");
        var sameNetwork = IPAddress.Parse("203.0.113.200");
        var other = IPAddress.Parse("198.51.100.1");

        using VerificationSlots.Lease one = slots.TryAcquire(a)!;
        VerificationSlots.Lease two = slots.TryAcquire(sameNetwork)!;
        Assert.Null(slots.TryAcquire(a));   // the third from the same /24
        Assert.False(slots.HasFreeSlotFor(a));
        Assert.True(slots.HasFreeSlotFor(other));
        using VerificationSlots.Lease three = slots.TryAcquire(other)!;
        Assert.Null(slots.TryAcquire(IPAddress.Parse("192.0.2.1")));   // all three are in use
        Assert.Equal(3, slots.InUse);

        two.Dispose();
        two.Dispose();   // twice is harmless
        Assert.Equal(2, slots.InUse);
        Assert.NotNull(slots.TryAcquire(a));
    }

    [Fact]
    public void A_window_counter_counts_per_minute_and_stays_within_its_bound()
    {
        var counter = new BoundedWindowCounter("remote", maxEntries: 10);
        DateTimeOffset t = new(2026, 10, 16, 12, 0, 5, TimeSpan.Zero);

        Assert.Equal(1, counter.Add("a", t));
        Assert.Equal(2, counter.Add("a", t.AddSeconds(30)));
        Assert.Equal(2, counter.Peek("a", t.AddSeconds(40)));
        Assert.Equal(0, counter.Peek("a", t.AddSeconds(60)));   // the next minute
        Assert.Equal(1, counter.Add("a", t.AddSeconds(60)));

        for (int i = 0; i < 100; i++)
        {
            counter.Add("k" + i, t.AddSeconds(60));
        }

        Assert.True(counter.Count <= 10);
    }

    // ------------------------------------------------------------------ the listener and the configuration

    private static SmtpListenerOptions Bounce() => new() { Name = "bounce", Port = 2526, Role = ListenerRole.Bounce, AuthRequired = false };

    [Fact]
    public void With_inbound_on_the_port_25_listener_becomes_an_mx_receiver_with_the_inbound_limits_and_submission_listeners_are_untouched()
    {
        var on = new InboundReceiveOptions { Enabled = true, MaxRecipients = 7, Ceilings = new InboundCeilings(12345, 1, 1, 0, 0, 0) };
        var submission = new SmtpListenerOptions { Name = "submission", Port = 5587, Role = ListenerRole.Submission };

        SmtpListenerOptions mx = EggMailRuntime.InboundListener(Bounce(), on);

        Assert.Equal((ListenerRole.Inbound, 12345L, 8, false), (mx.Role, mx.MaxMessageSize, mx.MaxRecipients, mx.AuthRequired));
        Assert.Same(submission, EggMailRuntime.InboundListener(submission, on));
    }

    [Fact]
    public void With_inbound_off_the_listener_is_the_bounce_listener_it_always_was_even_when_configured_as_inbound()
    {
        var off = new InboundReceiveOptions { Enabled = false };

        Assert.Equal(ListenerRole.Bounce, EggMailRuntime.InboundListener(Bounce(), off).Role);
        Assert.Equal(ListenerRole.Bounce, EggMailRuntime.InboundListener(new SmtpListenerOptions { Name = "bounce", Port = 1, Role = ListenerRole.Inbound }, off).Role);
        Assert.Equal(ListenerRole.Submission, EggMailRuntime.InboundListener(new SmtpListenerOptions { Name = "s", Port = 1, Role = ListenerRole.Submission }, off).Role);
    }

    private static MtaConfig Load(params (string Key, string Value)[] values)
    {
        IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build();
        return ConfigLoader.Load(configuration).Config;
    }

    [Fact]
    public void The_defaults_are_off_and_the_documented_limits()
    {
        MtaConfig config = Load();
        InboundReceiveOptions o = InboundReceiveOptions.From(config);

        Assert.False(o.Enabled);
        Assert.Equal((20, 256L << 20, 32, 4, TimeSpan.FromSeconds(20), 21), (o.MaxRecipients, o.MaxTransactionBytes, o.VerificationMaxConcurrency, o.VerificationMaxConcurrencyPerRemote, o.VerificationTimeout, o.SrsMaxAgeDays));
        Assert.Equal(config.Smtp.MaxMessageSize, o.Ceilings.MaxMessageBytes);
        Assert.Equal((600, 60, 2L << 30, 10L << 30), (o.Ceilings.MaxMessagesPerMinute, o.Ceilings.MaxMessagesPerMinutePerRemote, o.Ceilings.MaxStoredBytesPerDomain, o.Ceilings.MaxStoredBytesPerTenant));
        Assert.Empty(o.TrustedArcSealers);
        Assert.Empty(o.DnsblZones);
        Assert.False(o.DnsblReject);
    }

    [Fact]
    public void The_keys_are_read_lists_included()
    {
        MtaConfig config = Load(
            ("Inbound:Enabled", "true"), ("Inbound:MaxMessageSize", "1000000"), ("Inbound:MaxRecipients", "5"), ("Inbound:Verification:Timeout", "00:00:07"),
            ("Inbound:Arc:TrustedSealers", "Forwarder.Test, other.test"), ("Inbound:Dnsbl:Zones", "bl.example;bl2.example"), ("Inbound:Dnsbl:Action", "Reject"), ("Inbound:AuthenticationResultsId", "mx.example.org"));
        InboundReceiveOptions o = InboundReceiveOptions.From(config);

        Assert.True(o.Enabled);
        Assert.Equal((1_000_000L, 5, TimeSpan.FromSeconds(7), "mx.example.org"), (o.Ceilings.MaxMessageBytes, o.MaxRecipients, o.VerificationTimeout, o.AuthenticationResultsId));
        Assert.Equal(["forwarder.test", "other.test"], o.TrustedArcSealers);
        Assert.Equal(["bl.example", "bl2.example"], o.DnsblZones);
        Assert.True(o.DnsblReject);
    }

    [Theory]
    [InlineData("Inbound:MaxRecipients", "0")]
    [InlineData("Inbound:MaxTransactionBytes", "10")]
    [InlineData("Inbound:Verification:MaxConcurrency", "0")]
    [InlineData("Inbound:Verification:Timeout", "00:00:00")]
    [InlineData("Inbound:Srs:MaxAgeDays", "0")]
    [InlineData("Inbound:Dnsbl:Zones", "not a domain!")]
    [InlineData("Inbound:Arc:TrustedSealers", "bad_domain;x")]
    [InlineData("Inbound:AuthenticationResultsId", "a;b")]
    [InlineData("Inbound:Dnsbl:Zones", "a.test,b.test,c.test,d.test,e.test,f.test,g.test,h.test,i.test")]
    public void A_contradictory_inbound_setting_is_a_configuration_error(string key, string value)
    {
        var errors = new List<string>();

        ConfigLoader.Validate(Load((key, value)), errors);

        Assert.Contains(errors, e => e.Contains("Inbound", StringComparison.Ordinal));
    }
}
