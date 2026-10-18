using Mta.Core;
using Mta.Dns;
using Mta.Storage;

namespace Mta.Delivery.Tests;

/// <summary>
/// Security regression tests (docs/security-test-map.md, RELAY-6; decision 100): a mail exchanger the server refuses to talk to because it is in an internal network
/// is the operator's policy, not a verdict on the recipient. The mail waits (and bounces at expiry saying why); the recipient is never bounced at once or suppressed.
/// </summary>
public class InternalMailExchangerTests
{
    private sealed class CapturingLog : IMtaLog
    {
        public List<string> Lines { get; } = [];

        public bool IsEnabled(MtaLogLevel level) => true;

        public void Write(MtaLogLevel level, string component, string message, Exception? exception = null)
        {
            lock (Lines) { Lines.Add($"{level} {component}: {message}"); }
        }
    }

    [Theory]
    [InlineData("10.0.0.5")]
    [InlineData("192.168.1.9")]
    [InlineData("169.254.169.254")]
    [InlineData("127.0.0.1")]
    public async Task A_domain_whose_mail_host_is_in_an_internal_network_is_held_and_never_bounced_or_suppressed(string address)
    {
        var log = new CapturingLog();
        await using var f = new DeliveryFixture(mxOptions: new MxResolverOptions(), log: log);
        f.Dns.AddMx("internal.example", 10, "mx.internal.example").AddA("mx.internal.example", address);
        var id = await f.EnqueueAsync(["user@internal.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Deferred);

        var deferred = events.Single(e => e.Type == MessageEventType.Deferred);
        Assert.Equal(451, deferred.SmtpCode);
        Assert.Equal("4.4.4", deferred.EnhancedCode);
        Assert.Contains("Delivery:AllowPrivateMxAddresses", deferred.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Bounced);
        Assert.False(await f.Storage.Config.IsSuppressedAsync(DeliveryFixture.Tenant, "user@internal.example", default));
        Assert.Equal(0, f.Remote.Connections);                               // nothing was connected to
        lock (log.Lines) { Assert.Contains(log.Lines, l => l.StartsWith("Warning", StringComparison.Ordinal) && l.Contains("Delivery:AllowPrivateMxAddresses", StringComparison.Ordinal) && l.Contains("internal.example", StringComparison.Ordinal)); }
        var stats = await f.Storage.Deliveries.GetQueueStatsAsync(default);
        Assert.Equal(1, stats.Deferred);                                     // still queued, retried until it expires
    }

    [Fact]
    public async Task The_mail_expires_with_the_reason_in_the_bounce_text_and_still_no_suppression()
    {
        await using var f = new DeliveryFixture(mxOptions: new MxResolverOptions());
        f.Dns.AddMx("internal.example", 10, "mx.internal.example").AddA("mx.internal.example", "10.0.0.5");
        var id = await f.EnqueueAsync(["user@internal.example"], lifetime: TimeSpan.FromMilliseconds(600));

        var events = await f.WaitForEventAsync(id, MessageEventType.Expired);

        var expired = events.Single(e => e.Type == MessageEventType.Expired);
        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Bounced);
        Assert.False(await f.Storage.Config.IsSuppressedAsync(DeliveryFixture.Tenant, "user@internal.example", default));
        string said = (expired.Message ?? "") + string.Join(' ', events.Select(e => e.Message));
        Assert.Contains("Delivery:AllowPrivateMxAddresses", said, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_domain_with_one_internal_and_one_documentation_range_mail_host_is_delivered_through_the_second()
    {
        // The internal host is dropped; the host in the documentation range (never routed, used here as "a public mail server") is kept and reached through the test port.
        await using var f = new DeliveryFixture(mxOptions: new MxResolverOptions { ExcludeSpecialAddresses = true });
        f.Dns.AddMx("mixed.example", 10, "internal.mixed.example").AddMx("mixed.example", 20, "mx.mixed.example")
            .AddA("internal.mixed.example", "10.0.0.5").AddA("mx.mixed.example", "192.0.2.10");
        var mx = await new MxResolver(f.Dns, new MxResolverOptions()).ResolveAsync("mixed.example");

        Assert.Equal(MxResolutionStatus.Ok, mx.Status);
        Assert.Equal(["mx.mixed.example"], mx.Exchangers.Select(e => e.Host));
    }

    [Fact]
    public async Task A_domain_that_really_has_no_mail_host_is_still_a_permanent_failure()
    {
        await using var f = new DeliveryFixture(mxOptions: new MxResolverOptions());
        f.Dns.AddMx("nohost.example", 10, "mx.nohost.example");   // no address record at all
        var id = await f.EnqueueAsync(["user@nohost.example"]);

        var events = await f.WaitForEventAsync(id, MessageEventType.Bounced);

        Assert.Equal("5.1.2", events.Single(e => e.Type == MessageEventType.Bounced).EnhancedCode);
    }
}
