using System.Net;
using System.Text;
using Mta.Core;
using Mta.Storage;
using Mta.Webhooks;

namespace Mta.Webhooks.Tests;

public class SignerTests
{
    // Known-answer test built from the Standard Webhooks reference algorithm:
    // key = base64("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"), id msg_p5jXN8AQM9LWM0D4loKWxJek, ts 1614265330, payload {"test": 2432232314}
    [Fact]
    public void Matches_reference_vector()
    {
        const string secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        string sig = StandardWebhooksSigner.Sign("msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, "{\"test\": 2432232314}"u8, secret);
        Assert.Equal("v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=", sig);
    }

    [Fact]
    public void Sign_and_verify_roundtrip_with_rotation()
    {
        string s1 = StandardWebhooksSigner.GenerateSecret(), s2 = StandardWebhooksSigner.GenerateSecret();
        var now = DateTimeOffset.UtcNow;
        byte[] payload = Encoding.UTF8.GetBytes("{\"a\":1}");
        string header = StandardWebhooksSigner.Sign("evt_1", now.ToUnixTimeSeconds(), payload, [s1, s2]);
        Assert.Equal(2, header.Split(' ').Length);
        Assert.True(StandardWebhooksSigner.Verify("evt_1", now.ToUnixTimeSeconds().ToString(), header, payload, [s2], now));
        Assert.True(StandardWebhooksSigner.Verify("evt_1", now.ToUnixTimeSeconds().ToString(), header, payload, [s1], now));
    }

    [Fact]
    public void Verification_rejects_tampering_replay_and_garbage()
    {
        string s = StandardWebhooksSigner.GenerateSecret();
        var now = DateTimeOffset.UtcNow;
        long ts = now.ToUnixTimeSeconds();
        byte[] payload = "{\"a\":1}"u8.ToArray();
        string header = StandardWebhooksSigner.Sign("evt_1", ts, payload, s);
        Assert.False(StandardWebhooksSigner.Verify("evt_2", ts.ToString(), header, payload, [s], now));            // other id
        Assert.False(StandardWebhooksSigner.Verify("evt_1", ts.ToString(), header, "{\"a\":2}"u8, [s], now));        // other payload
        Assert.False(StandardWebhooksSigner.Verify("evt_1", ts.ToString(), header, payload, [StandardWebhooksSigner.GenerateSecret()], now));
        Assert.False(StandardWebhooksSigner.Verify("evt_1", ts.ToString(), header, payload, [s], now.AddMinutes(10))); // too old
        Assert.False(StandardWebhooksSigner.Verify("evt_1", ts.ToString(), header, payload, [s], now.AddMinutes(-10))); // from the future
        Assert.False(StandardWebhooksSigner.Verify("evt_1", "abc", header, payload, [s], now));
        Assert.False(StandardWebhooksSigner.Verify("evt_1", ts.ToString(), "v1,!!!notbase64", payload, [s], now));
        Assert.False(StandardWebhooksSigner.Verify("evt_1", ts.ToString(), "v2,AAAA", payload, [s], now));
    }
}

public class SsrfGuardTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("1.1.1.1", true)]
    [InlineData("93.184.216.34", true)]
    [InlineData("2606:4700:4700::1111", true)]
    [InlineData("127.0.0.1", false)]
    [InlineData("127.1.2.3", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.31.255.255", false)]
    [InlineData("172.32.0.1", true)]
    [InlineData("192.168.1.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("169.254.0.1", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("0.0.0.0", false)]
    [InlineData("224.0.0.1", false)]
    [InlineData("255.255.255.255", false)]
    [InlineData("240.0.0.1", false)]
    [InlineData("198.18.0.1", false)]
    [InlineData("192.0.2.1", false)]
    [InlineData("::1", false)]
    [InlineData("::", false)]
    [InlineData("fc00::1", false)]
    [InlineData("fd12:3456::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("ff02::1", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("::ffff:127.0.0.1", false)]
    [InlineData("::ffff:10.1.2.3", false)]
    [InlineData("::ffff:8.8.8.8", true)]
    [InlineData("2002:7f00:0001::1", false)]   // 6to4 embedding 127.0.0.1
    [InlineData("64:ff9b::a00:1", false)]      // NAT64 embedding 10.0.0.1
    public void Classifies_addresses(string ip, bool publicAddr) => Assert.Equal(publicAddr, SsrfGuard.IsPubliclyRoutable(IPAddress.Parse(ip)));

    [Fact]
    public async Task Rebinding_style_answers_are_filtered_per_address()
    {
        // Resolver returns a public and a private address: only the public one may be used.
        ValueTask<IPAddress[]> Resolve(string h, CancellationToken ct) => ValueTask.FromResult(new[] { IPAddress.Parse("10.0.0.5"), IPAddress.Parse("8.8.4.4") });
        var ok = await SsrfGuard.ResolveAllowedAsync("hook.example", Resolve, [], default);
        Assert.Equal([IPAddress.Parse("8.8.4.4")], ok);
        ValueTask<IPAddress[]> OnlyPrivate(string h, CancellationToken ct) => ValueTask.FromResult(new[] { IPAddress.Parse("169.254.169.254") });
        Assert.Empty(await SsrfGuard.ResolveAllowedAsync("metadata.example", OnlyPrivate, [], default));
    }

    [Fact]
    public async Task Allowlist_permits_internal_networks_explicitly()
    {
        ValueTask<IPAddress[]> Resolve(string h, CancellationToken ct) => ValueTask.FromResult(new[] { IPAddress.Parse("10.1.2.3") });
        Assert.Empty(await SsrfGuard.ResolveAllowedAsync("internal.example", Resolve, [], default));
        var allowed = await SsrfGuard.ResolveAllowedAsync("internal.example", Resolve, [IpNetwork.Parse("10.1.0.0/16")], default);
        Assert.Single(allowed);
        Assert.Empty(await SsrfGuard.ResolveAllowedAsync("internal.example", Resolve, [IpNetwork.Parse("10.2.0.0/16")], default));
    }

    [Fact]
    public async Task Literal_ip_hosts_skip_dns()
    {
        ValueTask<IPAddress[]> Resolve(string h, CancellationToken ct) => throw new InvalidOperationException("DNS must not be used for literals");
        Assert.Empty(await SsrfGuard.ResolveAllowedAsync("127.0.0.1", Resolve, [], default));
        Assert.Empty(await SsrfGuard.ResolveAllowedAsync("[::1]", Resolve, [], default));
        Assert.Single(await SsrfGuard.ResolveAllowedAsync("1.1.1.1", Resolve, [], default));
    }

    [Theory]
    [InlineData("10.0.0.0/8", "10.255.255.255", true)]
    [InlineData("10.0.0.0/8", "11.0.0.0", false)]
    [InlineData("192.168.1.128/25", "192.168.1.200", true)]
    [InlineData("192.168.1.128/25", "192.168.1.100", false)]
    [InlineData("fd00::/8", "fd12::1", true)]
    [InlineData("fd00::/8", "fe00::1", false)]
    [InlineData("127.0.0.1", "127.0.0.1", true)]
    public void Cidr_matching(string cidr, string ip, bool expected) => Assert.Equal(expected, IpNetwork.Parse(cidr).Contains(IPAddress.Parse(ip)));
}

public class UrlValidatorTests
{
    [Theory]
    [InlineData("https://hooks.example.com/path", true)]
    [InlineData("https://hooks.example.com:8443/x?y=1", true)]
    [InlineData("http://hooks.example.com/", false)]
    [InlineData("ftp://x.example/", false)]
    [InlineData("https://user:pw@hooks.example.com/", false)]
    [InlineData("https://127.0.0.1/", false)]
    [InlineData("https://[::1]/", false)]
    [InlineData("https://169.254.169.254/latest", false)]
    [InlineData("https://localhost/", false)]
    [InlineData("not a url", false)]
    [InlineData("", false)]
    public void Validates(string url, bool ok) => Assert.Equal(ok, WebhookUrlValidator.TryValidate(url, false, [], out _));

    [Fact]
    public void Http_allowed_when_configured_and_allowlist_overrides()
    {
        Assert.True(WebhookUrlValidator.TryValidate("http://hooks.example.com/", true, [], out _));
        Assert.False(WebhookUrlValidator.TryValidate("https://10.0.0.5/hook", false, [], out _));
        Assert.True(WebhookUrlValidator.TryValidate("https://10.0.0.5/hook", false, [IpNetwork.Parse("10.0.0.0/8")], out _));
    }
}

public class EventFactoryTests
{
    private static ClaimedDelivery Delivery() => new()
    {
        DeliveryId = Ids.New(), MessageId = Ids.New(), TenantId = Ids.New(), EnvelopeFrom = EmailAddress.Parse("s@example.org"),
        Recipient = EmailAddress.Parse("r@dest.example"), RecipientDomain = "dest.example", Attempt = 2,
        CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = DateTimeOffset.UtcNow.AddDays(5), LeaseUntil = DateTimeOffset.UtcNow.AddMinutes(5),
    };

    [Fact]
    public void Delivered_event_payload()
    {
        var d = Delivery();
        var at = new DateTimeOffset(2026, 10, 12, 8, 0, 0, TimeSpan.Zero);
        var ev = WebhookEventFactory.ForAttempt(d, new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = at, SmtpCode = 250, EnhancedCode = "2.0.0", Message = "queued", MxHost = "mx.dest.example" });
        Assert.NotNull(ev);
        Assert.Equal("message.delivered", ev!.EventType);
        using var doc = System.Text.Json.JsonDocument.Parse(ev.PayloadJson);
        var root = doc.RootElement;
        Assert.Equal("message.delivered", root.GetProperty("type").GetString());
        Assert.StartsWith("evt_", root.GetProperty("id").GetString());
        var data = root.GetProperty("data");
        Assert.Equal("r@dest.example", data.GetProperty("recipient").GetString());
        Assert.Equal(3, data.GetProperty("attempt").GetInt32());
        Assert.Equal(250, data.GetProperty("smtp_code").GetInt32());
    }

    [Theory]
    [InlineData(DeliveryOutcome.Deferred, "message.deferred")]
    [InlineData(DeliveryOutcome.Failed, "message.bounced")]
    [InlineData(DeliveryOutcome.Expired, "message.expired")]
    [InlineData(DeliveryOutcome.Suppressed, "message.suppressed")]
    public void Event_types(DeliveryOutcome outcome, string type) => Assert.Equal(type, WebhookEventFactory.EventTypeFor(outcome));

    [Fact]
    public void Internal_outcomes_have_no_public_event()
    {
        var d = Delivery();
        Assert.Null(WebhookEventFactory.ForAttempt(d, new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.AbortedBySwitch, At = DateTimeOffset.UtcNow }));
        Assert.Null(WebhookEventFactory.ForAttempt(d, new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Cancelled, At = DateTimeOffset.UtcNow }));
    }
}
