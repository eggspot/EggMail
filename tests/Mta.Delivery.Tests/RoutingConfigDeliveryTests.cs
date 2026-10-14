using Mta.Core;
using Mta.Smtp.Client;
using Mta.Storage;

namespace Mta.Delivery.Tests;

/// <summary>
/// Relay routes and per-domain TLS policies written to the config store reach the running engine: its refresh reloads them and the next delivery follows them.
/// Waits are on the engine's refresh counter and on stored events, never on time.
/// </summary>
[Collection("delivery-pipeline")]
public class RoutingConfigDeliveryTests
{
    private static DeliveryOptions Refresh(DeliveryOptions o, TimeSpan interval) =>
        new() { Owner = o.Owner, Hostname = o.Hostname, RemotePort = o.RemotePort, IdlePoll = o.IdlePoll, ExpirySweepInterval = o.ExpirySweepInterval, BounceDomain = null, ConfigRefreshInterval = interval };

    private static RelayRouteRecord Relay(string name, int port, string tlsMode, string domain = "dest.example") =>
        new(Ids.New(), name, "mx.dest.example", port, tlsMode, null, null, 10, true, [domain]);

    /// <summary>A delivery that has no route is held (queued without an attempt, due in the future) and leaves no event.</summary>
    private static async Task WaitUntilHeldAsync(DeliveryFixture f) =>
        await DeliveryFixture.WaitAsync(() => f.Storage.Deliveries.GetQueueStatsAsync(default).AsTask().Result is { Queued: 1, Leased: 0 } s && s.OldestDueAt > DateTimeOffset.UtcNow);

    /// <summary>Reloads on request, twice: the second reload certainly began after the change even if the first was already running when the change was made.</summary>
    private static async Task RequestReloadAsync(DeliveryFixture f)
    {
        for (int i = 0; i < 2; i++)
        {
            long before = f.Engine.ConfigRefreshCount;
            f.Engine.RequestConfigRefresh();
            await DeliveryFixture.WaitAsync(() => f.Engine.ConfigRefreshCount > before);
        }
    }

    /// <summary>Waits until the engine completed a reload that began after the change: one that was running when the change was made may have read the old data.</summary>
    private static async Task WaitForReloadAsync(DeliveryFixture f, long before) =>
        await DeliveryFixture.WaitAsync(() => f.Engine.ConfigRefreshCount >= before + 2);

    [Fact]
    public async Task A_relay_added_or_removed_while_the_engine_runs_is_used_after_the_next_refresh()
    {
        await using var f = new DeliveryFixture(o => Refresh(o, TimeSpan.FromMilliseconds(50)));
        f.Services.Routes.DirectMxAvailable = false; // so that the relay is the only way out, and a missing relay leaves the mail waiting

        long before = f.Engine.ConfigRefreshCount;
        await f.Storage.Config.UpsertRelayRouteAsync(Relay("backup", f.Port, "none"), default);
        await WaitForReloadAsync(f, before); // the interval alone, no request

        var id = await f.EnqueueAsync(["rcpt@dest.example"]);
        var events = await f.WaitForEventAsync(id, MessageEventType.Delivered);
        Assert.Equal("backup", events.Single(e => e.Type == MessageEventType.Delivered).Route);
        Assert.Single(f.Remote.Messages);

        before = f.Engine.ConfigRefreshCount;
        foreach (var r in await f.Storage.Config.GetRelayRoutesAsync(default))
        {
            await f.Storage.Config.DeleteRelayRouteAsync(r.Id, default);
        }

        await WaitForReloadAsync(f, before);
        await f.EnqueueAsync(["other@dest.example"]);
        await WaitUntilHeldAsync(f);
        Assert.Single(f.Remote.Messages); // held: no route, nothing sent
    }

    [Fact]
    public async Task A_route_only_serves_the_domains_it_lists_and_a_change_can_be_requested_without_waiting_for_the_interval()
    {
        await using var f = new DeliveryFixture(o => Refresh(o, TimeSpan.FromHours(1)));
        f.Services.Routes.DirectMxAvailable = false;
        await DeliveryFixture.WaitAsync(() => f.Engine.ConfigRefreshCount >= 1); // the first refresh is at start; the next would be an hour later

        await f.Storage.Config.UpsertRelayRouteAsync(Relay("partner-only", f.Port, "none", domain: "partner.example"), default);
        await RequestReloadAsync(f);

        var id = await f.EnqueueAsync(["rcpt@dest.example"]);
        await WaitUntilHeldAsync(f);
        Assert.Empty(f.Remote.Messages);

        await f.Storage.Config.UpsertRelayRouteAsync(Relay("wildcard", f.Port, "none", domain: "*.example"), default);
        await RequestReloadAsync(f);
        var second = await f.EnqueueAsync(["rcpt2@dest.example"]);
        var events = await f.WaitForEventAsync(second, MessageEventType.Delivered);
        Assert.Equal("wildcard", events.Single(e => e.Type == MessageEventType.Delivered).Route);
        Assert.NotEqual(id, second);
    }

    [Fact]
    public async Task A_tls_policy_changes_what_the_next_delivery_requires()
    {
        await using var f = new DeliveryFixture(o => Refresh(o, TimeSpan.FromMilliseconds(50))); // the remote offers no STARTTLS

        var plain = await f.EnqueueAsync(["a@dest.example"]);
        await f.WaitForEventAsync(plain, MessageEventType.Delivered);
        Assert.False(Assert.Single(f.Remote.Messages).Tls);

        long before = f.Engine.ConfigRefreshCount;
        var policy = new TlsPolicyRecord(Ids.New(), "dest.example", TlsLevel.Encrypt);
        await f.Storage.Config.UpsertTlsPolicyAsync(policy, default);
        await WaitForReloadAsync(f, before);
        var refused = await f.EnqueueAsync(["b@dest.example"]);
        var events = await f.WaitForEventAsync(refused, MessageEventType.Deferred);
        Assert.Single(f.Remote.Messages); // nothing was sent in plaintext
        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Delivered);

        before = f.Engine.ConfigRefreshCount;
        await f.Storage.Config.UpsertTlsPolicyAsync(policy with { Level = TlsLevel.May }, default);
        await WaitForReloadAsync(f, before);
        var again = await f.EnqueueAsync(["c@dest.example"]);
        await f.WaitForEventAsync(again, MessageEventType.Delivered);
        Assert.Equal(2, f.Remote.Messages.Count);
    }

    [Fact]
    public async Task A_wildcard_policy_applies_to_every_destination_and_the_most_specific_pattern_wins()
    {
        await using var f = new DeliveryFixture(o => Refresh(o, TimeSpan.FromMilliseconds(50)));
        long before = f.Engine.ConfigRefreshCount;
        await f.Storage.Config.UpsertTlsPolicyAsync(new TlsPolicyRecord(Ids.New(), "*", TlsLevel.Verify), default);
        await f.Storage.Config.UpsertTlsPolicyAsync(new TlsPolicyRecord(Ids.New(), "dest.example", TlsLevel.None), default);
        await WaitForReloadAsync(f, before);

        var id = await f.EnqueueAsync(["a@dest.example"]);
        await f.WaitForEventAsync(id, MessageEventType.Delivered); // "dest.example" beats "*"
        Assert.False(Assert.Single(f.Remote.Messages).Tls);
    }

    [Fact]
    public async Task A_relay_in_required_mode_encrypts_without_checking_the_certificate_and_verify_mode_refuses_an_untrusted_one()
    {
        await using var f = new DeliveryFixture(o => Refresh(o, TimeSpan.FromMilliseconds(50)), serverTls: true); // self-signed certificate
        f.Services.Routes.DirectMxAvailable = false;

        long before = f.Engine.ConfigRefreshCount;
        await f.Storage.Config.UpsertRelayRouteAsync(Relay("verified", f.Port, "verify"), default);
        await WaitForReloadAsync(f, before);
        var refused = await f.EnqueueAsync(["a@dest.example"]);
        var events = await f.WaitForEventAsync(refused, MessageEventType.Deferred);
        Assert.Empty(f.Remote.Messages);
        Assert.DoesNotContain(events, e => e.Type == MessageEventType.Delivered);

        before = f.Engine.ConfigRefreshCount;
        var route = (await f.Storage.Config.GetRelayRoutesAsync(default)).Single();
        await f.Storage.Config.UpsertRelayRouteAsync(route with { TlsMode = "required" }, default);
        await WaitForReloadAsync(f, before);
        var accepted = await f.EnqueueAsync(["b@dest.example"]);
        var delivered = await f.WaitForEventAsync(accepted, MessageEventType.Delivered);
        Assert.True(Assert.Single(f.Remote.Messages).Tls);
        Assert.True(delivered.Single(e => e.Type == MessageEventType.Delivered).Tls!.Used);
    }

    [Fact]
    public async Task A_policy_raised_to_verify_is_not_served_by_an_idle_connection_that_never_validated_the_certificate()
    {
        await using var f = new DeliveryFixture(o => Refresh(o, TimeSpan.FromMilliseconds(50)), serverTls: true); // a self-signed certificate: valid for encrypt, refused by verify

        long before = f.Engine.ConfigRefreshCount;
        var policy = new TlsPolicyRecord(Ids.New(), "dest.example", TlsLevel.Encrypt);
        await f.Storage.Config.UpsertTlsPolicyAsync(policy, default);
        await WaitForReloadAsync(f, before);
        var first = await f.EnqueueAsync(["a@dest.example"]);
        await f.WaitForEventAsync(first, MessageEventType.Delivered);
        Assert.True(Assert.Single(f.Remote.Messages).Tls);
        await DeliveryFixture.WaitAsync(() => f.Services.Pool.IdleConnections == 1); // the encrypt-only connection waits in the pool

        before = f.Engine.ConfigRefreshCount;
        await f.Storage.Config.UpsertTlsPolicyAsync(policy with { Level = TlsLevel.Verify }, default);
        await WaitForReloadAsync(f, before);
        var second = await f.EnqueueAsync(["b@dest.example"]);
        await f.WaitForEventAsync(second, MessageEventType.Deferred);
        Assert.Single(f.Remote.Messages); // nothing went over the unvalidated connection
    }

    /// <summary>Reversible and purpose-bound like Data Protection, without a key ring.</summary>
    private sealed class TestProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => [.. System.Text.Encoding.UTF8.GetBytes(purpose + "|"), .. plaintext.ToArray()];

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose)
        {
            byte[] prefix = System.Text.Encoding.UTF8.GetBytes(purpose + "|");
            if (!protectedData.StartsWith(prefix))
            {
                throw new System.Security.Cryptography.CryptographicException("wrong purpose");
            }

            return protectedData[prefix.Length..].ToArray();
        }
    }

    [Fact]
    public async Task A_relay_logs_in_with_the_protected_password_and_a_rotated_secret_takes_effect_at_once()
    {
        var protector = new TestProtector();
        await using var f = new DeliveryFixture(o => Refresh(o, TimeSpan.FromMilliseconds(50)), serverTls: true, authListener: true, secrets: protector);
        f.Services.Routes.DirectMxAvailable = false;
        f.Remote.Authenticate = (user, password) => user == "relay-user" && password == "s3cret-one";
        RelayRouteRecord Route(string password) => Relay("authed", f.RelayPort, "required") with { UserName = "relay-user", PasswordProtected = protector.Protect(System.Text.Encoding.UTF8.GetBytes(password), SecretPurposes.RelayPassword) };

        long before = f.Engine.ConfigRefreshCount;
        var route = Route("s3cret-one");
        await f.Storage.Config.UpsertRelayRouteAsync(route, default);
        await WaitForReloadAsync(f, before);
        var first = await f.EnqueueAsync(["a@dest.example"]);
        var events = await f.WaitForEventAsync(first, MessageEventType.Delivered);
        Assert.Equal("authed", events.Single(e => e.Type == MessageEventType.Delivered).Route);
        Assert.True(Assert.Single(f.Remote.Messages).Tls);
        await DeliveryFixture.WaitAsync(() => f.Services.Pool.IdleConnections == 1); // the logged-in connection waits in the pool

        // The secret is rotated at the relay and in EggMail: the old connection must not carry the next message, and the new password must be the one used.
        f.Remote.Authenticate = (user, password) => user == "relay-user" && password == "s3cret-two";
        before = f.Engine.ConfigRefreshCount;
        await f.Storage.Config.UpsertRelayRouteAsync(Route("s3cret-two") with { Id = route.Id }, default);
        await WaitForReloadAsync(f, before);
        var second = await f.EnqueueAsync(["b@dest.example"]);
        await f.WaitForEventAsync(second, MessageEventType.Delivered);
        Assert.Equal(2, f.Remote.Messages.Count);

        // A password the relay refuses delivers nothing, even though an authenticated connection with the earlier password is idle.
        before = f.Engine.ConfigRefreshCount;
        await f.Storage.Config.UpsertRelayRouteAsync(Route("wrong") with { Id = route.Id }, default);
        await WaitForReloadAsync(f, before);
        var third = await f.EnqueueAsync(["c@dest.example"]);
        await DeliveryFixture.WaitAsync(() => f.EventsAsync(third).GetAwaiter().GetResult().Any(e => e.Type is MessageEventType.Deferred));
        Assert.Equal(2, f.Remote.Messages.Count);
    }

    [Fact]
    public void A_wildcard_policy_covers_the_subdomains_at_any_depth_and_not_the_domain_itself()
    {
        var table = new TlsPolicyTable(Mta.Tls.OutboundTlsConfiguration.Default);
        table.Update([new TlsPolicyRecord(Ids.New(), "*.bank.example", TlsLevel.Verify)]);
        Assert.Equal(Mta.Tls.TlsSecurityLevel.Verify, table.For("mail.bank.example").Level);
        Assert.Equal(Mta.Tls.TlsSecurityLevel.Verify, table.For("a.b.bank.example").Level);
        Assert.Equal(Mta.Tls.TlsSecurityLevel.May, table.For("bank.example").Level);
        Assert.Equal(Mta.Tls.TlsSecurityLevel.May, table.For("notbank.example").Level);
        table.Update([new TlsPolicyRecord(Ids.New(), "*.bank.example", TlsLevel.Verify), new TlsPolicyRecord(Ids.New(), "bank.example", TlsLevel.Encrypt)]);
        Assert.Equal(Mta.Tls.TlsSecurityLevel.Encrypt, table.For("bank.example").Level);
    }

    [Theory]
    [InlineData("none", SmtpTlsMode.None, false, false)]
    [InlineData("starttls", SmtpTlsMode.StartTls, false, false)]
    [InlineData("required", SmtpTlsMode.StartTls, true, false)]
    [InlineData("VERIFY", SmtpTlsMode.StartTls, true, true)]
    [InlineData("implicit", SmtpTlsMode.Implicit, true, true)]
    [InlineData("unknown", SmtpTlsMode.StartTls, false, false)]
    public void Relay_tls_modes_map_to_the_client_policy(string mode, SmtpTlsMode expectedMode, bool require, bool validates)
    {
        var policy = DeliveryProcessor.RelayTlsPolicy(Relay("r", 587, mode));
        Assert.Equal(expectedMode, policy.Mode);
        Assert.Equal(require, policy.Require);
        Assert.Equal(validates, policy.ValidationCallback is not null);
        if (validates)
        {
            Assert.True(policy.ValidationCallback!(this, null, null, System.Net.Security.SslPolicyErrors.None));
            Assert.False(policy.ValidationCallback!(this, null, null, System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch));
            Assert.False(policy.ValidationCallback!(this, null, null, System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors));
        }
    }
}
