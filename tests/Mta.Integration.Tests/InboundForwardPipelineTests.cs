using System.Net;
using System.Security.Cryptography;
using System.Text;
using MimeKit;
using MimeKit.Cryptography;
using Mta.Core;
using Mta.Dkim;
using MkVerifier = MimeKit.Cryptography.DkimVerifier;
using Mta.Dns;
using Mta.Dsn;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Sqlite;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Mta.Integration.Tests;

/// <summary>
/// A forward of received mail through the whole runtime (route action runner, forward intake, delivery engine, SMTP client) to a fake receiving MTA, checked by MimeKit as an independent verifier:
/// the original DKIM signature still verifies, our signature is the route domain's, the ARC set validates, the envelope is SRS0 and the body is the original byte for byte.
/// </summary>
[Collection("Runtime")]
public sealed class InboundForwardPipelineTests : IAsyncLifetime
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private static readonly FormatOptions Wire = CreateWire();

    private readonly string _dir = Directory.CreateTempSubdirectory("eggmail-fwd-").FullName;
    private readonly FakeInternet _internet = new();
    private readonly CancellationTokenSource _stop = new();
    private SmtpServer _remote = null!;
    private EggMailRuntime _runtime = null!;
    private StaticDnsResolver _dns = null!;
    private Task _engine = Task.CompletedTask;
    private RSA _routeKey = null!;
    private RSA _senderKey = null!;
    private Guid _domainId;
    private InboundRouteRecord _route = null!;

    private static FormatOptions CreateWire()
    {
        var o = FormatOptions.Default.Clone();
        o.NewLineFormat = NewLineFormat.Dos;
        return o;
    }

    public async Task InitializeAsync()
    {
        _remote = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.dest.example",
            Listeners = [new SmtpListenerOptions { Name = "mx", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce }],
        }, _internet);
        _remote.Start();
        int remotePort = _remote.LocalEndPoints["mx"].Port;

        _dns = new StaticDnsResolver();
        _dns.AddMx("dest.example", 10, "mx.dest.example").AddA("mx.dest.example", "127.0.0.1");

        var config = new MtaConfig
        {
            Hostname = "egg.test",
            Storage = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = _dir } },
            Smtp = new SmtpSection { Listeners = new Dictionary<string, ListenerSection> { ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.StartTls, AuthRequired = true } } },
            Inbound = new InboundSection { Enabled = true },
            Delivery = new DeliverySection { BounceDomain = "bounces.egg.test", RemotePort = remotePort, AllowPrivateMxAddresses = true, PollInterval = TimeSpan.FromMilliseconds(30) },
        };
        var storage = SqliteStorage.Create(config.Storage);
        await storage.InitializeAsync(default);
        _runtime = await EggMailRuntime.CreateAsync(config, storage, SystemClock.Instance, NullMtaLog.Instance, default, _dns);

        var now = DateTimeOffset.UtcNow;
        _domainId = Ids.New();
        _routeKey = DkimKeyTools.GenerateRsa2048();
        _senderKey = DkimKeyTools.GenerateRsa2048();
        await storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
        await storage.Config.UpsertDomainAsync(new DomainRecord(_domainId, TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await storage.Config.AddDkimKeyAsync(new Mta.Storage.DkimKeyRecord(
            Ids.New(), _domainId, "egg1", _runtime.Secrets.Protect(_routeKey.ExportPkcs8PrivateKey(), SecretPurposes.DkimKey), DkimKeyTools.ExportPublicKeyBase64(_routeKey), now, true, null), default);
        _dns.AddTxt("egg1._domainkey.example.org", DkimKeyTools.FormatDnsTxtValue(_routeKey));
        _dns.AddTxt("sel._domainkey.sender.test", DkimKeyTools.FormatDnsTxtValue(_senderKey));

        await storage.Inbound.UpsertSettingsAsync(new InboundDomainSettings(_domainId, TenantId, true, InboundDmarcAction.RecordOnly, null, null, null, null, null, now), default);
        _route = new InboundRouteRecord(Ids.New(), TenantId, _domainId, "fwd", 10, true, InboundMatchKind.CatchAll, null, false, InboundActionKind.Forward, null, InboundWebhookFormat.Json, ["rcpt@dest.example"], now, now);
        await storage.Inbound.UpsertRouteAsync(_route, default);
        _engine = Task.Run(() => _runtime.Delivery.RunAsync(_stop.Token));
    }

    public async Task DisposeAsync()
    {
        await _stop.CancelAsync();
        try { await _engine; } catch (OperationCanceledException) { }
        await _remote.DisposeAsync();
        await _runtime.DisposeAsync();
        await _runtime.Storage.DisposeAsync();
        _routeKey.Dispose();
        _senderKey.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    private sealed class Locator(Dictionary<string, RSA> keys) : DkimPublicKeyLocatorBase
    {
        public override AsymmetricKeyParameter LocatePublicKey(string methods, string domain, string selector, CancellationToken cancellationToken = default) =>
            PublicKeyFactory.CreateKey(keys[domain].ExportSubjectPublicKeyInfo());

        public override Task<AsymmetricKeyParameter> LocatePublicKeyAsync(string methods, string domain, string selector, CancellationToken cancellationToken = default) =>
            Task.FromResult(LocatePublicKey(methods, domain, selector, cancellationToken));
    }

    private Locator KeyLocator() => new(new Dictionary<string, RSA>(StringComparer.OrdinalIgnoreCase) { ["example.org"] = _routeKey, ["sender.test"] = _senderKey });

    /// <summary>A message from sender.test, DKIM-signed by sender.test (the fixture only; MimeKit does the verifying), as the receive path would store it.</summary>
    private byte[] SignedByTheSender(string body, string? extraHeader = null)
    {
        string message = "From: Alice <alice@sender.test>\r\nTo: support@example.org\r\nSubject: Hello\r\nDate: Fri, 16 Oct 2026 07:00:00 +0000\r\nMessage-ID: <orig1@sender.test>\r\n"
            + (extraHeader is null ? string.Empty : extraHeader + "\r\n")
            + "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + body;
        using var signer = Mta.Dkim.DkimSigner.FromPem(new DkimSignerOptions { Domain = "sender.test", Selector = "sel" }, _senderKey.ExportPkcs8PrivateKeyPem());
        byte[] signature = Encoding.UTF8.GetBytes(signer.Sign(Encoding.UTF8.GetBytes(message)));
        return [.. Encoding.ASCII.GetBytes("Received: from mail.sender.test by egg.test; Fri, 16 Oct 2026 07:00:01 +0000\r\n"), .. signature, .. Encoding.UTF8.GetBytes(message)];
    }

    private async Task<InboundMessageDraft> ReceiveAsync(byte[] raw, string from = "alice@sender.test")
    {
        DateTimeOffset at = DateTimeOffset.UtcNow;
        var draft = new InboundMessageDraft
        {
            Id = Ids.New(at), TenantId = TenantId, DomainId = _domainId, Domain = "example.org", ReceivedAt = at, RemoteAddress = "203.0.113.9", Helo = "mail.sender.test", TlsUsed = true,
            EnvelopeFrom = from, EnvelopeTo = "support@example.org", Subject = "Grüße",
            Auth = new InboundAuthResults(InboundVerdict.Pass, "sender.test", InboundVerdict.None, InboundVerdict.Pass, "sender.test", InboundVerdict.Pass, "none", InboundVerdict.None),
            RouteId = _route.Id, ActionKind = InboundActionKind.Forward, Raw = raw,
        };
        await _runtime.Storage.Inbound.AcceptAsync([draft], default);
        return draft;
    }

    private async Task RunActionsUntilAsync(Guid id, InboundActionState state)
    {
        var until = DateTime.UtcNow.AddSeconds(60);
        while ((await _runtime.Storage.Inbound.GetAsync(TenantId, id, default))!.ActionState != state)
        {
            await _runtime.InboundActions.RunOnceAsync(default);
            if (DateTime.UtcNow > until)
            {
                throw new TimeoutException();
            }

            await Task.Delay(20);
        }
    }

    private async Task WaitForMailAsync(int count)
    {
        var until = DateTime.UtcNow.AddSeconds(60);
        while (true)
        {
            lock (_internet.Received)
            {
                if (_internet.Received.Count >= count)
                {
                    return;
                }
            }

            if (DateTime.UtcNow > until)
            {
                throw new TimeoutException();
            }

            await Task.Delay(25);
        }
    }

    private static MimeMessage Load(byte[] raw)
    {
        using var ms = new MemoryStream(raw);
        return MimeMessage.Load(ms);
    }

    [Fact]
    public async Task A_forward_arrives_with_a_srs_envelope_a_valid_original_signature_the_route_domains_signature_a_valid_arc_set_and_the_original_bytes()
    {
        byte[] original = SignedByTheSender("Grüße aus München\r\n" + new string('x', 900) + "\r\nlast line\r\n");
        MimeMessage before = Load(original);
        Assert.True(new MkVerifier(KeyLocator()).Verify(Wire, before, before.Headers.First(h => h.Id == HeaderId.DkimSignature)), "the original verifies before it is forwarded");
        InboundMessageDraft draft = await ReceiveAsync(original);

        await RunActionsUntilAsync(draft.Id, InboundActionState.Done);
        await WaitForMailAsync(1);

        FakeInternet.Mail mail = _internet.Received.Single();
        Assert.Equal(["rcpt@dest.example"], mail.Recipients);
        // Envelope: SRS0 at the route's domain, not a bounce address, and it verifies with the ring (so a bounce to it is recognized and dropped).
        Assert.EndsWith("@example.org", mail.Sender);
        Assert.StartsWith("SRS0=", mail.Sender, StringComparison.Ordinal);
        Assert.True(new SrsCodec(_runtime.Verp).TryVerify(mail.Sender[..mail.Sender.IndexOf('@')], DateTimeOffset.UtcNow));

        // The body and every original header are there byte for byte: headers were only added on top.
        string delivered = Encoding.UTF8.GetString(mail.Body);
        Assert.EndsWith(Encoding.UTF8.GetString(original), delivered, StringComparison.Ordinal);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(delivered, "(?im)^X-EggMail-Hops: 1; "));

        // MimeKit, not our own code, verifies the signatures and the chain.
        MimeMessage parsed = Load(mail.Body);
        var verifier = new MkVerifier(KeyLocator());
        var sigHeaders = parsed.Headers.Where(h => h.Id == HeaderId.DkimSignature).ToList();
        Assert.Equal(2, sigHeaders.Count);
        Header ours = sigHeaders[0];
        Header theirs = sigHeaders[1];
        Assert.Contains("d=example.org", ours.Value, StringComparison.Ordinal);
        Assert.Contains("d=sender.test", theirs.Value, StringComparison.Ordinal);
        Assert.True(verifier.Verify(Wire, parsed, ours), "our signature");
        Assert.True(verifier.Verify(Wire, parsed, theirs), "the sender's original signature");

        ArcValidationResult arc = new ArcVerifier(KeyLocator()).Verify(Wire, parsed);
        Assert.Equal(ArcSignatureValidationResult.Pass, arc.Chain);
        Assert.Contains("i=1", delivered[..delivered.IndexOf("Received:", StringComparison.Ordinal)], StringComparison.Ordinal);
        Assert.Contains("cv=none", delivered, StringComparison.Ordinal);

        InboundMessage stored = (await _runtime.Storage.Inbound.GetAsync(TenantId, draft.Id, default))!;
        Assert.NotNull(stored.ForwardMessageId);
        Assert.False(stored.HasRaw);
    }

    /// <summary>The message as an earlier hop (relay.test) left it: sealed with an ARC set of its own key, published in the fake DNS.</summary>
    private byte[] SealedByAnEarlierHop(byte[] message, RSA relayKey)
    {
        using var sealer = new Mta.Auth.Arc.ArcSealer(new Mta.Auth.Arc.ArcSealerOptions { Domain = "relay.test", Selector = "s1" }, relayKey);
        Mta.Auth.Arc.ArcSealResult sealedHop = sealer.Seal(message, "relay.test; spf=pass smtp.mailfrom=sender.test; dkim=pass header.d=sender.test", new Mta.Auth.Arc.ArcChainResult(Mta.Auth.Arc.ArcChainStatus.None, "no chain"));
        Assert.True(sealedHop.IsSealed);
        return [.. sealedHop.HeaderBytes.ToArray(), .. message];
    }

    private string TopArcSeal(byte[] mail)
    {
        string text = Encoding.UTF8.GetString(mail);
        int at = text.IndexOf("ARC-Seal:", StringComparison.Ordinal);
        return text[at..text.IndexOf("\r\n", at, StringComparison.Ordinal)];
    }

    [Fact]
    public async Task A_valid_arc_chain_is_continued_with_cv_pass_and_a_broken_one_is_sealed_cv_fail()
    {
        using RSA relayKey = DkimKeyTools.GenerateRsa2048();
        _dns.AddTxt("s1._domainkey.relay.test", DkimKeyTools.FormatDnsTxtValue(relayKey));
        var locator = new Locator(new Dictionary<string, RSA>(StringComparer.OrdinalIgnoreCase) { ["example.org"] = _routeKey, ["sender.test"] = _senderKey, ["relay.test"] = relayKey });

        // Valid chain: ours is instance 2, cv=pass, and MimeKit validates the two sets.
        byte[] chained = SealedByAnEarlierHop(SignedByTheSender("through a relay\r\n"), relayKey);
        InboundMessageDraft good = await ReceiveAsync(chained);
        await RunActionsUntilAsync(good.Id, InboundActionState.Done);
        await WaitForMailAsync(1);
        byte[] delivered;
        lock (_internet.Received) { delivered = _internet.Received[0].Body; }
        string seal = TopArcSeal(delivered);
        Assert.Contains("i=2", seal, StringComparison.Ordinal);
        Assert.Contains("cv=pass", seal, StringComparison.Ordinal);
        Assert.Equal(Mta.Auth.Arc.ArcChainStatus.Pass, (await new Mta.Auth.Arc.ArcValidator(_dns).ValidateAsync(delivered)).Status);
        Assert.Equal(ArcSignatureValidationResult.Pass, new ArcVerifier(locator).Verify(Wire, Load(delivered)).Chain);

        // Broken chain (the earlier hop's signature no longer matches): the new seal says cv=fail and vouches for nothing.
        byte[] broken = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(SealedByAnEarlierHop(SignedByTheSender("through a relay\r\n"), relayKey)).Replace("through a relay", "through a RELAY", StringComparison.Ordinal));
        InboundMessageDraft bad = await ReceiveAsync(broken);
        await RunActionsUntilAsync(bad.Id, InboundActionState.Done);
        await WaitForMailAsync(2);
        byte[] deliveredBad;
        lock (_internet.Received) { deliveredBad = _internet.Received[1].Body; }
        string failSeal = TopArcSeal(deliveredBad);
        Assert.Contains("i=2", failSeal, StringComparison.Ordinal);
        Assert.Contains("cv=fail", failSeal, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_forwarded_message_is_not_forwarded_again_after_three_hops_and_a_forged_marker_does_not_count()
    {
        var hops = new ForwardHopMarker(_runtime.Verp);
        byte[] plain = SignedByTheSender("loop body\r\n");

        // Three honest hops: the fourth is refused.
        byte[] threeTimes = hops.Apply(plain, 3);
        InboundMessageDraft stopped = await ReceiveAsync(threeTimes);
        await RunActionsUntilAsync(stopped.Id, InboundActionState.Failed);
        Assert.Equal("loop_detected", (await _runtime.Storage.Inbound.GetAsync(TenantId, stopped.Id, default))!.ActionLastError);
        Assert.Empty(_internet.Received);

        // A forged count of 3 is not a count (the receive path would have removed it; the forwarder ignores it as well).
        string forged = "X-EggMail-Hops: 3; 0123456789abcdef\r\n";
        InboundMessageDraft allowed = await ReceiveAsync([.. Encoding.ASCII.GetBytes(forged), .. plain]);
        await RunActionsUntilAsync(allowed.Id, InboundActionState.Done);
        await WaitForMailAsync(1);
        string text = Encoding.UTF8.GetString(_internet.Received.Single().Body);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(text, "(?im)^X-EggMail-Hops:"));
        Assert.Contains("X-EggMail-Hops: 1; ", text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("victim.test", false)]    // a domain of another tenant that holds a DKIM key here
    [InlineData("sibling.test", true)]    // another domain of the same tenant that holds a DKIM key here
    public async Task A_spoofed_from_of_a_domain_that_also_holds_a_dkim_key_here_is_never_signed_with_that_domain(string fromDomain, bool sameTenant)
    {
        // The review's probes P1 and P1b: the copy is signed (DKIM, and the ARC set) by the route's domain only, whoever the From says it is and whichever keys the server holds.
        Guid tenant = sameTenant ? TenantId : Guid.Parse("a0000000-0000-7000-8000-000000000002");
        var now = DateTimeOffset.UtcNow;
        if (!sameTenant)
        {
            await _runtime.Storage.Config.UpsertTenantAsync(new Tenant(tenant, "Globex", "globex", true, now, false), default);
        }

        Guid otherDomain = Ids.New();
        using RSA otherKey = DkimKeyTools.GenerateRsa2048();
        await _runtime.Storage.Config.UpsertDomainAsync(new DomainRecord(otherDomain, tenant, fromDomain, DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await _runtime.Storage.Config.AddDkimKeyAsync(new Mta.Storage.DkimKeyRecord(
            Ids.New(), otherDomain, "k1", _runtime.Secrets.Protect(otherKey.ExportPkcs8PrivateKey(), SecretPurposes.DkimKey), DkimKeyTools.ExportPublicKeyBase64(otherKey), now, true, null), default);
        _dns.AddTxt("k1._domainkey." + fromDomain, DkimKeyTools.FormatDnsTxtValue(otherKey));
        byte[] spoof = Encoding.UTF8.GetBytes($"Received: from mail.sender.test by egg.test\r\nFrom: CEO <ceo@{fromDomain}>\r\nTo: support@example.org\r\nSubject: pay now\r\nDate: Fri, 16 Oct 2026 07:00:00 +0000\r\nMessage-ID: <p@x.test>\r\n\r\nplease\r\n");
        InboundMessageDraft draft = await ReceiveAsync(spoof, from: $"ceo@{fromDomain}");

        await RunActionsUntilAsync(draft.Id, InboundActionState.Done);
        await WaitForMailAsync(1);

        FakeInternet.Mail mail = _internet.Received.Single();
        string text = Encoding.UTF8.GetString(mail.Body);
        var ours = System.Text.RegularExpressions.Regex.Matches(text, @"(?im)^(DKIM-Signature|ARC-Seal|ARC-Message-Signature):[^\r\n]*(\r\n[ \t][^\r\n]*)*");
        Assert.Equal(3, ours.Count);   // our DKIM signature and the two signed ARC headers
        foreach (System.Text.RegularExpressions.Match header in ours)
        {
            string flat = System.Text.RegularExpressions.Regex.Replace(header.Value, @"\s+", "");
            Assert.Contains("d=example.org", flat, StringComparison.Ordinal);
            Assert.DoesNotContain(fromDomain, flat, StringComparison.Ordinal);
        }

        Assert.StartsWith("SRS0=", mail.Sender, StringComparison.Ordinal);
        Assert.EndsWith("@example.org", mail.Sender, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_suppressed_target_is_not_mailed_and_when_all_are_the_action_says_so()
    {
        await _runtime.Storage.Config.AddSuppressionAsync(new SuppressionRecord(TenantId, "rcpt@dest.example", SuppressionReason.Manual, null, DateTimeOffset.UtcNow, null), default);
        InboundMessageDraft draft = await ReceiveAsync(SignedByTheSender("body\r\n"));

        await RunActionsUntilAsync(draft.Id, InboundActionState.Done);

        InboundMessage stored = (await _runtime.Storage.Inbound.GetAsync(TenantId, draft.Id, default))!;
        Assert.Equal("all_targets_suppressed", stored.ActionNote);
        Assert.Null(stored.ForwardMessageId);
        Assert.True(stored.HasRaw);
        Assert.Empty(_internet.Received);
    }

    [Fact]
    public async Task A_message_with_the_null_sender_is_forwarded_with_the_null_sender()
    {
        InboundMessageDraft draft = await ReceiveAsync(SignedByTheSender("a bounce\r\n"), from: "");

        await RunActionsUntilAsync(draft.Id, InboundActionState.Done);
        await WaitForMailAsync(1);

        Assert.Equal(string.Empty, _internet.Received.Single().Sender);
    }
}
