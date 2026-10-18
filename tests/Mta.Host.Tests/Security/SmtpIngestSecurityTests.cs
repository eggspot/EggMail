using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mta.Core;
using Mta.Dsn;
using Mta.Host.Ingest;
using Mta.Host.Security;
using Mta.Host.Submission;
using Mta.Policy;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests.Security;

/// <summary>
/// Security regression tests for the SMTP side of the host (docs/security-test-map.md, RELAY-*, AUTH-*): the real ingest handler behind the real SMTP
/// server over loopback. An unauthenticated sender cannot relay or queue anything, a credential reaches only its own tenant's domains, repeated failures
/// lock out even the right password, and hostile credentials are plain failures. The in-house review, not an independent audit.
/// </summary>
[Collection("CpuHeavy")]
public sealed class SmtpIngestSecurityTests : IAsyncLifetime
{
    private static readonly Guid TenantA = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    private static readonly Guid TenantB = Guid.Parse("b0000000-0000-7000-8000-000000000002");

    private sealed class SelfSigned : IServerCertificateProvider
    {
        private readonly X509Certificate2 _cert;

        public SelfSigned()
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var temp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            _cert = X509CertificateLoader.LoadPkcs12(temp.Export(X509ContentType.Pfx, "x"), "x", X509KeyStorageFlags.Exportable);
        }

        public X509Certificate2? GetCertificate(string? serverName) => _cert;
    }

    private InMemoryStorage _storage = null!;
    private SmtpServer _server = null!;
    private AuthThrottle _throttle = null!;
    private VerpCodec _verp = null!;
    private int _submissionPort;
    private int _bouncePort;

    public async Task InitializeAsync()
    {
        _storage = new InMemoryStorage(new StorageOptions());
        await _storage.InitializeAsync(default);
        var now = DateTimeOffset.UtcNow;
        await _storage.Config.UpsertTenantAsync(new Tenant(TenantA, "Acme", "acme", true, now, false), default);
        await _storage.Config.UpsertTenantAsync(new Tenant(TenantB, "Globex", "globex", true, now, false), default);
        await _storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantA, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await _storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantB, "globex.test", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        await _storage.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantA, "acme-user", PasswordHasher.Hash("s3cret-pass", 2000), true, now), default);
        await _storage.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantA, "acme-disabled", PasswordHasher.Hash("s3cret-pass", 2000), false, now), default);
        await _storage.Config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantB, "globex-user", PasswordHasher.Hash("other-pass", 2000), true, now), default);

        _throttle = new AuthThrottle(maxFailures: 5);
        _verp = new VerpCodec(new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() }, 1);
        var submission = new SubmissionService(_storage, SystemClock.Instance, new SenderPolicy(), new StorageOptions(), new SubmissionOptions { MessageIdDomain = "egg.test" });
        var bounces = new BounceProcessor(_verp, _storage.Config, _storage.Stats, new StorageWebhookPublisher(_storage), SystemClock.Instance);
        var handler = new IngestHandler(_storage, submission, _throttle, new IngestOptions { BounceDomain = "bounces.egg.test" }, bounces);
        _server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "egg.test",
            Certificates = new SelfSigned(),
            AuthFailureDelay = TimeSpan.Zero,
            Listeners =
            [
                new SmtpListenerOptions { Name = "submission", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.StartTls, AuthRequired = true },
                new SmtpListenerOptions { Name = "implicit", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Implicit, AuthRequired = true },
                new SmtpListenerOptions { Name = "bounce", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = ListenerRole.Bounce },
            ],
        }, handler);
        _server.Start();
        _submissionPort = _server.LocalEndPoints["submission"].Port;
        _bouncePort = _server.LocalEndPoints["bounce"].Port;
    }

    public async Task DisposeAsync()
    {
        await _server.DisposeAsync();
        await _storage.DisposeAsync();
    }

    /// <summary>A bare SMTP conversation (the bytes are ours to choose, which a client library would not let us).</summary>
    private sealed class Conversation : IDisposable
    {
        private readonly TcpClient _tcp = new();
        private Stream _stream = null!;
        private readonly StringBuilder _buffer = new();

        public static async Task<Conversation> OpenAsync(int port, bool startTls)
        {
            var c = new Conversation();
            await c._tcp.ConnectAsync(IPAddress.Loopback, port);
            c._stream = c._tcp.GetStream();
            await c.ExpectAsync("220");
            await c.SayAsync("EHLO client.test", "250");
            if (startTls)
            {
                await c.SayAsync("STARTTLS", "220");
                var ssl = new SslStream(c._stream, false, (_, _, _, _) => true);
                await ssl.AuthenticateAsClientAsync("localhost");
                c._stream = ssl;
                await c.SayAsync("EHLO client.test", "250");
            }

            return c;
        }

        public async Task<string> ReadReplyAsync()
        {
            byte[] buf = new byte[4096];
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            while (true)
            {
                string text = _buffer.ToString();
                int end = text.IndexOf("\r\n", StringComparison.Ordinal);
                while (end >= 0)
                {
                    string line = text[..end];
                    if (line.Length >= 4 && line[3] == ' ')
                    {
                        _buffer.Remove(0, end + 2);
                        return line;
                    }

                    if (line.Length < 4) { _buffer.Remove(0, end + 2); return line; }
                    _buffer.Remove(0, end + 2);
                    text = _buffer.ToString();
                    end = text.IndexOf("\r\n", StringComparison.Ordinal);
                }

                int n = await _stream.ReadAsync(buf, cts.Token);
                if (n == 0) { return ""; }
                _buffer.Append(Encoding.UTF8.GetString(buf, 0, n));
            }
        }

        public async Task ExpectAsync(string code)
        {
            string reply = await ReadReplyAsync();
            Assert.StartsWith(code, reply, StringComparison.Ordinal);
        }

        public async Task<string> SayAsync(string line, string? expect = null)
        {
            await _stream.WriteAsync(Encoding.UTF8.GetBytes(line + "\r\n"));
            string reply = await ReadReplyAsync();
            if (expect is not null) { Assert.StartsWith(expect, reply, StringComparison.Ordinal); }
            return reply;
        }

        public async Task<string> SayRawAsync(byte[] bytes)
        {
            await _stream.WriteAsync(bytes);
            return await ReadReplyAsync();
        }

        public void Dispose() => _tcp.Dispose();
    }

    private static string Plain(string user, string password) => Convert.ToBase64String(Encoding.UTF8.GetBytes($"\0{user}\0{password}"));

    private static async Task<int> CountQueuedAsync(IStorage storage) =>
        (await storage.Deliveries.ClaimAsync("t", 100, DateTimeOffset.UtcNow.AddMinutes(1), TimeSpan.FromMinutes(1), default)).Count;

    // Open relay

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Without_authentication_no_sender_can_start_a_transaction_on_a_submission_listener_not_even_from_a_domain_of_the_server(bool startTls)
    {
        using var c = await Conversation.OpenAsync(_submissionPort, startTls);

        // The sender is a registered, verified domain of a tenant; the recipient is anybody. Nothing is accepted and nothing is queued.
        await c.SayAsync("MAIL FROM:<boss@example.org>", "530");
        await c.SayAsync("RCPT TO:<victim@elsewhere.example>", "503");
        await c.SayAsync("DATA", "503");
        await c.SayAsync("MAIL FROM:<>", "530");
        await c.SayAsync("MAIL FROM:<postmaster@egg.test>", "530");
        await c.SayAsync("MAIL FROM:<x@bounces.egg.test>", "530");

        Assert.Equal(0, await CountQueuedAsync(_storage));
    }

    [Fact]
    public async Task The_bounce_listener_takes_mail_from_anybody_but_only_for_a_signed_bounce_address_and_never_queues_it_for_delivery()
    {
        // Every kind of recipient that is not a valid bounce token is refused at RCPT: no relay to a third party, none to a tenant's mailbox.
        // (One connection each: a session that collects errors is closed after a few, which is its own defence.)
        foreach (string recipient in new[]
        {
            "victim@elsewhere.example", "boss@example.org", "postmaster@example.org", "abuse@example.org", "user@bounces.egg.test", "bounce+AAAA@bounces.egg.test",
            "x@bounces.egg.test.evil.example", "\"a@b\"@bounces.egg.test", "VERP-FORGED@bounces.egg.test", new string('a', 60) + "@bounces.egg.test",
        })
        {
            using var each = await Conversation.OpenAsync(_bouncePort, startTls: false);
            await each.SayAsync("MAIL FROM:<mailer-daemon@remote.example>", "250");
            string reply = await each.SayAsync($"RCPT TO:<{recipient}>");
            Assert.StartsWith("550", reply, StringComparison.Ordinal);
        }

        Assert.Equal(0, await CountQueuedAsync(_storage));
        using var c = await Conversation.OpenAsync(_bouncePort, startTls: false);

        // A real token at the shared bounce domain is accepted at RCPT, and a message to it is processed as a report: still nothing is queued for delivery.
        string token = _verp.CreateAddress(TenantA, Ids.New(), "bounces.egg.test", DateTimeOffset.UtcNow);
        await c.SayAsync("MAIL FROM:<mailer-daemon@remote.example>", "250");
        await c.SayAsync($"RCPT TO:<{token}>", "250");
        await c.SayAsync("DATA", "354");
        await c.SayAsync("Subject: whatever\r\n\r\nnot a report\r\n.");
        Assert.Equal(0, await CountQueuedAsync(_storage));
    }

    [Fact]
    public async Task A_credential_reaches_only_the_domains_of_its_own_tenant_by_envelope_and_by_header()
    {
        using var c = await Conversation.OpenAsync(_submissionPort, startTls: true);
        await c.SayAsync("AUTH PLAIN " + Plain("acme-user", "s3cret-pass"), "235");

        // Envelope sender at another tenant's verified domain, in other spellings of it, and at look-alikes. (A subdomain of the tenant's own domain is allowed by design, decision 47.)
        foreach (string from in new[] { "boss@globex.test", "BOSS@GLOBEX.TEST", "boss@globex.test.", "boss@example.org.evil.test", "\"boss@example.org\"@globex.test", "boss@xn--example-9d0b.org" })
        {
            string reply = await c.SayAsync($"MAIL FROM:<{from}>");
            if (reply.StartsWith("250", StringComparison.Ordinal))
            {
                reply = await c.SayAsync("RCPT TO:<rcpt@dest.example>");
                reply = await c.SayAsync("DATA");
                if (reply.StartsWith("354", StringComparison.Ordinal))
                {
                    reply = await c.SayAsync($"From: {from}\r\nTo: rcpt@dest.example\r\nSubject: s\r\n\r\nbody\r\n.");
                }
            }

            Assert.False(reply.StartsWith("250", StringComparison.Ordinal), $"{from}: {reply}");
            await c.SayAsync("RSET");
        }

        // The header From is held to the same rule: the envelope is ours, the header is another tenant's.
        await c.SayAsync("MAIL FROM:<boss@example.org>", "250");
        await c.SayAsync("RCPT TO:<rcpt@dest.example>", "250");
        await c.SayAsync("DATA", "354");
        string spoofed = await c.SayAsync("From: CEO <ceo@globex.test>\r\nTo: rcpt@dest.example\r\nSubject: s\r\n\r\nbody\r\n.");
        Assert.False(spoofed.StartsWith("250", StringComparison.Ordinal), spoofed);
        Assert.Equal(0, await CountQueuedAsync(_storage));
    }

    // Authentication

    [Fact]
    public async Task Repeated_failures_lock_the_account_out_even_for_the_right_password_and_the_other_account_is_unaffected()
    {
        using (var attacker = await Conversation.OpenAsync(_submissionPort, startTls: true))
        {
            for (int i = 0; i < 5; i++)
            {
                string reply = await attacker.SayAsync("AUTH PLAIN " + Plain("acme-user", "guess-" + i));
                if (reply.StartsWith("454", StringComparison.Ordinal)) { break; }
                Assert.StartsWith("535", reply, StringComparison.Ordinal);
            }
        }

        using var legitimate = await Conversation.OpenAsync(_submissionPort, startTls: true);
        string locked = await legitimate.SayAsync("AUTH PLAIN " + Plain("acme-user", "s3cret-pass"));
        Assert.StartsWith("454", locked, StringComparison.Ordinal);
        Assert.Equal(0, await CountQueuedAsync(_storage));
    }

    [Fact]
    public async Task A_wrong_password_an_unknown_user_a_disabled_credential_and_a_suspended_tenant_look_alike()
    {
        await _storage.Config.UpsertTenantAsync(new Tenant(TenantB, "Globex", "globex", false, DateTimeOffset.UtcNow, false), default);
        var replies = new List<string>();
        foreach (var (user, password) in new[] { ("acme-user", "wrong"), ("nobody", "wrong"), ("acme-disabled", "s3cret-pass"), ("globex-user", "other-pass") })
        {
            using var c = await Conversation.OpenAsync(_submissionPort, startTls: true);
            replies.Add(await c.SayAsync("AUTH PLAIN " + Plain(user, password)));
        }

        Assert.All(replies, r => Assert.StartsWith("535", r, StringComparison.Ordinal));
        Assert.Single(replies.Distinct());   // the same words: nothing tells which part was wrong
    }

    [Theory]
    [InlineData("\0")]
    [InlineData("a\0b")]
    [InlineData("\u0001")]
    [InlineData("é")]
    [InlineData("'; DROP TABLE smtp_credentials; --")]
    public async Task A_hostile_user_name_or_password_is_a_failed_login_and_not_an_error_or_a_crash(string hostile)
    {
        foreach (string[] pair in new string[][] { [hostile, "x"], ["acme-user", hostile] })
        {
            using var c = await Conversation.OpenAsync(_submissionPort, startTls: true);
            await c.SayAsync("AUTH LOGIN", "334");
            await c.SayAsync(Convert.ToBase64String(Encoding.UTF8.GetBytes(pair[0])), "334");
            string reply = await c.SayAsync(Convert.ToBase64String(Encoding.UTF8.GetBytes(pair[1])));
            Assert.StartsWith("535", reply, StringComparison.Ordinal);
        }

        using var again = await Conversation.OpenAsync(_submissionPort, startTls: true);
        await again.SayAsync("AUTH PLAIN " + Plain("acme-user", "s3cret-pass"), "235");   // the server is still there and the data intact
    }

    [Fact]
    public async Task The_lockout_is_the_one_budget_of_the_dashboard_sign_in_and_SMTP_for_an_account()
    {
        // Failures through SMTP count against the same key the API sign-in checks (decision 82): the throttle object is the shared one.
        using (var c = await Conversation.OpenAsync(_submissionPort, startTls: true))
        {
            for (int i = 0; i < 5; i++)
            {
                string reply = await c.SayAsync("AUTH PLAIN " + Plain("acme-user", "guess-" + i));
                if (reply.StartsWith("454", StringComparison.Ordinal)) { break; }
            }
        }

        var check = await _throttle.CheckAsync(default, "203.0.113.5", "user:acme-user");
        Assert.True(check.IsLockedOut, "the account is locked for sign-in from other addresses too");
    }

    [Fact]
    public async Task Credentials_are_never_accepted_before_TLS_on_a_submission_listener_and_the_connection_survives_the_attempt()
    {
        using var c = await Conversation.OpenAsync(_submissionPort, startTls: false);

        string reply = await c.SayAsync("AUTH PLAIN " + Plain("acme-user", "s3cret-pass"));

        Assert.StartsWith("538", reply, StringComparison.Ordinal);
        await c.SayAsync("STARTTLS", "220");   // the session can still upgrade
    }

    [Fact]
    public async Task A_message_over_the_size_limit_or_with_too_many_recipients_is_refused_without_queueing_anything()
    {
        using var c = await Conversation.OpenAsync(_submissionPort, startTls: true);
        await c.SayAsync("AUTH PLAIN " + Plain("acme-user", "s3cret-pass"), "235");
        await c.SayAsync("MAIL FROM:<boss@example.org> SIZE=999999999999", "552");
        await c.SayAsync("RSET", "250");
        await c.SayAsync("MAIL FROM:<boss@example.org>", "250");
        string last = "";
        for (int i = 0; i < 120; i++)
        {
            last = await c.SayAsync($"RCPT TO:<r{i}@dest.example>");
            if (!last.StartsWith("250", StringComparison.Ordinal)) { break; }
        }

        Assert.StartsWith("4", last, StringComparison.Ordinal);   // the recipient limit answers with a temporary refusal
        Assert.Equal(0, await CountQueuedAsync(_storage));
    }
}
