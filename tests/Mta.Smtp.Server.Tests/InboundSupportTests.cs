using System.Net;
using System.Text;
using Mta.Core;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Server.Tests;

/// <summary>The server features the inbound receive path relies on: the start-of-DATA hook, a per-transaction size limit, per-listener limits and the role.</summary>
public class InboundSupportTests
{
    private sealed class HookHandler : ISmtpServerHandler
    {
        public Func<SmtpSessionContext, SmtpReply?> OnDataStart { get; set; } = _ => null;
        public Action<SmtpSessionContext, EmailAddress>? OnRcpt { get; set; }
        public List<int> DeliveredSizes { get; } = [];
        public List<SmtpReply> Refused { get; } = [];
        public int DataStarts;
        public List<SmtpSessionContext> Sessions { get; } = [];

        public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken ct) => ValueTask.FromResult<SmtpReply?>(null);

        public ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct) => ValueTask.FromResult(SmtpAuthResult.Failed);

        public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct) => ValueTask.FromResult(SmtpReplies.SenderOk);

        public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters parameters, CancellationToken ct)
        {
            OnRcpt?.Invoke(session, recipient);
            return ValueTask.FromResult(SmtpReplies.RecipientOk);
        }

        public ValueTask<SmtpReply?> OnDataStartAsync(SmtpSessionContext session, MailFromInfo mail, IReadOnlyList<EmailAddress> recipients, CancellationToken ct)
        {
            Interlocked.Increment(ref DataStarts);
            Sessions.Add(session);
            return ValueTask.FromResult(OnDataStart(session));
        }

        public ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
        {
            lock (DeliveredSizes)
            {
                DeliveredSizes.Add((int)message.Size);
            }

            return ValueTask.FromResult(SmtpReply.Create(250, "2.0.0", "Accepted"));
        }

        public void OnMessageRefused(SmtpSessionContext session, SmtpReply reply)
        {
            lock (Refused)
            {
                Refused.Add(reply);
            }
        }

        public void OnDisconnected(SmtpSessionContext session)
        {
        }
    }

    private static (SmtpServer Server, int Port) Start(HookHandler handler, SmtpListenerOptions listener, SmtpServerOptions? options = null)
    {
        var server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.test",
            MaxMessageSize = options?.MaxMessageSize ?? 25L * 1024 * 1024,
            MaxRecipients = options?.MaxRecipients ?? 50,
            Listeners = [listener],
        }, handler);
        server.Start();
        return (server, server.LocalEndPoints[listener.Name].Port);
    }

    private static SmtpListenerOptions Open(long? maxMessageSize = null, int? maxRecipients = null, ListenerRole role = ListenerRole.Inbound) =>
        new() { Name = "open", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.Plain, AuthRequired = false, Role = role, MaxMessageSize = maxMessageSize, MaxRecipients = maxRecipients };

    private static async Task<RawClient> OpenAsync(int port)
    {
        var c = await RawClient.ConnectAsync(port);
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO client.test", 250);
        return c;
    }

    [Fact]
    public async Task A_refusal_from_the_start_of_data_hook_answers_data_at_once_and_ends_the_transaction()
    {
        var handler = new HookHandler { OnDataStart = _ => SmtpReply.Create(451, "4.7.0", "Server busy") };
        var (server, port) = Start(handler, Open());
        await using var _ = server;
        using RawClient c = await OpenAsync(port);
        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<b@example.org>", 250);

        var reply = await c.CommandAsync("DATA", 451);

        Assert.Equal("4.7.0", reply.EnhancedCode);
        await c.CommandAsync("DATA", 503);   // the transaction is over: MAIL FROM again
        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        Assert.Empty(handler.DeliveredSizes);
        Assert.Equal(1, handler.DataStarts);
    }

    [Fact]
    public async Task The_hook_runs_once_per_message_and_lets_it_through_when_it_returns_null()
    {
        var handler = new HookHandler();
        var (server, port) = Start(handler, Open());
        await using var _ = server;
        using RawClient c = await OpenAsync(port);
        for (int i = 0; i < 2; i++)
        {
            await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
            await c.CommandAsync("RCPT TO:<b@example.org>", 250);
            await c.CommandAsync("DATA", 354);
            await c.SendAsync("Subject: s\r\n\r\nbody\r\n.\r\n");
            await c.ExpectAsync(250);
        }

        Assert.Equal(2, handler.DataStarts);
        Assert.Equal(2, handler.DeliveredSizes.Count);
    }

    [Fact]
    public async Task A_refusal_at_the_start_of_a_bdat_sequence_still_consumes_the_chunks_and_answers_the_last_one()
    {
        var handler = new HookHandler { OnDataStart = _ => SmtpReply.Create(451, "4.7.0", "Server busy") };
        var (server, port) = Start(handler, Open());
        await using var _ = server;
        using RawClient c = await OpenAsync(port);
        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<b@example.org>", 250);
        const string chunk = "Subject: s\r\n\r\npart one\r\n";

        await c.SendAsync($"BDAT {chunk.Length}\r\n{chunk}");
        await c.ExpectAsync(451);
        await c.SendAsync($"BDAT {chunk.Length} LAST\r\n{chunk}");
        await c.ExpectAsync(451);

        await c.CommandAsync("NOOP", 250);   // in sync again, nothing was delivered
        Assert.Empty(handler.DeliveredSizes);
        Assert.Empty(handler.Refused);   // a refusal by the handler is not reported back to it
    }

    [Fact]
    public async Task A_size_limit_set_for_the_transaction_is_enforced_while_reading_with_552_and_cleared_afterwards()
    {
        var handler = new HookHandler { OnRcpt = (session, recipient) => session.TransactionMaxMessageSize = recipient.LocalPart == "small" ? 100 : null };
        var (server, port) = Start(handler, Open());
        await using var _ = server;
        using RawClient c = await OpenAsync(port);

        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<small@example.org>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("Subject: s\r\n\r\n" + new string('x', 500) + "\r\n.\r\n");
        var refusal = await c.ExpectAsync(552);
        Assert.Equal("5.3.4", refusal.EnhancedCode);
        Assert.Empty(handler.DeliveredSizes);
        Assert.Equal(552, Assert.Single(handler.Refused).Code);   // the handler can count what it never saw

        // The next transaction is not limited by the previous one.
        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<big@example.org>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("Subject: s\r\n\r\n" + new string('x', 500) + "\r\n.\r\n");
        await c.ExpectAsync(250);
    }

    [Fact]
    public async Task A_listener_limit_is_advertised_as_size_and_applies_to_the_declared_size_and_the_body_and_other_listeners_keep_the_server_default()
    {
        var handler = new HookHandler();
        var (server, port) = Start(handler, Open(maxMessageSize: 2000), new SmtpServerOptions { MaxMessageSize = 1_000_000 });
        await using var _ = server;
        using var c = await RawClient.ConnectAsync(port);
        await c.ExpectAsync(220);
        var ehlo = await c.CommandAsync("EHLO client.test", 250);
        Assert.Contains("SIZE 2000", ehlo.Lines);

        var declared = await SendAsync(c, "MAIL FROM:<a@sender.test> SIZE=5000");
        Assert.Equal(552, declared.Code);

        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<b@example.org>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("Subject: s\r\n\r\n" + new string('x', 3000) + "\r\n.\r\n");
        await c.ExpectAsync(552);
        Assert.Empty(handler.DeliveredSizes);

        // A listener without its own limit advertises the server's.
        var (other, otherPort) = Start(new HookHandler(), Open(), new SmtpServerOptions { MaxMessageSize = 1_000_000 });
        await using var _2 = other;
        using var d = await RawClient.ConnectAsync(otherPort);
        await d.ExpectAsync(220);
        Assert.Contains("SIZE 1000000", (await d.CommandAsync("EHLO client.test", 250)).Lines);
    }

    private static async Task<SmtpReply> SendAsync(RawClient c, string line)
    {
        await c.SendLineAsync(line);
        return (await c.ReadReplyAsync())!;
    }

    [Fact]
    public async Task A_listener_recipient_limit_overrides_the_servers()
    {
        var handler = new HookHandler();
        var (server, port) = Start(handler, Open(maxRecipients: 2), new SmtpServerOptions { MaxRecipients = 50 });
        await using var _ = server;
        using RawClient c = await OpenAsync(port);
        await c.CommandAsync("MAIL FROM:<a@sender.test>", 250);
        await c.CommandAsync("RCPT TO:<a@example.org>", 250);
        await c.CommandAsync("RCPT TO:<b@example.org>", 250);

        var third = await c.CommandAsync("RCPT TO:<c@example.org>", 452);

        Assert.Equal("4.5.3", third.EnhancedCode);
    }

    [Theory]
    [InlineData(ListenerRole.Inbound)]
    [InlineData(ListenerRole.Bounce)]
    public async Task A_port_25_role_offers_no_auth_and_refuses_it_even_on_a_tls_session(ListenerRole role)
    {
        var handler = new HookHandler();
        var server = new SmtpServer(new SmtpServerOptions
        {
            Hostname = "mx.test",
            Certificates = TestCertificates.Instance,
            Listeners = [new SmtpListenerOptions { Name = "open", BindAddress = IPAddress.Loopback, Port = 0, Mode = ListenerMode.StartTls, AuthRequired = false, Role = role }],
        }, handler);
        server.Start();
        await using var _ = server;
        using var c = await RawClient.ConnectAsync(server.LocalEndPoints["open"].Port);
        await c.ExpectAsync(220);
        await c.CommandAsync("EHLO client.test", 250);
        await c.CommandAsync("STARTTLS", 220);
        await c.StartTlsHandshakeAsync();

        var ehlo = await c.CommandAsync("EHLO client.test", 250);

        Assert.DoesNotContain(ehlo.Lines, l => l.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase));
        await c.CommandAsync("AUTH PLAIN " + Convert.ToBase64String(Encoding.ASCII.GetBytes("\0user\0pass")), 502);
    }
}
