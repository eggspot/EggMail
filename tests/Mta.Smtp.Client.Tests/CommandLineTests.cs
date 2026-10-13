using System.Text;
using Mta.Core;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Client.Tests;

/// <summary>The MAIL FROM and RCPT TO lines are written into stack memory; the server must see exactly the addresses and parameters of the envelope.</summary>
public class CommandLineTests
{
    private static byte[] Msg(int bodyBytes = 10) => Encoding.UTF8.GetBytes("From: a@b.example\r\nTo: c@d.example\r\nSubject: t\r\n\r\n" + new string('x', bodyBytes) + "\r\n");

    private static async Task<(RealServer Server, SmtpSendResult Result)> SendAsync(SmtpEnvelope envelope, byte[] message, bool pipelining)
    {
        var server = new RealServer();
        var options = new SmtpClientOptions { HeloName = "client.test", Pipelining = pipelining };
        await using var conn = await SmtpClientConnection.ConnectAsync(server.Target(SmtpTlsPolicy.Disabled), options);
        var result = await conn.SendAsync(envelope, message);
        return (server, result);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Mail_from_carries_the_sender_the_size_and_the_flags(bool pipelining)
    {
        byte[] message = Msg(300);
        var envelope = new SmtpEnvelope(EmailAddress.Parse("Jürgen.Sender+tag@Example.ORG"), [EmailAddress.Parse("réci@dést.example")], SmtpUtf8: true, EightBit: true);
        var (server, result) = await SendAsync(envelope, message, pipelining);
        await using (server)
        {
            Assert.True(result.Delivered, result.FinalReply?.ToString());
            var received = Assert.Single(server.Handler.Messages);
            Assert.Equal("Jürgen.Sender+tag@example.org", received.From.ToString());
            Assert.Equal(["réci@xn--dst-bma.example"], received.To);   // the domain travels in its A-label form
            Assert.Equal(message.Length, received.Parameters.Size);
            Assert.True(received.Parameters.SmtpUtf8);
            Assert.Equal(SmtpBodyType.EightBitMime, received.Parameters.BodyType);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task The_null_reverse_path_is_written_as_empty_brackets_and_plain_mail_has_no_flags(bool pipelining)
    {
        var envelope = new SmtpEnvelope(EmailAddress.Null, [EmailAddress.Parse("a@dest.example"), EmailAddress.Parse("b@dest.example")], false, false);
        var (server, result) = await SendAsync(envelope, Msg(), pipelining);
        await using (server)
        {
            Assert.True(result.Delivered);
            var received = Assert.Single(server.Handler.Messages);
            Assert.True(received.From.IsNull);
            Assert.Equal(["a@dest.example", "b@dest.example"], received.To);
            Assert.False(received.Parameters.SmtpUtf8);
            Assert.Equal(SmtpBodyType.SevenBit, received.Parameters.BodyType);
        }
    }

    [Fact]
    public async Task A_long_address_longer_than_the_first_stack_buffer_is_written_whole()
    {
        string local = new('l', 64);
        string domain = string.Join('.', Enumerable.Repeat(new string('d', 60), 3)) + ".example";   // 64 + 1 + 191 characters per path
        var envelope = new SmtpEnvelope(EmailAddress.Parse(local + "@" + domain), [EmailAddress.Parse(local + "@" + domain)], false, false);
        var (server, result) = await SendAsync(envelope, Msg(), pipelining: true);
        await using (server)
        {
            Assert.True(result.Delivered);
            var received = Assert.Single(server.Handler.Messages);
            Assert.Equal(local + "@" + domain, received.From.ToString());
            Assert.Equal([local + "@" + domain], received.To);
        }
    }

    [Fact]
    public async Task Several_transactions_on_one_connection_each_get_their_own_timeout()
    {
        // The timeout source is shared by all reads of a connection; a second transaction with another cancellation token must not inherit the first one's.
        await using var server = new RealServer();
        var options = new SmtpClientOptions { HeloName = "client.test", CommandTimeout = TimeSpan.FromSeconds(5), EndOfDataTimeout = TimeSpan.FromSeconds(5) };
        await using var conn = await SmtpClientConnection.ConnectAsync(server.Target(SmtpTlsPolicy.Disabled), options);
        for (int i = 0; i < 5; i++)
        {
            using var cts = new CancellationTokenSource();
            var result = await conn.SendAsync(new SmtpEnvelope(EmailAddress.Parse("s@example.org"), [EmailAddress.Parse($"r{i}@dest.example")], false, false), Msg(), cts.Token);
            Assert.True(result.Delivered);
        }

        Assert.Equal(5, server.Handler.Messages.Count);

        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await conn.SendAsync(new SmtpEnvelope(EmailAddress.Parse("s@example.org"), [EmailAddress.Parse("late@dest.example")], false, false), Msg(), cancelled.Token));
    }
}
