using System.Text;
using Mta.Core;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Client.Tests;

/// <summary>
/// Security regression tests (docs/security-test-map.md, SMTP-13): a message a tenant submits can contain anything, including text that looks like the
/// end of the data and the commands of a second message. Whatever the framing (DATA or BDAT, pipelined or not), the receiving server must see exactly
/// one message, with the body unchanged. The in-house review, not an independent audit.
/// </summary>
public class EgressSmugglingTests
{
    private static byte[] Message(string body) => Encoding.UTF8.GetBytes("From: a@b.example\r\nTo: c@d.example\r\nSubject: t\r\n\r\n" + body);

    private static SmtpEnvelope Envelope() => new(EmailAddress.Parse("sender@example.org"), [EmailAddress.Parse("rcpt@dest.example")], false, false);

    public static TheoryData<string> Bodies() => new()
    {
        "first\r\n.\r\nMAIL FROM:<evil@x.test>\r\nRCPT TO:<evil@x.test>\r\nDATA\r\nsmuggled\r\n.\r\nQUIT\r\n",
        ".\r\n",
        "..\r\n",
        "...\r\n.\r\n..\r\n",
        "line\r\n.\r\n",
        "line\r\n.",
        "\r\n.\r\n\r\n.\r\n",
        "BDAT 5\r\nabcde\r\nBDAT 0 LAST\r\n",
        "x\r\n.dot\r\n..dots\r\n.",
    };

    [Theory]
    [MemberData(nameof(Bodies))]
    public async Task A_body_that_looks_like_the_end_of_data_arrives_as_one_unchanged_message_in_every_framing(string body)
    {
        foreach (var (pipelining, chunking) in new[] { (false, false), (true, false), (true, true), (false, true) })
        {
            await using var server = new RealServer();
            var options = new SmtpClientOptions { HeloName = "client.test", Pipelining = pipelining, PreferChunking = chunking, BdatChunkSize = 7 };
            await using var conn = await SmtpClientConnection.ConnectAsync(server.Target(SmtpTlsPolicy.Disabled), options);

            var result = await conn.SendAsync(Envelope(), Message(body));

            Assert.True(result.Delivered, $"pipelining={pipelining} chunking={chunking}");
            var received = Assert.Single(server.Handler.Messages);
            string expected = Encoding.UTF8.GetString(Message(body));
            string actual = Encoding.UTF8.GetString(received.Body);
            // Unchanged, except that a body that does not end in a line break may be handed on with one (the framing decides): the property is that
            // nothing of the body is lost, split into a second message, or taken for the end of the data.
            Assert.True(actual == expected || actual == expected + "\r\n", $"pipelining={pipelining} chunking={chunking}: {actual}");
            Assert.Equal(["rcpt@dest.example"], received.To);
        }
    }

    [Theory]
    [InlineData("bare\nlf\r\n")]
    [InlineData("bare\rcr\r\n")]
    [InlineData("nul\0byte\r\n")]
    public async Task A_body_with_a_bare_line_ending_or_NUL_is_refused_before_a_byte_is_sent(string body)
    {
        await using var server = new RealServer();
        await using var conn = await SmtpClientConnection.ConnectAsync(server.Target(SmtpTlsPolicy.Disabled), new SmtpClientOptions { HeloName = "client.test" });

        var result = await conn.SendAsync(Envelope(), Message(body));

        Assert.False(result.Delivered);
        Assert.NotEqual(LocalFailure.None, result.LocalFailure);
        Assert.Empty(server.Handler.Messages);
    }
}
