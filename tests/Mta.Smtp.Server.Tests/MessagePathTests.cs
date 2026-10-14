using System.Buffers;
using System.Text;
using System.Text.RegularExpressions;

namespace Mta.Smtp.Server.Tests;

/// <summary>The per-message work of the session: the Received field, the message buffer handed to the handler and the paths parsed from MAIL/RCPT.</summary>
public partial class MessagePathTests
{
    [GeneratedRegex(@"^Received: from (?<helo>\S+) \(\[(?<ip>[^\]]+)\]\)\r\n\tby mx\.test with (?<with>\w+) id (?<id>[0-9a-f]{16})(?<tls>\r\n\t\([^)]*\))?(?<for>\r\n\tfor <[^>]*>)?;\r\n\t(?<date>[A-Z][a-z]{2}, \d\d [A-Z][a-z]{2} \d{4} \d\d:\d\d:\d\d \+0000)\r\n$")]
    private static partial Regex ReceivedPattern();

    private static async Task<RawClient> OpenAsync(ServerFixture f)
    {
        var c = await RawClient.ConnectAsync(f.OpenPort);
        await c.ExpectAsync(220);
        return c;
    }

    private static async Task SendMessageAsync(RawClient c, string from, string[] recipients, string body = "Subject: s\r\n\r\nbody\r\n")
    {
        await c.CommandAsync($"MAIL FROM:<{from}>", 250);
        foreach (string r in recipients)
        {
            await c.CommandAsync($"RCPT TO:<{r}>", 250);
        }

        await c.CommandAsync("DATA", 354);
        await c.SendAsync(body + ".\r\n");
        await c.ExpectAsync(250);
    }

    [Fact]
    public async Task The_received_field_has_the_documented_shape_for_a_single_recipient()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO client.test", 250);
        await SendMessageAsync(c, "sender@example.org", ["rcpt@example.com"]);

        string received = Encoding.UTF8.GetString(Assert.Single(f.Handler.Messages).Received);
        var m = ReceivedPattern().Match(received);
        Assert.True(m.Success, received);
        Assert.Equal("client.test", m.Groups["helo"].Value);
        Assert.Equal("127.0.0.1", m.Groups["ip"].Value);
        Assert.Equal("ESMTP", m.Groups["with"].Value);
        Assert.False(m.Groups["tls"].Success);
        Assert.Equal("\r\n\tfor <rcpt@example.com>", m.Groups["for"].Value);
        Assert.True(DateTimeOffset.TryParseExact(m.Groups["date"].Value.Replace("+0000", "+00:00"), "ddd, dd MMM yyyy HH:mm:ss zzz", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var date));
        Assert.True(Math.Abs((DateTimeOffset.UtcNow - date).TotalMinutes) < 5);
    }

    [Fact]
    public async Task Several_recipients_leave_out_the_for_clause_and_every_message_gets_its_own_id()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO client.test", 250);
        await SendMessageAsync(c, "sender@example.org", ["a@example.com", "b@example.com"]);
        await SendMessageAsync(c, "sender@example.org", ["c@example.com"]);

        var first = ReceivedPattern().Match(Encoding.UTF8.GetString(f.Handler.Messages[0].Received));
        var second = ReceivedPattern().Match(Encoding.UTF8.GetString(f.Handler.Messages[1].Received));
        Assert.True(first.Success && second.Success);
        Assert.False(first.Groups["for"].Success);
        Assert.True(second.Groups["for"].Success);
        Assert.NotEqual(first.Groups["id"].Value, second.Groups["id"].Value);
    }

    [Fact]
    public async Task A_new_greeting_name_shows_in_the_next_received_field()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO first.test", 250);
        await SendMessageAsync(c, "sender@example.org", ["a@example.com"]);
        await c.CommandAsync("EHLO second.test", 250);
        await SendMessageAsync(c, "sender@example.org", ["a@example.com"]);

        Assert.Equal("first.test", ReceivedPattern().Match(Encoding.UTF8.GetString(f.Handler.Messages[0].Received)).Groups["helo"].Value);
        Assert.Equal("second.test", ReceivedPattern().Match(Encoding.UTF8.GetString(f.Handler.Messages[1].Received)).Groups["helo"].Value);
    }

    [Fact]
    public async Task A_non_ascii_recipient_is_written_as_utf8_in_the_received_field()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO client.test", 250);
        await c.CommandAsync("MAIL FROM:<sender@example.org> SMTPUTF8", 250);
        await c.CommandAsync("RCPT TO:<j\u00fcrgen@example.com>", 250);
        await c.CommandAsync("DATA", 354);
        await c.SendAsync("Subject: s\r\n\r\nbody\r\n.\r\n");
        await c.ExpectAsync(250);

        string received = Encoding.UTF8.GetString(Assert.Single(f.Handler.Messages).Received);
        Assert.Contains("for <j\u00fcrgen@example.com>;", received);
    }

    [Fact]
    public async Task A_message_larger_than_one_buffer_segment_arrives_complete()
    {
        // MessageBuffer segments are 16 KiB; below that the handler gets a plain single-segment sequence, above it a chain.
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO client.test", 250);
        string small = "Subject: small\r\n\r\n" + new string('s', 500) + "\r\n";
        string large = "Subject: large\r\n\r\n" + string.Concat(Enumerable.Range(0, 3000).Select(i => $"line {i} {new string('x', 40)}\r\n"));
        await SendMessageAsync(c, "sender@example.org", ["a@example.com"], small);
        await SendMessageAsync(c, "sender@example.org", ["a@example.com"], large);

        Assert.Equal(small, Encoding.UTF8.GetString(f.Handler.Messages[0].Body));
        Assert.Equal(large, Encoding.UTF8.GetString(f.Handler.Messages[1].Body));
    }

    [Fact]
    public void The_message_buffer_of_one_segment_is_a_single_segment_sequence()
    {
        using var buffer = new MessageBuffer();
        Assert.True(buffer.AsSequence().IsEmpty);
        byte[] data = Encoding.ASCII.GetBytes("hello world");
        buffer.Write(data);
        var sequence = buffer.AsSequence();
        Assert.True(sequence.IsSingleSegment);
        Assert.Equal(data, sequence.ToArray());

        var big = new byte[MessageBuffer.SegmentSize * 3 + 17];
        new Random(1).NextBytes(big);
        using var chain = new MessageBuffer();
        chain.Write(big);
        Assert.False(chain.AsSequence().IsSingleSegment);
        Assert.Equal(big, chain.AsSequence().ToArray());
        Assert.Equal(big.Length, chain.Length);
    }

    [Theory]
    [InlineData("<a@example.com>", "a@example.com")]
    [InlineData("<\"quoted local\"@example.com>", "\"quoted local\"@example.com")]
    [InlineData("<@relay.example,@relay2.example:a@example.com>", "a@example.com")]   // the obsolete source route is dropped
    [InlineData("<Mixed.Case@Example.COM>", "Mixed.Case@example.com")]                  // the local part keeps its case, the domain is lower-cased
    public async Task Paths_are_decoded_to_the_address_the_handler_sees(string path, string expected)
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO client.test", 250);
        await SendMessageAsync(c, path[1..^1], [path[1..^1]]);

        var message = Assert.Single(f.Handler.Messages);
        Assert.Equal(expected, message.Sender.ToString());
        Assert.Equal([expected], message.Recipients);
    }

    [Fact]
    public async Task Overlong_and_unusual_paths_are_refused_without_harm()
    {
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO client.test", 250);
        await c.CommandAsync("MAIL FROM:<" + new string('a', 600) + "@example.com>", 501);   // longer than the 512-char stack buffer: still a clean syntax error
        await c.CommandAsync("MAIL FROM:<" + new string('\u00e9', 200) + "@example.com>", 501);
        await c.CommandAsync("MAIL FROM:<sender@example.org>", 250);
    }
}
