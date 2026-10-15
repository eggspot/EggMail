using System.Buffers;
using System.Text;
using System.Text.RegularExpressions;
using Mta.Smtp.Protocol;

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

    private static async Task SendMessageAsync(RawClient c, string from, string[] recipients, string body = "Subject: s\r\n\r\nbody\r\n", int expect = 250)
    {
        await c.CommandAsync($"MAIL FROM:<{from}>", 250);
        foreach (string r in recipients)
        {
            await c.CommandAsync($"RCPT TO:<{r}>", 250);
        }

        await c.CommandAsync("DATA", 354);
        await c.SendAsync(body + ".\r\n");
        await c.ExpectAsync(expect);
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

    [Fact]
    public void A_message_buffer_that_is_disposed_reset_and_used_again_never_shows_an_earlier_message()
    {
        // The session keeps one buffer (and the object of its first segment) for all its messages: sizes from one byte to several segments, many cycles.
        var buffer = new MessageBuffer();
        var random = new Random(7);
        var sizes = new[] { 5, MessageBuffer.SegmentSize * 3 + 11, 1, MessageBuffer.SegmentSize, 70_000, 0, 3, MessageBuffer.SegmentSize * 2, 12 };
        for (int round = 0; round < 40; round++)
        {
            int size = sizes[round % sizes.Length];
            byte[] data = new byte[size];
            random.NextBytes(data);
            buffer.Write(data);
            var sequence = buffer.AsSequence();
            Assert.Equal(size, sequence.Length);
            Assert.Equal(data, sequence.ToArray());
            Assert.Equal(size <= MessageBuffer.SegmentSize, sequence.IsSingleSegment);
            Assert.Equal(size, buffer.Length);

            buffer.Dispose();
            Assert.Equal(0, buffer.Length);
            Assert.Equal(0, buffer.Capacity);
            Assert.True(buffer.AsSequence().IsEmpty);
            Assert.Throws<ObjectDisposedException>(() => buffer.GetSpan(1));
            buffer.Dispose();   // twice is harmless
            buffer.Reset();
            Assert.True(buffer.AsSequence().IsEmpty);   // nothing of the last message is visible through the reset buffer
        }

        Assert.Throws<InvalidOperationException>(() => buffer.Reset());   // only a disposed buffer can be reset
        buffer.Dispose();
    }

    [Fact]
    public async Task The_in_flight_budget_is_back_to_zero_after_oversize_and_memory_refusals_and_a_good_message_still_goes_through()
    {
        // 552 (over MaxMessageSize), 452 (the in-flight budget is too small for a buffer segment) and a client that leaves mid-DATA all give back what they reserved.
        await using (var big = new ServerFixture(o => new SmtpServerOptions { Hostname = o.Hostname, Certificates = o.Certificates, Listeners = o.Listeners, MaxMessageSize = 1000, AuthFailureDelay = TimeSpan.Zero }))
        {
            using var c = await OpenAsync(big);
            await c.CommandAsync("EHLO x.test", 250);
            for (int i = 0; i < 3; i++)
            {
                await SendMessageAsync(c, "a@b.example", ["c@d.example"], string.Concat(Enumerable.Repeat(new string('x', 98) + "\r\n", 30)), expect: 552);
                Assert.Equal(0, big.Server.Budget.Used);
            }

            await SendMessageAsync(c, "a@b.example", ["c@d.example"], "Subject: ok\r\n\r\nsmall\r\n");
            Assert.Equal(0, big.Server.Budget.Used);
            Assert.Single(big.Handler.Messages);
        }

        await using (var small = new ServerFixture(o => new SmtpServerOptions { Hostname = o.Hostname, Certificates = o.Certificates, Listeners = o.Listeners, MaxInFlightBytes = 1024, AuthFailureDelay = TimeSpan.Zero }))
        {
            using var c = await OpenAsync(small);
            await c.CommandAsync("EHLO x.test", 250);
            for (int i = 0; i < 3; i++)
            {
                await SendMessageAsync(c, "a@b.example", ["c@d.example"], "Subject: s\r\n\r\nbody\r\n", expect: 452);
                Assert.Equal(0, small.Server.Budget.Used);
            }

            Assert.Empty(small.Handler.Messages);
        }

        await using (var leaves = new ServerFixture())
        {
            using (var c = await OpenAsync(leaves))
            {
                await c.CommandAsync("EHLO x.test", 250);
                await c.CommandAsync("MAIL FROM:<a@b.example>", 250);
                await c.CommandAsync("RCPT TO:<c@d.example>", 250);
                await c.CommandAsync("DATA", 354);
                await c.SendAsync("Subject: half\r\n\r\nno end of data");
            }   // disconnects in the middle of DATA

            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (leaves.Server.Budget.Used != 0 && DateTime.UtcNow < deadline)
            {
                await Task.Yield();
            }

            Assert.Equal(0, leaves.Server.Budget.Used);
            using var again = await OpenAsync(leaves);
            await again.CommandAsync("EHLO x.test", 250);
            await SendMessageAsync(again, "a@b.example", ["c@d.example"], "Subject: after\r\n\r\nfine\r\n");
            Assert.Equal(0, leaves.Server.Budget.Used);
            Assert.Equal("Subject: after\r\n\r\nfine\r\n", Encoding.UTF8.GetString(Assert.Single(leaves.Handler.Messages).Body));
        }
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

    [Fact]
    public async Task The_message_object_is_reused_but_every_message_shows_its_own_values_and_is_emptied_after_the_call()
    {
        // The server keeps one SmtpMessage and one MailFromInfo per session (no allocation per message); what the handler reads during its call
        // must be that message's own, and the memory behind the body must not stay reachable through the object once the call has returned.
        var seen = new List<(SmtpMessage Object, string Sender, string[] Recipients, string Body, string Received)>();
        var handler = new RecordingHandler
        {
            OnMessage = message =>
            {
                seen.Add((message, message.Sender.ToString(), message.Recipients.Select(r => r.ToString()).ToArray(),
                    Encoding.UTF8.GetString(message.Body.ToArray()), Encoding.UTF8.GetString(message.ReceivedHeader.Span)));
                return SmtpReply.Create(250, "2.0.0", "Queued");
            },
        };
        await using var f = new ServerFixture(handler: handler);
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO client.test", 250);
        await SendMessageAsync(c, "one@example.org", ["a@example.com"], "Subject: one\r\n\r\nfirst\r\n");
        await SendMessageAsync(c, "two@example.org", ["b@example.com", "c@example.com"], "Subject: two\r\n\r\nsecond\r\n");
        await SendMessageAsync(c, "one@example.org", ["a@example.com"], "Subject: three\r\n\r\nthird\r\n");

        Assert.Equal(3, seen.Count);
        Assert.Equal(["one@example.org", "two@example.org", "one@example.org"], seen.Select(x => x.Sender));
        Assert.Equal(["a@example.com"], seen[0].Recipients);
        Assert.Equal(["b@example.com", "c@example.com"], seen[1].Recipients);
        Assert.Equal(["a@example.com"], seen[2].Recipients);
        Assert.Equal(["Subject: one\r\n\r\nfirst\r\n", "Subject: two\r\n\r\nsecond\r\n", "Subject: three\r\n\r\nthird\r\n"], seen.Select(x => x.Body));
        Assert.Contains("for <a@example.com>", seen[0].Received);
        Assert.DoesNotContain("for <", seen[1].Received);
        Assert.Contains("for <a@example.com>", seen[2].Received);
        Assert.Same(seen[0].Object, seen[1].Object);   // one object per session
        Assert.True(seen[0].Object.Body.IsEmpty);
        Assert.True(seen[0].Object.ReceivedHeader.IsEmpty);
        Assert.Empty(seen[0].Object.Recipients);
    }

    [Fact]
    public async Task An_address_seen_before_in_the_session_parses_to_the_same_value()
    {
        // The per-session memo of parsed paths must give the result of a fresh parse: same text, same address; a different case of the domain, the lower-case domain.
        await using var f = new ServerFixture();
        using var c = await OpenAsync(f);
        await c.CommandAsync("EHLO client.test", 250);
        await SendMessageAsync(c, "Sender.One@example.org", ["Rcpt@Example.COM"]);
        await SendMessageAsync(c, "Sender.One@example.org", ["Rcpt@example.com"]);
        await SendMessageAsync(c, "Sender.One@EXAMPLE.org", ["rcpt@example.com"]);

        Assert.Equal(["Sender.One@example.org", "Sender.One@example.org", "Sender.One@example.org"], f.Handler.Messages.Select(m => m.Sender.ToString()));
        Assert.Equal([["Rcpt@example.com"], ["Rcpt@example.com"], ["rcpt@example.com"]], f.Handler.Messages.Select(m => m.Recipients));
    }
}
