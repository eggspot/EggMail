using System.Buffers;
using System.Text;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Protocol.Tests;

public class ReplyTests
{
    private static string Render(SmtpReply r, bool enhanced = true)
    {
        var w = new ArrayBufferWriter<byte>();
        r.WriteTo(w, enhanced);
        return Encoding.UTF8.GetString(w.WrittenSpan);
    }

    [Fact]
    public void Single_line_with_enhanced_status()
    {
        Assert.Equal("250 2.1.0 Sender OK\r\n", Render(SmtpReplies.SenderOk));
        Assert.Equal("250 Sender OK\r\n", Render(SmtpReplies.SenderOk, enhanced: false));
    }

    [Fact]
    public void Multi_line_reply_uses_hyphens()
    {
        var r = new SmtpReply(250, null, ["mail.example.com", "PIPELINING", "8BITMIME"]);
        Assert.Equal("250-mail.example.com\r\n250-PIPELINING\r\n250 8BITMIME\r\n", Render(r));
    }

    [Fact]
    public void A_reply_with_an_id_is_written_and_read_like_the_reply_with_the_same_text()
    {
        var id = Guid.Parse("0197a2b3-4c5d-7e6f-8091-a2b3c4d5e6f7");
        var withId = SmtpReply.CreateWithId(250, "2.0.0", "Queued as ", id);
        var plain = SmtpReply.Create(250, "2.0.0", "Queued as 0197a2b34c5d7e6f8091a2b3c4d5e6f7");
        Assert.Equal(Render(plain), Render(withId));
        Assert.Equal(Render(plain, enhanced: false), Render(withId, enhanced: false));
        Assert.Equal("250 2.0.0 Queued as 0197a2b34c5d7e6f8091a2b3c4d5e6f7\r\n", Render(withId));
        Assert.Equal(["Queued as 0197a2b34c5d7e6f8091a2b3c4d5e6f7"], withId.Lines);
        Assert.Equal(plain.ToString(), withId.ToString());
        Assert.True(withId.IsPositiveCompletion);
        Assert.Throws<ArgumentException>(() => SmtpReply.CreateWithId(250, null, "bad\r\n", id));
        Assert.Throws<ArgumentOutOfRangeException>(() => SmtpReply.CreateWithId(100, null, "x", id));
    }

    [Fact]
    public void A_single_line_reply_makes_its_list_of_lines_only_when_asked_and_writes_the_same_either_way()
    {
        var reply = SmtpReply.Create(451, "4.3.0", "Temporary problem");
        string before = Render(reply);
        Assert.Equal(["Temporary problem"], reply.Lines);
        Assert.Same(reply.Lines, reply.Lines);
        Assert.Equal(before, Render(reply));
        Assert.Equal("451 4.3.0 Temporary problem\r\n", before);
        Assert.Equal("451 Temporary problem\r\n", Render(reply, enhanced: false));
        Assert.Equal("250 café\r\n", Render(SmtpReply.Create(250, null, "café")));
    }

    [Fact]
    public void Rejects_crlf_injection_in_text()
    {
        Assert.Throws<ArgumentException>(() => SmtpReply.Create(250, null, "ok\r\n550 evil"));
    }

    [Fact]
    public void Parses_multiline_and_enhanced()
    {
        var bytes = Encoding.ASCII.GetBytes("250-mx.example.com Hello\r\n250-2.0.0 PIPELINING\r\n250 2.0.0 SIZE 100\r\nQUIT");
        var status = SmtpReplyParser.TryParse(new ReadOnlySequence<byte>(bytes), out var reply, out var consumed);
        Assert.Equal(ReplyParseStatus.Ok, status);
        Assert.Equal(250, reply!.Code);
        Assert.Equal("2.0.0", reply.EnhancedCode);
        Assert.Equal(3, reply.Lines.Count);
        Assert.Equal("PIPELINING", reply.Lines[1]);
        Assert.Equal(bytes.Length - 4, new ReadOnlySequence<byte>(bytes).Slice(0, consumed).Length);
    }

    [Fact]
    public void Needs_more_data_for_incomplete()
    {
        var bytes = Encoding.ASCII.GetBytes("250-first\r\n250 sec");
        Assert.Equal(ReplyParseStatus.NeedMoreData, SmtpReplyParser.TryParse(new ReadOnlySequence<byte>(bytes), out _, out _));
    }

    [Theory]
    [InlineData("25 short\r\n")]
    [InlineData("abc hello\r\n")]
    [InlineData("250-a\r\n251 b\r\n")]
    [InlineData("250xhello\r\n")]
    [InlineData("250 a\rb\r\n")]
    [InlineData("100 nope\r\n")]
    public void Rejects_malformed(string input)
    {
        var status = SmtpReplyParser.TryParse(new ReadOnlySequence<byte>(Encoding.ASCII.GetBytes(input)), out _, out _);
        Assert.Equal(ReplyParseStatus.Invalid, status);
    }

    [Fact]
    public void Parses_across_segments()
    {
        var first = new Segment(Encoding.ASCII.GetBytes("250-aa\r"));
        var last = first.Append(Encoding.ASCII.GetBytes("\n250 bb\r\n"));
        var seq = new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
        Assert.Equal(ReplyParseStatus.Ok, SmtpReplyParser.TryParse(seq, out var reply, out _));
        Assert.Equal(2, reply!.Lines.Count);
    }

    [Fact]
    public void Capabilities_roundtrip()
    {
        var caps = new SmtpCapabilities
        {
            Pipelining = true, EightBitMime = true, StartTls = true, SmtpUtf8 = true, Chunking = true,
            EnhancedStatusCodes = true, Size = 26214400, AuthMechanisms = ["PLAIN", "LOGIN"],
        };
        var lines = caps.ToEhloLines("mx.example.com greets you");
        var parsed = SmtpCapabilities.Parse(lines.Skip(1));
        Assert.True(parsed.Pipelining && parsed.EightBitMime && parsed.StartTls && parsed.SmtpUtf8 && parsed.Chunking && parsed.EnhancedStatusCodes);
        Assert.Equal(26214400, parsed.Size);
        Assert.Equal(["PLAIN", "LOGIN"], parsed.AuthMechanisms);
    }

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public Segment(ReadOnlyMemory<byte> memory) => Memory = memory;

        public Segment Append(ReadOnlyMemory<byte> memory)
        {
            var next = new Segment(memory) { RunningIndex = RunningIndex + Memory.Length };
            Next = next;
            return next;
        }
    }
}
