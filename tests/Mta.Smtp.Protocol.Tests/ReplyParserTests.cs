using System.Buffers;
using System.Text;

namespace Mta.Smtp.Protocol.Tests;

/// <summary>Reply parsing reads a line in place when it sits in one segment and copies only a line that is split; both must give the same reply.</summary>
public class ReplyParserTests
{
    private sealed class Chain : ReadOnlySequenceSegment<byte>
    {
        public Chain(byte[] data, long runningIndex)
        {
            Memory = data;
            RunningIndex = runningIndex;
        }

        public Chain Append(byte[] data)
        {
            var next = new Chain(data, RunningIndex + Memory.Length);
            Next = next;
            return next;
        }
    }

    private static ReadOnlySequence<byte> Split(string text, params int[] cuts)
    {
        byte[] all = Encoding.UTF8.GetBytes(text);
        var parts = new List<byte[]>();
        int from = 0;
        foreach (int cut in cuts.Append(all.Length))
        {
            parts.Add(all[from..cut]);
            from = cut;
        }

        var first = new Chain(parts[0], 0);
        var last = first;
        foreach (var part in parts.Skip(1))
        {
            last = last.Append(part);
        }

        return new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
    }

    private static string Render(SmtpReply r) => $"{r.Code}|{r.EnhancedCode}|{string.Join("\n", r.Lines)}";

    [Theory]
    [InlineData("250 2.0.0 OK queued as 12345\r\n")]
    [InlineData("250 OK\r\n")]
    [InlineData("250-mx.example.com Hello\r\n250-PIPELINING\r\n250 2.0.0 SIZE 100\r\n")]
    [InlineData("550 5.1.1 <a@b.example>: User unknown\r\n")]
    [InlineData("451 4.7.1 Greylisted, try again\r\n")]
    [InlineData("554 5.7.1\r\n")]
    [InlineData("421\r\n")]
    [InlineData("354 End data with <CR><LF>.<CR><LF>\r\n")]
    [InlineData("250 2.1.0\r\n")]
    [InlineData("250 9.9.9 not an enhanced code for class 2\r\n")]
    [InlineData("250 2.99999.0 five digits\r\n")]
    [InlineData("250 été 2.0.0 non-ascii text\r\n")]
    public void A_reply_split_anywhere_parses_like_the_same_reply_in_one_piece(string text)
    {
        var whole = new ReadOnlySequence<byte>(Encoding.UTF8.GetBytes(text));
        Assert.Equal(ReplyParseStatus.Ok, SmtpReplyParser.TryParse(whole, out var expected, out var expectedConsumed));
        for (int cut = 1; cut < Encoding.UTF8.GetByteCount(text); cut++)
        {
            var sequence = Split(text, cut);
            Assert.Equal(ReplyParseStatus.Ok, SmtpReplyParser.TryParse(sequence, out var actual, out var consumed));
            Assert.Equal(Render(expected!), Render(actual!));
            Assert.Equal(sequence.Length, sequence.Slice(0, consumed).Length);
        }

        Assert.Equal(whole.Length, whole.Slice(0, expectedConsumed).Length);
    }

    [Fact]
    public void Common_enhanced_status_codes_are_shared_strings_and_others_are_still_exact()
    {
        SmtpReplyParser.TryParse(new ReadOnlySequence<byte>("250 2.0.0 OK\r\n"u8.ToArray()), out var a, out _);
        SmtpReplyParser.TryParse(new ReadOnlySequence<byte>("250 2.0.0 Other text\r\n"u8.ToArray()), out var b, out _);
        Assert.Same(a!.EnhancedCode, b!.EnhancedCode);
        Assert.Equal("OK", a.Lines[0]);
        Assert.Equal("Other text", b.Lines[0]);

        SmtpReplyParser.TryParse(new ReadOnlySequence<byte>("550 5.7.26 DMARC\r\n"u8.ToArray()), out var c, out _);
        Assert.Equal("5.7.26", c!.EnhancedCode);
        Assert.Equal("DMARC", c.Lines[0]);
    }

    [Fact]
    public void The_enhanced_code_of_the_first_line_wins_and_every_line_is_stripped()
    {
        SmtpReplyParser.TryParse(new ReadOnlySequence<byte>("250-2.1.5 first\r\n250-2.9.9 second\r\n250 third\r\n"u8.ToArray()), out var reply, out _);
        Assert.Equal("2.1.5", reply!.EnhancedCode);
        Assert.Equal(["first", "second", "third"], reply.Lines);
    }

    [Theory]
    [InlineData("250 ok\n")]
    [InlineData("250 ok\r\n")]
    public void A_bare_line_feed_is_accepted(string text)
    {
        Assert.Equal(ReplyParseStatus.Ok, SmtpReplyParser.TryParse(new ReadOnlySequence<byte>(Encoding.ASCII.GetBytes(text)), out var reply, out _));
        Assert.Equal("ok", reply!.Lines[0]);
    }

    [Fact]
    public void A_reply_with_too_many_lines_is_invalid()
    {
        string text = string.Concat(Enumerable.Repeat("250-more\r\n", SmtpReplyParser.MaxLines + 1)) + "250 end\r\n";
        Assert.Equal(ReplyParseStatus.Invalid, SmtpReplyParser.TryParse(new ReadOnlySequence<byte>(Encoding.ASCII.GetBytes(text)), out _, out _));
        string fine = string.Concat(Enumerable.Repeat("250-more\r\n", SmtpReplyParser.MaxLines - 1)) + "250 end\r\n";
        Assert.Equal(ReplyParseStatus.Ok, SmtpReplyParser.TryParse(new ReadOnlySequence<byte>(Encoding.ASCII.GetBytes(fine)), out var reply, out _));
        Assert.Equal(SmtpReplyParser.MaxLines, reply!.Lines.Count);
    }

    // ---- the parser before it was changed to read lines in place and share enhanced codes, kept as the reference for a differential check

    private static ReplyParseStatus ReferenceParse(in ReadOnlySequence<byte> buffer, out SmtpReply? reply, out SequencePosition consumed)
    {
        reply = null;
        consumed = buffer.Start;
        var reader = new SequenceReader<byte>(buffer);
        var lines = new List<string>(2);
        int code = -1;
        string? enhanced = null;

        while (true)
        {
            if (!reader.TryReadTo(out ReadOnlySequence<byte> lineSeq, (byte)'\n', advancePastDelimiter: true))
            {
                return buffer.Length > SmtpReplyParser.MaxLineLength * 2L ? ReplyParseStatus.Invalid : ReplyParseStatus.NeedMoreData;
            }

            if (lineSeq.Length > SmtpReplyParser.MaxLineLength || lines.Count >= SmtpReplyParser.MaxLines)
            {
                return ReplyParseStatus.Invalid;
            }

            byte[] bytes = lineSeq.ToArray();
            var line = bytes.AsSpan();
            if (line.Length > 0 && line[^1] == '\r')
            {
                line = line[..^1];
            }

            if (line.IndexOf((byte)'\r') >= 0 || line.IndexOf((byte)0) >= 0 || line.Length < 3)
            {
                return ReplyParseStatus.Invalid;
            }

            if (!(char.IsAsciiDigit((char)line[0]) && char.IsAsciiDigit((char)line[1]) && char.IsAsciiDigit((char)line[2])))
            {
                return ReplyParseStatus.Invalid;
            }

            int thisCode = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
            if (thisCode < 200 || thisCode > 599)
            {
                return ReplyParseStatus.Invalid;
            }

            if (code >= 0 && thisCode != code)
            {
                return ReplyParseStatus.Invalid;
            }

            code = thisCode;
            bool last;
            ReadOnlySpan<byte> text;
            if (line.Length == 3) { last = true; text = default; }
            else if (line[3] == ' ') { last = true; text = line[4..]; }
            else if (line[3] == '-') { last = false; text = line[4..]; }
            else { return ReplyParseStatus.Invalid; }

            string t = Encoding.UTF8.GetString(text);
            if (SmtpReplyParser_TryStripEnhanced(ref t, code, out string? enh))
            {
                enhanced ??= enh;
            }

            lines.Add(t);
            if (last)
            {
                reply = new SmtpReply(code, enhanced, lines);
                consumed = reader.Position;
                return ReplyParseStatus.Ok;
            }
        }
    }

    private static bool SmtpReplyParser_TryStripEnhanced(ref string text, int code, out string? enhanced)
    {
        enhanced = null;
        if (text.Length < 5) { return false; }
        char cls = text[0];
        if (cls != (char)('0' + code / 100) || (cls != '2' && cls != '4' && cls != '5') || text[1] != '.') { return false; }
        int i = 2;
        int d1 = 0;
        while (i < text.Length && char.IsAsciiDigit(text[i]) && d1 < 4) { i++; d1++; }
        if (d1 == 0 || i >= text.Length || text[i] != '.') { return false; }
        i++;
        int d2 = 0;
        while (i < text.Length && char.IsAsciiDigit(text[i]) && d2 < 4) { i++; d2++; }
        if (d2 == 0 || (i < text.Length && text[i] != ' ')) { return false; }
        enhanced = text[..i];
        text = i < text.Length ? text[(i + 1)..] : "";
        return true;
    }

    [Fact]
    public void The_parser_agrees_with_the_one_it_replaced_on_random_input()
    {
        string[] pieces = ["250", "550", "451", "354", "200", "199", "600", "25", "-", " ", "2.0.0", "5.1.1", "4.7.0", "2.1", "9.9.9", "2.", "OK", "queued", "\u00e9", "\r\n", "\n", "\r", "\0", "x"];
        var random = new Random(4242);
        int ok = 0;
        for (int i = 0; i < 30_000; i++)
        {
            var sb = new StringBuilder();
            int count = random.Next(1, 14);
            for (int p = 0; p < count; p++)
            {
                sb.Append(pieces[random.Next(pieces.Length)]);
            }

            if (random.Next(2) == 0)
            {
                sb.Append("\r\n");
            }

            var bytes = Encoding.UTF8.GetBytes(sb.ToString());
            var whole = new ReadOnlySequence<byte>(bytes);
            var expectedStatus = ReferenceParse(whole, out var expected, out var expectedConsumed);
            var actualStatus = SmtpReplyParser.TryParse(whole, out var actual, out var actualConsumed);
            Assert.True(expectedStatus == actualStatus, $"[{sb}] status {expectedStatus} vs {actualStatus}");
            if (expectedStatus == ReplyParseStatus.Ok)
            {
                ok++;
                Assert.Equal(Render(expected!), Render(actual!));
                Assert.Equal(whole.Slice(0, expectedConsumed).Length, whole.Slice(0, actualConsumed).Length);
            }
        }

        Assert.True(ok > 500, $"only {ok} of the generated inputs were valid replies");
    }
}
