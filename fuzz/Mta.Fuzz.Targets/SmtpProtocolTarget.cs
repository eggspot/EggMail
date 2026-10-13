using System.Buffers;
using System.Text;
using Mta.Smtp.Protocol;

namespace Mta.Fuzz;

/// <summary>
/// The pure SMTP protocol pieces: command line scanning and parsing (server side), reply parsing and EHLO capability parsing
/// (client side), the DATA scanner (dot-unstuffing and the smuggling defense) and the SASL helpers.
/// </summary>
internal static class SmtpProtocolTarget
{
    private static readonly SmtpParseOptions Options = new() { MaxLineLength = 512 };

    public static FuzzTarget Create() => new(
        "smtp-protocol",
        "SMTP command line scanner and parser, reply parser, EHLO capabilities, DATA scanner, SASL PLAIN and xtext",
        Run,
        Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 70000,
    };

    private static IReadOnlyList<byte[]> Seeds() =>
    [
        Bytes("EHLO client.example.org\r\n"),
        Bytes("HELO [192.0.2.7]\r\n"),
        Bytes("MAIL FROM:<alice@example.com> SIZE=12345 BODY=8BITMIME SMTPUTF8 AUTH=<>\r\nRCPT TO:<bob@example.net> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;bob@example.net\r\n"),
        Bytes("MAIL FROM:<> RET=HDRS ENVID=abc+3Dxyz\r\n"),
        Bytes("RCPT TO:<\"quoted local\"@[IPv6:2001:db8::1]>\r\nDATA\r\n"),
        Bytes("AUTH PLAIN AHVzZXIAcGFzcw==\r\nAUTH LOGIN\r\nBDAT 12 LAST\r\nSTARTTLS\r\nRSET\r\nNOOP\r\nVRFY postmaster\r\nQUIT\r\n"),
        Bytes("Subject: x\r\n\r\n.hidden\r\n..dotted\r\nbody line\r\n.\r\n"),
        Bytes("250-mx.example.org Hello\r\n250-PIPELINING\r\n250-SIZE 35882577\r\n250-8BITMIME\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250 STARTTLS\r\n"),
        Bytes("550 5.1.1 <nobody@example.org>: Recipient address rejected\r\n"),
        Bytes("\0user\0password"),
        Bytes("a+2Bb=3D;+0D"),
        Bytes("MAIL FROM:<a@b>\n\rRCPT\r\r\n\n\n.\r\n.\n"),
    ];

    private static IReadOnlyList<byte[]> Tokens() =>
    [
        Bytes("\r\n"), Bytes("\r\n.\r\n"), Bytes("\n.\n"), Bytes("\r\n.\n"), Bytes("MAIL FROM:"), Bytes("RCPT TO:"), Bytes("EHLO "), Bytes("BDAT "),
        Bytes(" SIZE="), Bytes(" BODY="), Bytes(" SMTPUTF8"), Bytes(" NOTIFY="), Bytes(" ORCPT="), Bytes(" AUTH="), Bytes("<"), Bytes(">"), Bytes("\""),
        Bytes("[IPv6:"), Bytes("=?utf-8?"), Bytes("250-"), Bytes("250 "), Bytes("5.7.1 "), Bytes("\0"), Bytes(" LAST"),
    ];

    private static void Run(ReadOnlySpan<byte> input)
    {
        byte[] data = input.ToArray();

        // ---- server side: scan lines, parse each as a command
        ScanLines(data);

        // ---- the same bytes as one command line (without terminator)
        _ = SmtpCommandParser.TryParse(data, Options, out _);

        // ---- client side
        Replies(data);

        // ---- the DATA scanner: one call versus resumed at arbitrary boundaries must agree
        DataScan(data);

        // ---- helpers
        string text = Latin1(data);
        _ = Sasl.TryParsePlain(data, out _, out _, out _);
        _ = Sasl.TryDecodeXtext(text, out _);
        _ = SmtpCapabilities.Parse(text.Split('\n').Select(l => l.TrimEnd('\r')));
    }

    private static void ScanLines(byte[] data)
    {
        var scratch = new byte[Options.MaxLineLength + 1];
        // Once as one segment and once split in the middle (the scanner has a separate path for lines that cross segments).
        foreach (ReadOnlySequence<byte> sequence in new[] { new ReadOnlySequence<byte>(data), Segments.Split(data, data.Length / 2) })
        {
            ReadOnlySequence<byte> remaining = sequence;
            int lines = 0;
            while (lines++ < 100_000 && !remaining.IsEmpty)
            {
                var status = SmtpLineScanner.TryGetLine(remaining, Options.MaxLineLength, scratch, out var line, out int consumed);
                if (status != LineStatus.Ok)
                {
                    Guard.Check(consumed == 0 || status == LineStatus.Incomplete, "a failed line scan must not consume input");
                    break;
                }

                Guard.Check(consumed == line.Length + 2, "consumed must be the line plus CRLF");
                Guard.Check(consumed > 0 && consumed <= remaining.Length, "consumed must stay within the buffer");
                Guard.Check(line.Length + 2 <= Options.MaxLineLength + 2, "line longer than the limit accepted");
                if (SmtpCommandParser.TryParse(line, Options, out var command) == SmtpParseError.None)
                {
                    Guard.Check(command.Verb != SmtpVerb.Unknown || line.Length > 0, "a parsed command must have a verb");
                }

                remaining = remaining.Slice(consumed);
            }
        }
    }

    private static void Replies(byte[] data)
    {
        foreach (ReadOnlySequence<byte> sequence in new[] { new ReadOnlySequence<byte>(data), Segments.Split(data, data.Length / 3) })
        {
            var status = SmtpReplyParser.TryParse(sequence, out var reply, out var consumed);
            if (status == ReplyParseStatus.Ok)
            {
                Guard.Check(reply is not null && reply.Code is >= 200 and <= 599, "an accepted reply has a code in 2xx-5xx");
                long used = sequence.Slice(sequence.Start, consumed).Length;
                Guard.Check(used > 0 && used <= sequence.Length, "reply consumed out of range");
                _ = reply!.ToString();
            }
        }
    }

    private static void DataScan(byte[] data)
    {
        var whole = new ArrayBufferWriter<byte>();
        var scanner = new DataScanner();
        var wholeStatus = scanner.Scan(data, whole, out int wholeConsumed);
        Guard.Check(wholeConsumed >= 0 && wholeConsumed <= data.Length, "DATA scanner consumed out of range");
        if (wholeStatus == DataScanStatus.NeedMoreData)
        {
            Guard.Check(wholeConsumed == data.Length, "NeedMoreData must have consumed everything");
        }

        // Resume at pseudo-random boundaries derived from the data itself.
        var parts = new ArrayBufferWriter<byte>();
        var resumed = new DataScanner();
        DataScanStatus status = DataScanStatus.NeedMoreData;
        int position = 0;
        int step = 1 + (data.Length == 0 ? 0 : data[0] % 7);
        while (position < data.Length && status == DataScanStatus.NeedMoreData)
        {
            int take = Math.Min(step, data.Length - position);
            status = resumed.Scan(data.AsSpan(position, take), parts, out int consumed);
            position += consumed == take ? take : consumed;
            if (status != DataScanStatus.NeedMoreData)
            {
                break;
            }

            step = 1 + ((step * 5) + position) % 11;
        }

        Guard.Check(status == wholeStatus, $"DATA scanner status differs when resumed: {wholeStatus} vs {status}");
        Guard.Check(parts.WrittenSpan.SequenceEqual(whole.WrittenSpan), "DATA scanner output differs when resumed at other boundaries");
        Guard.Check(resumed.BytesWritten == whole.WrittenCount && scanner.BytesWritten == whole.WrittenCount, "BytesWritten disagrees with the output");
    }

    private static byte[] Bytes(string s) => Encoding.Latin1.GetBytes(s);

    private static string Latin1(byte[] data) => Encoding.Latin1.GetString(data);
}

/// <summary>Builds a multi-segment <see cref="ReadOnlySequence{T}"/> for tests of code that has a separate path for segment boundaries.</summary>
internal static class Segments
{
    public static ReadOnlySequence<byte> Split(byte[] data, int at)
    {
        if (data.Length < 2 || at <= 0 || at >= data.Length)
        {
            return new ReadOnlySequence<byte>(data);
        }

        var first = new Segment(data.AsMemory(0, at), 0);
        var last = first.Append(data.AsMemory(at));
        return new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
    }

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public Segment(ReadOnlyMemory<byte> memory, long runningIndex)
        {
            Memory = memory;
            RunningIndex = runningIndex;
        }

        public Segment Append(ReadOnlyMemory<byte> memory)
        {
            var next = new Segment(memory, RunningIndex + Memory.Length);
            Next = next;
            return next;
        }
    }
}
