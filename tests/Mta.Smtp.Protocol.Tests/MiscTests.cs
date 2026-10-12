using System.Buffers;
using System.Text;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Protocol.Tests;

public class LineScannerTests
{
    private static LineStatus Get(string s, out string line, int max = 512)
    {
        var bytes = Encoding.ASCII.GetBytes(s);
        var st = SmtpLineScanner.TryGetLine(new ReadOnlySequence<byte>(bytes), max, new byte[max + 2], out var l, out _);
        line = Encoding.ASCII.GetString(l);
        return st;
    }

    [Fact]
    public void Reads_crlf_lines() { Assert.Equal(LineStatus.Ok, Get("NOOP\r\nrest", out var l)); Assert.Equal("NOOP", l); }

    [Fact]
    public void Incomplete() { Assert.Equal(LineStatus.Incomplete, Get("NOO", out _)); Assert.Equal(LineStatus.Incomplete, Get("NOOP\r", out _)); }

    [Fact]
    public void Bare_lf_and_cr_are_errors()
    {
        Assert.Equal(LineStatus.BareLf, Get("NOOP\n", out _));
        Assert.Equal(LineStatus.BareCr, Get("NO\rOP\r\n", out _));
        Assert.Equal(LineStatus.BareCr, Get("NO\rOP", out _));
    }

    [Fact]
    public void Too_long() { Assert.Equal(LineStatus.TooLong, Get(new string('a', 600), out _)); Assert.Equal(LineStatus.TooLong, Get(new string('a', 600) + "\r\n", out _)); }

    [Fact]
    public void Line_spanning_segments()
    {
        var a = new Seg(Encoding.ASCII.GetBytes("MAIL FR"));
        var b = a.Append(Encoding.ASCII.GetBytes("OM:<a@b.c>\r"));
        var c = b.Append(Encoding.ASCII.GetBytes("\nX"));
        var seq = new ReadOnlySequence<byte>(a, 0, c, c.Memory.Length);
        Assert.Equal(LineStatus.Ok, SmtpLineScanner.TryGetLine(seq, 512, new byte[600], out var line, out int consumed));
        Assert.Equal("MAIL FROM:<a@b.c>", Encoding.ASCII.GetString(line));
        Assert.Equal(19, consumed);
    }

    private sealed class Seg : ReadOnlySequenceSegment<byte>
    {
        public Seg(ReadOnlyMemory<byte> m) => Memory = m;
        public Seg Append(ReadOnlyMemory<byte> m) { var n = new Seg(m) { RunningIndex = RunningIndex + Memory.Length }; Next = n; return n; }
    }
}

public class DotStufferTests
{
    private static string Stuff(string message, int chunk = int.MaxValue)
    {
        var s = new DotStuffer();
        var w = new ArrayBufferWriter<byte>();
        byte[] bytes = Encoding.ASCII.GetBytes(message);
        for (int i = 0; i < bytes.Length; i += chunk)
        {
            Assert.True(s.Write(bytes.AsSpan(i, Math.Min(chunk, bytes.Length - i)), w));
        }

        Assert.True(s.Complete(w));
        return Encoding.ASCII.GetString(w.WrittenSpan);
    }

    [Fact]
    public void Stuffs_leading_dots_and_terminates()
    {
        Assert.Equal("a\r\n..b\r\n.\r\n", Stuff("a\r\n.b\r\n"));
        Assert.Equal("...\r\n.\r\n", Stuff("..\r\n"));
        Assert.Equal("..a\r\n.\r\n", Stuff(".a\r\n"));
    }

    [Fact]
    public void Adds_missing_final_crlf() => Assert.Equal("abc\r\n.\r\n", Stuff("abc"));

    [Fact]
    public void Empty_message() => Assert.Equal("\r\n.\r\n", Stuff(""));

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    public void Chunking_does_not_change_output(int chunk)
    {
        string m = "H: v\r\n\r\n.x\r\n..y\r\n\r\n.\r\nend";
        Assert.Equal(Stuff(m), Stuff(m, chunk));
    }

    [Fact]
    public void Refuses_bare_line_endings()
    {
        var w = new ArrayBufferWriter<byte>();
        Assert.False(new DotStuffer().Write("a\nb"u8, w));
        Assert.False(new DotStuffer().Write("a\rb"u8, w));
        Assert.False(new DotStuffer().Write("a\0b"u8, w));
    }

    [Fact]
    public void Roundtrips_through_scanner()
    {
        var rng = new Random(3);
        for (int i = 0; i < 500; i++)
        {
            var sb = new StringBuilder();
            for (int l = 0; l < rng.Next(0, 6); l++)
            {
                if (rng.Next(2) == 0) { sb.Append('.'); }
                sb.Append(new string('x', rng.Next(0, 4))).Append("\r\n");
            }

            string message = sb.ToString();
            string wire = Stuff(message);
            var scanner = new DataScanner();
            var outW = new ArrayBufferWriter<byte>();
            var status = scanner.Scan(Encoding.ASCII.GetBytes(wire), outW, out _);
            Assert.Equal(DataScanStatus.Complete, status);
            string back = Encoding.ASCII.GetString(outW.WrittenSpan);
            Assert.Equal(message.Length == 0 ? "\r\n" : message, back);
        }
    }
}

public class SaslTests
{
    [Fact]
    public void Plain_parse()
    {
        Assert.True(Sasl.TryParsePlain("\0user\0pa ss"u8, out var z, out var u, out var p));
        Assert.Equal("", z); Assert.Equal("user", u); Assert.Equal("pa ss", p);
        Assert.True(Sasl.TryParsePlain("admin\0user\0pw"u8, out z, out _, out _));
        Assert.Equal("admin", z);
    }

    [Theory]
    [InlineData("")]
    [InlineData("user\0pw")]
    [InlineData("\0\0pw")]
    [InlineData("\0user\0")]
    [InlineData("\0user\0a\0b")]
    public void Plain_rejects(string s) => Assert.False(Sasl.TryParsePlain(Encoding.UTF8.GetBytes(s), out _, out _, out _));

    [Fact]
    public void Base64_strict()
    {
        Assert.True(Sasl.TryDecodeBase64("dXNlcg==", out var d)); Assert.Equal("user", Encoding.ASCII.GetString(d));
        Assert.False(Sasl.TryDecodeBase64("dXNlcg", out _));
        Assert.False(Sasl.TryDecodeBase64("dXN lcg==", out _));
        Assert.False(Sasl.TryDecodeBase64("!!!!", out _));
    }

    [Theory]
    [InlineData("plain")]
    [InlineData("a+b=c")]
    [InlineData("ünï")]
    public void Xtext_roundtrip(string s)
    {
        Assert.True(Sasl.TryDecodeXtext(Sasl.EncodeXtext(s), out var back));
        Assert.Equal(s, back);
    }
}

public class SessionStateTests
{
    private static SmtpSessionState New(bool tls = false) =>
        new() { StartTlsAvailable = true, AuthAvailable = true, RequireAuthForMail = true, RequireTlsForMail = true, MaxRecipients = 2 };

    [Fact]
    public void Sequence_rules()
    {
        var s = New();
        Assert.Same(SmtpReplies.BadSequence, s.Check(SmtpVerb.Mail));
        s.OnGreeted(true);
        Assert.Same(SmtpReplies.TlsRequired, s.Check(SmtpVerb.Mail));
        Assert.Null(s.Check(SmtpVerb.StartTls));
        s.OnTlsEstablished();
        Assert.Same(SmtpReplies.BadSequence, s.Check(SmtpVerb.Mail)); // must re-greet
        s.OnGreeted(true);
        Assert.Same(SmtpReplies.AuthRequired, s.Check(SmtpVerb.Mail));
        Assert.Null(s.Check(SmtpVerb.Auth));
        s.OnAuthenticated();
        Assert.Same(SmtpReplies.BadSequence, s.Check(SmtpVerb.Auth));
        Assert.Null(s.Check(SmtpVerb.Mail));
        Assert.Same(SmtpReplies.BadSequence, s.Check(SmtpVerb.Rcpt));
        s.OnMailAccepted();
        Assert.Same(SmtpReplies.NoValidRecipients, s.Check(SmtpVerb.Data));
        s.OnRecipientAccepted(); s.OnRecipientAccepted();
        Assert.Same(SmtpReplies.TooManyRecipients, s.Check(SmtpVerb.Rcpt));
        Assert.Null(s.Check(SmtpVerb.Data));
        s.OnChunkingStarted();
        Assert.Same(SmtpReplies.BadSequence, s.Check(SmtpVerb.Data));
        s.ResetTransaction();
        Assert.Null(s.Check(SmtpVerb.Mail));
    }

    [Fact]
    public void Starttls_not_allowed_in_transaction_or_twice()
    {
        var s = new SmtpSessionState { StartTlsAvailable = true };
        s.OnGreeted(true);
        s.OnMailAccepted();
        Assert.Same(SmtpReplies.BadSequence, s.Check(SmtpVerb.StartTls));
        s.ResetTransaction();
        s.OnTlsEstablished();
        s.OnGreeted(true);
        Assert.Same(SmtpReplies.BadSequence, s.Check(SmtpVerb.StartTls));
    }
}
