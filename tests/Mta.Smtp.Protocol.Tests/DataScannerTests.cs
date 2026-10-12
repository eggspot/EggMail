using System.Buffers;
using System.Text;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Protocol.Tests;

public class DataScannerTests
{
    private static (DataScanStatus Status, string Body, int Consumed) ScanAll(string input, int chunk = int.MaxValue, bool rejectNul = true)
    {
        var scanner = new DataScanner(rejectNul);
        var output = new ArrayBufferWriter<byte>();
        byte[] bytes = Encoding.Latin1.GetBytes(input);
        int pos = 0;
        DataScanStatus status = DataScanStatus.NeedMoreData;
        while (pos < bytes.Length)
        {
            int take = Math.Min(chunk, bytes.Length - pos);
            status = scanner.Scan(bytes.AsSpan(pos, take), output, out int used);
            pos += used;
            if (status != DataScanStatus.NeedMoreData)
            {
                break;
            }
        }

        return (status, Encoding.Latin1.GetString(output.WrittenSpan), pos);
    }

    [Fact]
    public void Simple_message_completes_and_keeps_trailing_crlf()
    {
        var r = ScanAll("Subject: hi\r\n\r\nHello\r\n.\r\n");
        Assert.Equal(DataScanStatus.Complete, r.Status);
        Assert.Equal("Subject: hi\r\n\r\nHello\r\n", r.Body);
    }

    [Fact]
    public void Unstuffs_leading_dots()
    {
        var r = ScanAll("a\r\n..b\r\n...\r\n.\r\n");
        Assert.Equal(DataScanStatus.Complete, r.Status);
        Assert.Equal("a\r\n.b\r\n..\r\n", r.Body);
    }

    [Fact]
    public void Empty_body_terminator_only()
    {
        var r = ScanAll(".\r\n");
        Assert.Equal(DataScanStatus.Complete, r.Status);
        Assert.Equal("", r.Body);
    }

    [Fact]
    public void Does_not_consume_pipelined_bytes_after_terminator()
    {
        string input = "x\r\n.\r\nQUIT\r\n";
        var r = ScanAll(input);
        Assert.Equal(DataScanStatus.Complete, r.Status);
        Assert.Equal(input.Length - "QUIT\r\n".Length, r.Consumed);
    }

    [Theory]
    [InlineData("a\nb\r\n.\r\n")]            // bare LF
    [InlineData("a\r\nb\n.\r\n")]
    [InlineData("a\r\n.\n")]                 // LF-dot-LF smuggling
    [InlineData("a\n.\n")]
    public void Bare_lf_is_rejected(string input)
    {
        Assert.Equal(DataScanStatus.BareLf, ScanAll(input).Status);
    }

    [Theory]
    [InlineData("a\rb\r\n.\r\n")]            // bare CR
    [InlineData("a\r\n.\rX")]                // dot CR not LF
    [InlineData("a\r\r\n.\r\n")]
    public void Bare_cr_is_rejected(string input)
    {
        Assert.Equal(DataScanStatus.BareCr, ScanAll(input).Status);
    }

    [Fact]
    public void Smuggling_sequences_never_terminate_early()
    {
        // Classic smuggling payloads: "\n.\r\n", "\r.\r\n", "\n.\n" must be errors, never a terminator.
        foreach (string payload in new[] { "x\n.\r\nMAIL FROM:<a@b.c>\r\n", "x\r.\r\n", "x\r\n.\r\r\n", "x\n.\n" })
        {
            var status = ScanAll(payload).Status;
            Assert.NotEqual(DataScanStatus.Complete, status);
            Assert.NotEqual(DataScanStatus.NeedMoreData, status);
        }
    }

    [Fact]
    public void Nul_is_rejected_unless_allowed()
    {
        Assert.Equal(DataScanStatus.Nul, ScanAll("a\0b\r\n.\r\n").Status);
        Assert.Equal(DataScanStatus.Complete, ScanAll("a\0b\r\n.\r\n", rejectNul: false).Status);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(7)]
    public void Result_is_independent_of_chunking(int chunk)
    {
        string input = "H: v\r\n\r\n.dot first\r\n..two\r\nbody\r\n\r\n.\r\n";
        var whole = ScanAll(input);
        var split = ScanAll(input, chunk);
        Assert.Equal(whole.Status, split.Status);
        Assert.Equal(whole.Body, split.Body);
    }

    [Fact]
    public void Randomized_chunking_matches_single_pass()
    {
        var rng = new Random(7);
        for (int i = 0; i < 2000; i++)
        {
            var sb = new StringBuilder();
            int lines = rng.Next(0, 8);
            for (int l = 0; l < lines; l++)
            {
                if (rng.Next(3) == 0) { sb.Append('.'); }
                sb.Append(new string('a', rng.Next(0, 5)));
                sb.Append(rng.Next(12) == 0 ? "\n" : rng.Next(15) == 0 ? "\r" : "\r\n");
            }

            sb.Append(rng.Next(4) == 0 ? "." : ".\r\n");
            string input = sb.ToString();
            var whole = ScanAll(input);
            var split = ScanAll(input, rng.Next(1, 6));
            Assert.Equal(whole.Status, split.Status);
            if (whole.Status == DataScanStatus.Complete)
            {
                Assert.Equal(whole.Body, split.Body);
            }
        }
    }
}
