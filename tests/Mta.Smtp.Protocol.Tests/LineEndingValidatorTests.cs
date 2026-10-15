using System.Text;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Protocol.Tests;

public class LineEndingValidatorTests
{
    private static LineEndingStatus Run(string input, int piece = int.MaxValue, bool rejectNul = true)
    {
        var validator = new LineEndingValidator(rejectNul);
        byte[] bytes = Encoding.Latin1.GetBytes(input);
        for (int pos = 0; pos < bytes.Length; pos += piece)
        {
            var status = validator.Check(bytes.AsSpan(pos, Math.Min(piece, bytes.Length - pos)));
            if (status != LineEndingStatus.Ok)
            {
                return status;
            }
        }

        return validator.Complete();
    }

    [Theory]
    [InlineData("")]
    [InlineData("no line ending at all")]
    [InlineData("Subject: x\r\n\r\nbody\r\n")]
    [InlineData("\r\n\r\n\r\n")]
    [InlineData("a\r\nb\r\nc")]
    [InlineData("QUIT\r\n.\r\nMAIL FROM:<a@b.c>\r\n")]   // commands and dots inside a BDAT body are only data
    public void Well_formed_bodies_are_accepted_at_every_split_point(string input)
    {
        foreach (int piece in new[] { int.MaxValue, 1, 2, 3, 5 })
        {
            Assert.Equal(LineEndingStatus.Ok, Run(input, piece));
        }
    }

    [Theory]
    [InlineData("a\nb", LineEndingStatus.BareLf)]
    [InlineData("\n", LineEndingStatus.BareLf)]
    [InlineData("a\r\nb\n.\r\n", LineEndingStatus.BareLf)]
    [InlineData("a\rb", LineEndingStatus.BareCr)]
    [InlineData("a\r", LineEndingStatus.BareCr)]
    [InlineData("a\r\r\n", LineEndingStatus.BareCr)]
    [InlineData("a\r.\r\n", LineEndingStatus.BareCr)]
    [InlineData("a\0b", LineEndingStatus.Nul)]
    public void Bare_line_endings_and_nul_are_found_at_every_split_point(string input, LineEndingStatus expected)
    {
        foreach (int piece in new[] { int.MaxValue, 1, 2, 3, 5 })
        {
            Assert.Equal(expected, Run(input, piece));
        }
    }

    [Fact]
    public void A_cr_at_the_end_of_one_piece_and_the_lf_at_the_start_of_the_next_is_one_line_ending()
    {
        var validator = new LineEndingValidator();
        Assert.Equal(LineEndingStatus.Ok, validator.Check("abc\r"u8));
        Assert.Equal(LineEndingStatus.Ok, validator.Check("\ndef"u8));
        Assert.Equal(LineEndingStatus.Ok, validator.Complete());
    }

    [Fact]
    public void Nul_can_be_allowed_by_option()
    {
        Assert.Equal(LineEndingStatus.Ok, Run("a\0b\r\n", rejectNul: false));
        Assert.Equal(LineEndingStatus.BareLf, Run("a\0b\n", rejectNul: false));
    }

    [Fact]
    public void The_verdict_agrees_with_the_data_scanner_for_random_bodies_at_random_splits()
    {
        var rng = new Random(20261015);
        byte[] alphabet = "ab.\r\n\0"u8.ToArray();
        for (int round = 0; round < 3000; round++)
        {
            byte[] body = new byte[rng.Next(0, 40)];
            for (int i = 0; i < body.Length; i++)
            {
                body[i] = alphabet[rng.Next(alphabet.Length)];
            }

            // DATA ends with CRLF.CRLF: the scanner's verdict on the body followed by the terminator is the reference. A body that has no
            // violation completes, one that has stops with the violation (or is cut short by a premature terminator, which a BDAT body cannot contain
            // as a special sequence, so those are skipped).
            var scanner = new DataScanner(rejectNul: true);
            var sink = new System.Buffers.ArrayBufferWriter<byte>();
            byte[] framed = [.. body, .. "\r\n.\r\n"u8.ToArray()];
            DataScanStatus reference = scanner.Scan(framed, sink, out _);
            if (reference == DataScanStatus.Complete && sink.WrittenCount != body.Length + 2)
            {
                continue;   // the body itself held CRLF.CRLF: DATA ends there, BDAT does not
            }

            string text = Encoding.Latin1.GetString(body);
            LineEndingStatus actual = Run(text, rng.Next(1, 8));
            LineEndingStatus expected = reference switch
            {
                DataScanStatus.BareLf => LineEndingStatus.BareLf,
                DataScanStatus.BareCr => LineEndingStatus.BareCr,
                DataScanStatus.Nul => LineEndingStatus.Nul,
                _ => LineEndingStatus.Ok,
            };
            // The first violation can differ in kind when a body has several; both must agree on whether there is one.
            Assert.True(expected == LineEndingStatus.Ok == (actual == LineEndingStatus.Ok), $"body {Convert.ToHexString(body)}: scanner {reference}, validator {actual}");
        }
    }
}
