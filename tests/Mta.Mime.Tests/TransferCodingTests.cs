using System.Buffers;
using System.Text;

namespace Mta.Mime.Tests;

public class TransferCodingTests
{
    private static byte[] Decode(string input, ContentTransferEncoding cte, out DecodeResult result, long max = long.MaxValue)
    {
        var writer = new ArrayBufferWriter<byte>();
        result = BodyDecoder.Decode(Encoding.Latin1.GetBytes(input), cte, writer, max);
        return writer.WrittenSpan.ToArray();
    }

    private static string DecodeStr(string input, ContentTransferEncoding cte) => Encoding.Latin1.GetString(Decode(input, cte, out _));

    // ---- base64

    [Theory]
    [InlineData("", "")]
    [InlineData("Zg==", "f")]
    [InlineData("Zm8=", "fo")]
    [InlineData("Zm9v", "foo")]
    [InlineData("Zm9vYg==", "foob")]
    [InlineData("Zm9vYmE=", "fooba")]
    [InlineData("Zm9vYmFy", "foobar")]
    [InlineData("Zm9v\r\nYmFy\r\n", "foobar")]
    [InlineData("Zm9v YmFy", "foobar")]
    [InlineData("  Zm9vYmFy  \n", "foobar")]
    public void Base64_decodes(string input, string expected) => Assert.Equal(expected, DecodeStr(input, ContentTransferEncoding.Base64));

    [Fact]
    public void Base64_truncated_data_yields_the_complete_bytes()
    {
        Assert.Equal("fo", DecodeStr("Zm8", ContentTransferEncoding.Base64));
        Assert.Equal("f", DecodeStr("Zg", ContentTransferEncoding.Base64));
        Assert.Equal("foo", DecodeStr("Zm9vZ", ContentTransferEncoding.Base64)); // single dangling sextet is dropped
        Decode("Zm8", ContentTransferEncoding.Base64, out var r);
        Assert.True(r.Anomalies.HasAny(MimeAnomaly.MalformedBase64));
    }

    [Fact]
    public void Base64_garbage_is_skipped_and_reported()
    {
        Assert.Equal("foobar", DecodeStr("Zm9v!!!YmFy###", ContentTransferEncoding.Base64));
        Decode("Zm9v!!!YmFy", ContentTransferEncoding.Base64, out var r);
        Assert.True(r.Anomalies.HasAny(MimeAnomaly.MalformedBase64));
    }

    [Fact]
    public void Base64_clean_data_has_no_anomaly()
    {
        Decode("Zm9vYmFy\r\n", ContentTransferEncoding.Base64, out var r);
        Assert.Equal(MimeAnomaly.None, r.Anomalies);
        Assert.Equal(6, r.BytesWritten);
    }

    [Fact]
    public void Base64_concatenated_streams_and_extra_padding()
    {
        Assert.Equal("foofoo", DecodeStr("Zm9vZm9v", ContentTransferEncoding.Base64));
        Assert.Equal("ffoo", DecodeStr("Zg==Zm9v", ContentTransferEncoding.Base64));
        Assert.Equal("f", DecodeStr("Zg======", ContentTransferEncoding.Base64));
    }

    [Fact]
    public void Base64_output_never_exceeds_three_quarters_of_input()
    {
        var rng = new Random(1);
        for (int i = 0; i < 200; i++)
        {
            var input = new byte[rng.Next(0, 300)];
            rng.NextBytes(input);
            var writer = new ArrayBufferWriter<byte>();
            BodyDecoder.Decode(input, ContentTransferEncoding.Base64, writer, long.MaxValue);
            Assert.True(writer.WrittenCount <= input.Length * 3 / 4 + 2);
        }
    }

    [Fact]
    public void Base64_chunking_does_not_change_the_result()
    {
        var data = new byte[1000];
        new Random(2).NextBytes(data);
        byte[] encoded = Encoding.ASCII.GetBytes(Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks));
        for (int step = 1; step < 200; step += 7)
        {
            var dec = new Base64Decoder();
            var output = new List<byte>();
            var buffer = new byte[Base64Decoder.GetMaxDecodedLength(step)];
            for (int i = 0; i < encoded.Length; i += step)
            {
                int n = dec.Decode(encoded.AsSpan(i, Math.Min(step, encoded.Length - i)), buffer);
                output.AddRange(buffer.AsSpan(0, n).ToArray());
            }

            var tail = new byte[4];
            output.AddRange(tail[..dec.Finish(tail)].ToArray());
            Assert.Equal(data, output.ToArray());
        }
    }

    // ---- quoted-printable

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("caf=C3=A9", "cafÃ©")]
    [InlineData("caf=c3=a9", "cafÃ©")]
    [InlineData("a=3Db", "a=b")]
    [InlineData("long =\r\nline", "long line")]
    [InlineData("long =\nline", "long line")]
    [InlineData("trailing   \r\nnext", "trailing\r\nnext")]
    [InlineData("trailing \t \nnext", "trailing\nnext")]
    [InlineData("keep  inner  spaces", "keep  inner  spaces")]
    [InlineData("tab\there", "tab\there")]
    [InlineData("end   ", "end")]
    public void Quoted_printable_decodes(string input, string expected) =>
        Assert.Equal(expected, DecodeStr(input, ContentTransferEncoding.QuotedPrintable));

    [Theory]
    [InlineData("a=ZZb", "a=ZZb")]
    [InlineData("a=Zb", "a=Zb")]
    [InlineData("a=4", "a=4")]
    [InlineData("a=", "a=")]
    [InlineData("a= b", "a= b")]
    [InlineData("a==41", "a=A")]
    public void Quoted_printable_malformed_escapes_are_kept_literally(string input, string expected)
    {
        Assert.Equal(expected, DecodeStr(input, ContentTransferEncoding.QuotedPrintable));
        Decode(input, ContentTransferEncoding.QuotedPrintable, out var r);
        Assert.True(r.Anomalies.HasAny(MimeAnomaly.MalformedQuotedPrintable), input);
    }

    [Fact]
    public void Quoted_printable_space_before_soft_break_is_data()
    {
        Assert.Equal("a b", DecodeStr("a =\r\nb", ContentTransferEncoding.QuotedPrintable));
    }

    [Fact]
    public void Quoted_printable_long_whitespace_runs_are_bounded()
    {
        string spaces = new string(' ', 1_000_000);
        var bytes = Decode("a" + spaces + "b", ContentTransferEncoding.QuotedPrintable, out _);
        Assert.Equal(1_000_002, bytes.Length);
        Assert.Empty(Decode(spaces, ContentTransferEncoding.QuotedPrintable, out _).Where(b => b != (byte)' ').ToArray());
    }

    [Fact]
    public void Quoted_printable_chunking_does_not_change_the_result()
    {
        string input = "Caf=C3=A9 =\r\nmenu   \r\nline=3D2 =4\r\nx=\r\ny =  \t\r\nend=";
        byte[] whole = Decode(input, ContentTransferEncoding.QuotedPrintable, out _);
        byte[] src = Encoding.Latin1.GetBytes(input);
        for (int step = 1; step <= src.Length; step++)
        {
            var dec = new QuotedPrintableDecoder();
            var output = new List<byte>();
            var buffer = new byte[QuotedPrintableDecoder.GetMaxDecodedLength(step)];
            for (int i = 0; i < src.Length; i += step)
            {
                int n = dec.Decode(src.AsSpan(i, Math.Min(step, src.Length - i)), buffer);
                output.AddRange(buffer.AsSpan(0, n).ToArray());
            }

            var tail = new byte[16];
            output.AddRange(tail[..dec.Finish(tail)].ToArray());
            Assert.Equal(whole, output.ToArray());
        }
    }

    // ---- identity, limits

    [Theory]
    [InlineData(ContentTransferEncoding.SevenBit)]
    [InlineData(ContentTransferEncoding.EightBit)]
    [InlineData(ContentTransferEncoding.Binary)]
    public void Identity_encodings_copy(ContentTransferEncoding cte) => Assert.Equal("a=3D\r\n\0b", DecodeStr("a=3D\r\n\0b", cte));

    [Fact]
    public void Unknown_encoding_is_identity_with_anomaly()
    {
        Assert.Equal("data", DecodeStr("data", ContentTransferEncoding.Unknown));
        Decode("data", ContentTransferEncoding.Unknown, out var r);
        Assert.True(r.Anomalies.HasAny(MimeAnomaly.UnknownTransferEncoding));
    }

    [Theory]
    [InlineData(ContentTransferEncoding.Base64)]
    [InlineData(ContentTransferEncoding.QuotedPrintable)]
    [InlineData(ContentTransferEncoding.SevenBit)]
    public void Size_limit_truncates_output(ContentTransferEncoding cte)
    {
        string input = cte == ContentTransferEncoding.Base64
            ? Convert.ToBase64String(new byte[10_000])
            : new string('a', 10_000);
        var bytes = Decode(input, cte, out var r, max: 100);
        Assert.Equal(100, bytes.Length);
        Assert.True(r.Truncated);
        Assert.True(r.Anomalies.HasAny(MimeAnomaly.DecodedSizeLimit));
    }

    [Fact]
    public void Exactly_at_the_limit_is_not_truncation()
    {
        Decode(new string('a', 100), ContentTransferEncoding.SevenBit, out var r, max: 100);
        Assert.False(r.Truncated);
        Assert.Equal(100, r.BytesWritten);
    }

    [Fact]
    public void Measure_counts_without_keeping_output()
    {
        var r = BodyDecoder.Measure(Encoding.ASCII.GetBytes(Convert.ToBase64String(new byte[100_000], Base64FormattingOptions.InsertLineBreaks)), ContentTransferEncoding.Base64);
        Assert.Equal(100_000, r.BytesWritten);
        Assert.Equal(10, BodyDecoder.Measure(Encoding.ASCII.GetBytes(new string('A', 100)), ContentTransferEncoding.Base64, 10).BytesWritten);
    }

    // ---- encoders

    [Fact]
    public void Base64_encoder_uses_76_column_lines()
    {
        var data = new byte[1000];
        new Random(3).NextBytes(data);
        var w = new ArrayBufferWriter<byte>();
        TransferEncoder.WriteBase64(data, w);
        string text = Encoding.ASCII.GetString(w.WrittenSpan);
        string[] lines = text.Split("\r\n");
        Assert.All(lines, l => Assert.True(l.Length <= 76));
        Assert.Equal(76, lines[0].Length);
        Assert.DoesNotContain("\n\n", text);
        Assert.Equal(data, Convert.FromBase64String(string.Concat(lines)));
        Assert.False(text.EndsWith("\r\n", StringComparison.Ordinal));
    }

    [Fact]
    public void Base64_encoder_empty()
    {
        var w = new ArrayBufferWriter<byte>();
        TransferEncoder.WriteBase64(ReadOnlySpan<byte>.Empty, w);
        Assert.Equal(0, w.WrittenCount);
    }

    [Theory]
    [InlineData("plain ascii\r\nsecond line")]
    [InlineData("café über")]
    [InlineData("trailing space \r\nand tab\t\r\n")]
    [InlineData("equals = sign")]
    [InlineData("bare\nlf lines\nhere")]
    [InlineData("\r\n\r\n")]
    [InlineData("")]
    [InlineData(".dot line\r\n.second")]
    public void Quoted_printable_round_trips(string text)
    {
        byte[] src = Encoding.UTF8.GetBytes(text);
        var w = new ArrayBufferWriter<byte>();
        TransferEncoder.WriteQuotedPrintable(src, w);
        string encoded = Encoding.ASCII.GetString(w.WrittenSpan);
        Assert.All(encoded.Split("\r\n"), l => Assert.True(l.Length <= 76, l));
        Assert.DoesNotContain(encoded.Split("\r\n"), l => l.EndsWith(' ') || l.EndsWith('\t'));

        var back = new ArrayBufferWriter<byte>();
        BodyDecoder.Decode(w.WrittenSpan, ContentTransferEncoding.QuotedPrintable, back, long.MaxValue);
        string expected = text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\n", "\r\n", StringComparison.Ordinal);
        Assert.Equal(expected, Encoding.UTF8.GetString(back.WrittenSpan));
    }

    [Fact]
    public void Quoted_printable_breaks_long_lines_without_splitting_escapes()
    {
        string text = new string('é', 500) + new string('a', 500) + new string('=', 200);
        var w = new ArrayBufferWriter<byte>();
        TransferEncoder.WriteQuotedPrintable(Encoding.UTF8.GetBytes(text), w);
        string encoded = Encoding.ASCII.GetString(w.WrittenSpan);
        foreach (string line in encoded.Split("\r\n"))
        {
            Assert.True(line.Length <= 76);
            // an escape never straddles a soft break
            Assert.DoesNotMatch(@"=[0-9A-F]?$", line.EndsWith('=') ? line[..^1] : "x");
        }

        var back = new ArrayBufferWriter<byte>();
        BodyDecoder.Decode(w.WrittenSpan, ContentTransferEncoding.QuotedPrintable, back, long.MaxValue);
        Assert.Equal(text, Encoding.UTF8.GetString(back.WrittenSpan));
    }

    [Fact]
    public void Choose_transfer_encoding_for_text()
    {
        Assert.Equal(ContentTransferEncoding.SevenBit, TransferEncoder.ChooseForText("hello\r\nworld"u8, false));
        Assert.Equal(ContentTransferEncoding.QuotedPrintable, TransferEncoder.ChooseForText(Encoding.UTF8.GetBytes("hello café world"), false));
        Assert.Equal(ContentTransferEncoding.EightBit, TransferEncoder.ChooseForText(Encoding.UTF8.GetBytes("hello café world"), true));
        Assert.Equal(ContentTransferEncoding.Base64, TransferEncoder.ChooseForText(Encoding.UTF8.GetBytes("世界世界"), false));
        Assert.Equal(ContentTransferEncoding.QuotedPrintable, TransferEncoder.ChooseForText(Encoding.ASCII.GetBytes(new string('a', 2000)), false));
        Assert.Equal(ContentTransferEncoding.QuotedPrintable, TransferEncoder.ChooseForText(Encoding.UTF8.GetBytes(new string('a', 2000) + "é"), true));
        Assert.Equal(ContentTransferEncoding.Base64, TransferEncoder.ChooseForText("a\0b"u8, false));
    }
}
