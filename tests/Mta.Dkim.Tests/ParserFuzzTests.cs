using System.Text;
using Mta.Dkim.Internal;

namespace Mta.Dkim.Tests;

/// <summary>Deterministic (seeded) robustness tests for the parsers that handle attacker controlled bytes.</summary>
public class ParserFuzzTests
{
    private static readonly string[] Fragments =
    [
        "v", "=", "1", ";", " ", "\t", "\r\n", "\r\n ", "a", "rsa-sha256", "d", "example.com", "s", "sel", "h", "from:to", "bh", "b", "AAAA", "==",
        "p", "MIIB", "k", "t", "y", "x", "l", "999999999999999999999", "-", "_", "\0", "é", ":", "\"", "\\", ";;", "=;", "z", "dkim-signature",
    ];

    private static byte[] RandomBytes(Random rng, int max)
    {
        var bytes = new byte[rng.Next(0, max)];
        rng.NextBytes(bytes);
        return bytes;
    }

    private static string RandomTagish(Random rng)
    {
        var sb = new StringBuilder();
        int n = rng.Next(0, 40);
        for (int i = 0; i < n; i++) { sb.Append(Fragments[rng.Next(Fragments.Length)]); }
        return sb.ToString();
    }

    [Fact]
    public void Tag_list_parser_survives_random_bytes_and_keeps_offsets_in_range()
    {
        var rng = new Random(1);
        var entries = new TagEntry[16];
        for (int i = 0; i < 20000; i++)
        {
            byte[] input = i % 2 == 0 ? RandomBytes(rng, 200) : Encoding.Latin1.GetBytes(RandomTagish(rng));
            int start = input.Length == 0 ? 0 : rng.Next(0, input.Length);
            bool ok = TagListParser.TryParse(input, start, entries, out int count, out string? error);
            Assert.True(count >= 0 && count <= entries.Length);
            if (!ok) { Assert.NotNull(error); }
            for (int e = 0; e < count; e++)
            {
                var t = entries[e];
                Assert.InRange(t.NameStart, 0, input.Length);
                Assert.InRange(t.NameStart + t.NameLength, 0, input.Length);
                Assert.InRange(t.ValueStart, 0, input.Length);
                Assert.InRange(t.ValueStart + t.ValueLength, 0, input.Length);
                Assert.InRange(t.RawValueStart, 0, input.Length);
                Assert.InRange(t.RawValueEnd, t.RawValueStart, input.Length);
                Assert.True(t.ValueStart >= t.RawValueStart && t.ValueStart + t.ValueLength <= t.RawValueEnd);
                Assert.True(t.NameLength > 0);
            }
        }
    }

    [Fact]
    public void Tag_list_parser_rejects_duplicates_and_overflow()
    {
        var entries = new TagEntry[3];
        Assert.False(TagListParser.TryParse("a=1; b=2; a=3"u8, 0, entries, out _, out string? e1));
        Assert.Equal("duplicate tag", e1);
        Assert.False(TagListParser.TryParse("a=1; b=2; c=3; d=4"u8, 0, entries, out _, out string? e2));
        Assert.Equal("too many tags", e2);
        Assert.True(TagListParser.TryParse("a=1; b=2; c=3;"u8, 0, entries, out int count, out _));
        Assert.Equal(3, count);
    }

    [Theory]
    [InlineData("a=1;b=2", 2)]
    [InlineData(" a = 1 ; b = 2 ; ", 2)]
    [InlineData("a=1;;b=2", 2)]
    [InlineData("a=\r\n b\r\n c;", 1)]
    [InlineData("", 0)]
    [InlineData(" \r\n ", 0)]
    [InlineData("a=;", 1)]
    [InlineData("a_1=x", 1)]
    public void Tag_list_parser_accepts_well_formed_lists(string text, int expected)
    {
        var entries = new TagEntry[8];
        Assert.True(TagListParser.TryParse(Encoding.ASCII.GetBytes(text), 0, entries, out int count, out string? error), error);
        Assert.Equal(expected, count);
    }

    [Theory]
    [InlineData("a")]
    [InlineData("=1")]
    [InlineData("1a=1")]
    [InlineData("a b=1")]
    [InlineData("a=\u0001")]
    [InlineData("a=é")]
    [InlineData("a=1; ;b")]
    public void Tag_list_parser_rejects_malformed_lists(string text)
    {
        var entries = new TagEntry[8];
        Assert.False(TagListParser.TryParse(Encoding.Latin1.GetBytes(text), 0, entries, out _, out string? error));
        Assert.NotNull(error);
    }

    [Fact]
    public void Value_trimming_keeps_internal_folding()
    {
        var input = "a= \r\n x \r\n y \r\n ;"u8.ToArray();
        var entries = new TagEntry[2];
        Assert.True(TagListParser.TryParse(input, 0, entries, out int count, out _));
        Assert.Equal(1, count);
        Assert.Equal("x \r\n y", Encoding.ASCII.GetString(TagListParser.Value(input, entries[0])));
    }

    [Fact]
    public void Key_record_parser_survives_random_input()
    {
        var rng = new Random(2);
        for (int i = 0; i < 20000; i++)
        {
            string text = i % 3 == 0 ? Encoding.Latin1.GetString(RandomBytes(rng, 300)) : RandomTagish(rng);
            bool ok = DkimKeyRecord.TryParse(text, out var record, out string? error);
            Assert.Equal(ok, record is not null);
            Assert.Equal(!ok, error is not null);
        }
    }

    [Fact]
    public void Key_record_parser_survives_mutations_of_a_real_record()
    {
        string real = DkimKeyTools.FormatDnsTxtValue(TestKeys.Rsa2048) + "; t=y; h=sha256; s=email";
        var rng = new Random(3);
        for (int i = 0; i < 5000; i++)
        {
            var chars = real.ToCharArray();
            int edits = rng.Next(1, 6);
            for (int e = 0; e < edits; e++) { chars[rng.Next(chars.Length)] = (char)rng.Next(0, 160); }
            string text = rng.Next(5) == 0 ? new string(chars, 0, rng.Next(chars.Length)) : new string(chars);
            _ = DkimKeyRecord.TryParse(text, out _, out _);
        }
    }

    [Fact]
    public void Signature_parser_survives_random_input()
    {
        var rng = new Random(4);
        for (int i = 0; i < 20000; i++)
        {
            string tags = RandomTagish(rng);
            byte[] field = Encoding.Latin1.GetBytes("DKIM-Signature: " + tags);
            var sig = DkimSignatureHeader.Parse(field, 14, 16384);
            Assert.True(sig.HasError || (sig.Domain is not null && sig.Selector is not null && sig.Signature.Length > 0 && sig.BodyHash.Length == 32 && sig.SignedHeaderNames.Length > 0));
            if (!sig.HasError)
            {
                Assert.InRange(sig.BValueStart, 0, field.Length);
                Assert.InRange(sig.BValueEnd, sig.BValueStart, field.Length);
            }
        }
    }

    [Fact]
    public void Signature_parser_survives_mutations_of_a_real_signature()
    {
        string signed = Msg.Sign(Msg.Signer(), Msg.Simple());
        string real = signed.Substring(0, signed.IndexOf("\r\nFrom:", StringComparison.Ordinal));
        var rng = new Random(5);
        for (int i = 0; i < 10000; i++)
        {
            var bytes = Encoding.Latin1.GetBytes(real);
            int edits = rng.Next(1, 5);
            for (int e = 0; e < edits; e++) { bytes[rng.Next(bytes.Length)] = (byte)rng.Next(256); }
            var field = rng.Next(4) == 0 ? bytes.AsSpan(0, rng.Next(bytes.Length)) : bytes;
            int colon = field.IndexOf((byte)':');
            var sig = DkimSignatureHeader.Parse(field, Math.Max(colon, 0), 16384);
            if (!sig.HasError) { Assert.InRange(sig.BValueEnd, sig.BValueStart, field.Length); }
        }
    }

    [Fact]
    public void Header_table_survives_random_messages()
    {
        var rng = new Random(6);
        for (int i = 0; i < 10000; i++)
        {
            byte[] msg = i % 2 == 0 ? RandomBytes(rng, 400) : Encoding.Latin1.GetBytes(RandomTagish(rng));
            var table = HeaderTable.Parse(msg, 64);
            try
            {
                Assert.InRange(table.BodyOffset, 0, msg.Length);
                Assert.True(table.Count <= 64);
                int end = 0;
                for (int f = 0; f < table.Count; f++)
                {
                    var field = table[f];
                    Assert.True(field.Start >= end);
                    Assert.True(field.Length > 0 && field.Start + field.Length <= msg.Length);
                    Assert.InRange(field.NameLength, 0, field.Length);
                    end = field.Start + field.Length;
                }
            }
            finally
            {
                table.Dispose();
            }
        }
    }

    [Fact]
    public void Header_table_splits_fields_and_finds_the_body()
    {
        byte[] msg = Msg.Bytes("A: 1\r\nB : two\r\n continued\r\n\tmore\r\nNoColon\r\n\r\nbody\r\n");
        var table = HeaderTable.Parse(msg, 100);
        try
        {
            Assert.Equal(3, table.Count);
            Assert.Equal("A: 1\r\n", Msg.Text(table.Raw(msg, 0)));
            Assert.Equal("B : two\r\n continued\r\n\tmore\r\n", Msg.Text(table.Raw(msg, 1)));
            Assert.True(table.NameEquals(msg, 1, "b"u8));
            Assert.True(table.NameEquals(msg, 1, "B"));
            Assert.False(table.NameEquals(msg, 1, "b "u8));
            Assert.Equal(0, table[2].NameLength); // no colon: never matches a name
            Assert.Equal("body\r\n", Msg.Text(msg.AsSpan(table.BodyOffset)));
            Assert.False(table.TooManyFields);
        }
        finally
        {
            table.Dispose();
        }
    }

    [Fact]
    public void Header_table_reports_too_many_fields()
    {
        byte[] msg = Msg.Bytes(string.Concat(Enumerable.Repeat("X: 1\r\n", 50)) + "\r\n");
        var table = HeaderTable.Parse(msg, 10);
        try
        {
            Assert.True(table.TooManyFields);
            Assert.Equal(10, table.Count);
        }
        finally
        {
            table.Dispose();
        }
    }

    [Fact]
    public void Header_table_grows_beyond_its_initial_capacity()
    {
        byte[] msg = Msg.Bytes(string.Concat(Enumerable.Repeat("X: 1\r\n", 500)) + "\r\n");
        var table = HeaderTable.Parse(msg, 1000);
        try
        {
            Assert.Equal(500, table.Count);
            Assert.Equal(msg.Length, table.BodyOffset);
        }
        finally
        {
            table.Dispose();
        }
    }

    [Theory]
    [InlineData("a%3Db", "a%3Db")]   // only "=XX" is an escape in dkim-quoted-printable
    [InlineData("a=3Db", "a=b")]
    [InlineData("a=3D=3b", "a=;")]
    [InlineData("a b\r\n c", "abc")]
    public void Quoted_printable_decoding(string input, string expected)
    {
        Assert.True(TagListParser.TryDecodeQuotedPrintable(Encoding.ASCII.GetBytes(input), out string decoded));
        Assert.Equal(expected, decoded);
    }

    [Theory]
    [InlineData("a=")]
    [InlineData("a=4")]
    [InlineData("a=ZZ")]
    [InlineData("=C3")]       // invalid UTF-8
    public void Quoted_printable_rejects_bad_escapes(string input) =>
        Assert.False(TagListParser.TryDecodeQuotedPrintable(Encoding.ASCII.GetBytes(input), out _));

    [Fact]
    public void Base64_decoder_enforces_its_limit_and_validity()
    {
        Assert.True(TagListParser.TryDecodeBase64("QUJD"u8, 3, out var ok));
        Assert.Equal("ABC"u8.ToArray(), ok);
        Assert.False(TagListParser.TryDecodeBase64("QUJDREVG"u8, 3, out _));      // too long
        Assert.False(TagListParser.TryDecodeBase64("QUJ"u8, 10, out _));          // bad padding
        Assert.False(TagListParser.TryDecodeBase64("QU!D"u8, 10, out _));
        Assert.True(TagListParser.TryDecodeBase64("QU\r\n\tJD"u8, 10, out var folded));
        Assert.Equal("ABC"u8.ToArray(), folded);
        Assert.True(TagListParser.TryDecodeBase64(new byte[5000].AsSpan().ToArray().Select(_ => (byte)'A').ToArray(), 4000, out _));
        Assert.False(TagListParser.TryDecodeBase64(new byte[5000].AsSpan().ToArray().Select(_ => (byte)'A').ToArray(), 100, out _));
    }
}
