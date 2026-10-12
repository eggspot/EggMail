using System.Security.Cryptography;
using System.Text;

namespace Mta.Dkim.Tests;

public class KeyToolsTests
{
    [Fact]
    public void Generated_key_is_2048_bits_and_round_trips_through_pem()
    {
        using var key = DkimKeyTools.GenerateRsa2048();
        Assert.Equal(2048, key.KeySize);

        string pem = DkimKeyTools.ExportPrivateKeyPem(key);
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pem);
        using var loaded = DkimKeyTools.LoadPrivateKeyPem(pem);
        Assert.Equal(key.ExportSubjectPublicKeyInfo(), loaded.ExportSubjectPublicKeyInfo());

        using var fromDer = DkimKeyTools.LoadPrivateKeyDer(DkimKeyTools.ExportPrivateKeyDer(key));
        Assert.Equal(key.ExportSubjectPublicKeyInfo(), fromDer.ExportSubjectPublicKeyInfo());
    }

    [Fact]
    public void Pkcs1_pem_and_der_are_accepted_too()
    {
        using var loaded = DkimKeyTools.LoadPrivateKeyPem(TestKeys.Rsa2048.ExportRSAPrivateKeyPem());
        Assert.Equal(2048, loaded.KeySize);
        using var der = DkimKeyTools.LoadPrivateKeyDer(TestKeys.Rsa2048.ExportRSAPrivateKey());
        Assert.Equal(2048, der.KeySize);
    }

    [Fact]
    public void Garbage_key_material_is_reported_as_dkim_exception()
    {
        Assert.Throws<DkimException>(() => DkimKeyTools.LoadPrivateKeyPem("-----BEGIN PRIVATE KEY-----\r\nAAAA\r\n-----END PRIVATE KEY-----"));
        Assert.Throws<DkimException>(() => DkimKeyTools.LoadPrivateKeyDer(new byte[100]));
    }

    [Fact]
    public void Generate_with_explicit_size_validates_range()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => DkimKeyTools.GenerateRsa(512));
        Assert.Throws<ArgumentOutOfRangeException>(() => DkimKeyTools.GenerateRsa(8192));
        using var k = DkimKeyTools.GenerateRsa(1024);
        Assert.Equal(1024, k.KeySize);
    }

    [Fact]
    public void Txt_value_has_the_dkim_format_and_parses_back()
    {
        string txt = DkimKeyTools.FormatDnsTxtValue(TestKeys.Rsa2048);
        Assert.StartsWith("v=DKIM1; k=rsa; p=MII", txt);
        Assert.Equal("v=DKIM1; k=rsa; p=" + DkimKeyTools.ExportPublicKeyBase64(TestKeys.Rsa2048), txt);

        Assert.True(DkimKeyRecord.TryParse(txt, out var record, out string? error), error);
        Assert.Equal("DKIM1", record!.Version);
        Assert.Equal("rsa", record.KeyType);
        Assert.False(record.IsRevoked);
        Assert.Equal(TestKeys.Rsa2048.ExportSubjectPublicKeyInfo(), record.PublicKeySubjectPublicKeyInfo);
    }

    [Fact]
    public void Long_txt_values_split_into_255_character_strings_and_join_back()
    {
        string txt = DkimKeyTools.FormatDnsTxtValue(TestKeys.Rsa2048);
        Assert.True(txt.Length > 255);

        var parts = DkimKeyTools.SplitTxtValue(txt);
        Assert.True(parts.Count >= 2);
        Assert.All(parts, p => Assert.True(p.Length is > 0 and <= 255));
        Assert.Equal(txt, string.Concat(parts));
        Assert.Equal(255, parts[0].Length);

        string quoted = DkimKeyTools.FormatDnsTxtQuoted(txt);
        Assert.StartsWith("\"v=DKIM1; k=rsa; p=", quoted);
        Assert.Equal(parts.Count, quoted.Count(c => c == '"') / 2);
        Assert.Equal(txt, DkimKeyTools.JoinQuotedStrings(quoted));

        Assert.True(DkimKeyTools.TryParseDnsTxtValue(quoted, out var record, out string? error), error);
        Assert.Equal(TestKeys.Rsa2048.ExportSubjectPublicKeyInfo(), record!.PublicKeySubjectPublicKeyInfo);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(100)]
    [InlineData(255)]
    public void Split_respects_a_custom_chunk_size(int size)
    {
        string txt = DkimKeyTools.FormatDnsTxtValue(TestKeys.Rsa1024);
        var parts = DkimKeyTools.SplitTxtValue(txt, size);
        Assert.All(parts, p => Assert.True(p.Length <= size));
        Assert.Equal(txt, string.Concat(parts));
    }

    [Fact]
    public void Split_rejects_invalid_sizes_and_handles_empty_text()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => DkimKeyTools.SplitTxtValue("x", 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => DkimKeyTools.SplitTxtValue("x", 256));
        Assert.Equal([string.Empty], DkimKeyTools.SplitTxtValue(string.Empty));
    }

    [Theory]
    [InlineData("\"abc\" \"def\"", "abcdef")]
    [InlineData("\"a\\\"b\"", "a\"b")]
    [InlineData("\"a\\\\b\"", "a\\b")]
    [InlineData("  plain text  ", "plain text")]
    [InlineData("\"unterminated", "unterminated")]
    [InlineData("\"\"", "")]
    [InlineData("junk \"in\" between \"quotes\"", "inquotes")]
    public void Joining_quoted_strings(string input, string expected) =>
        Assert.Equal(expected, DkimKeyTools.JoinQuotedStrings(input));

    [Fact]
    public void Dns_name_and_selector_suggestions()
    {
        Assert.Equal("sel._domainkey.example.com", DkimKeyTools.GetDnsName("example.com.", "sel"));
        Assert.Equal("egg202610", DkimKeyTools.SuggestSelector(new DateTimeOffset(2026, 10, 12, 0, 0, 0, TimeSpan.Zero)));
        Assert.Equal("mail202602", DkimKeyTools.SuggestSelector(new DateTimeOffset(2026, 1, 31, 23, 0, 0, TimeSpan.FromHours(-2)), "mail")); // the month is taken in UTC
        Assert.Throws<ArgumentException>(() => DkimKeyTools.SuggestSelector(Msg.Now, "bad prefix"));
        Assert.Throws<ArgumentException>(() => DkimKeyTools.SuggestSelector(Msg.Now, "a.b"));
        Assert.True(DkimKeyTools.TryParseDnsTxtValue(DkimKeyTools.FormatDnsTxtValue(TestKeys.Rsa2048), out _, out _));
    }

    [Fact]
    public void Key_record_flags_and_lists_are_parsed()
    {
        Assert.True(DkimKeyRecord.TryParse("v=DKIM1; h=sha1:SHA256; k=RSA; n=hello world; p=; s=email:*; t=y:s", out var r, out string? error), error);
        Assert.Equal("rsa", r!.KeyType);
        Assert.Equal(["sha1", "sha256"], r.HashAlgorithms!);
        Assert.Equal(["email", "*"], r.ServiceTypes!);
        Assert.Equal(["y", "s"], r.Flags);
        Assert.True(r.IsTesting);
        Assert.True(r.IsStrictIdentity);
        Assert.True(r.IsRevoked);
        Assert.True(r.AllowsSha256);
        Assert.True(r.AllowsEmail);
        Assert.Equal("hello world", r.Notes);
    }

    [Fact]
    public void Key_record_without_version_is_accepted_and_with_wrong_version_rejected()
    {
        Assert.True(DkimKeyRecord.TryParse("k=rsa; p=AAAA", out var r, out _));
        Assert.Null(r!.Version);
        Assert.False(DkimKeyRecord.TryParse("v=DKIM2; p=AAAA", out _, out string? error));
        Assert.Contains("version", error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("p")]
    [InlineData("p=AAAA=B")]
    [InlineData("v=DKIM1")]
    [InlineData("p=%%%")]
    [InlineData("1=2")]
    public void Invalid_key_records_are_rejected_without_exceptions(string? text)
    {
        Assert.False(DkimKeyRecord.TryParse(text, out var r, out string? error));
        Assert.Null(r);
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void Non_ascii_and_oversized_key_records_are_rejected()
    {
        Assert.False(DkimKeyRecord.TryParse("v=DKIM1; p=AAAA; n=é", out _, out _));
        Assert.False(DkimKeyRecord.TryParse("v=DKIM1; p=" + new string('A', DkimKeyRecord.MaxRecordLength), out _, out _));
        Assert.False(DkimKeyRecord.TryParse("v=DKIM1; p=" + new string('A', 2000), out _, out _)); // decodes to more than 1024 bytes
    }

    [Fact]
    public void Base64_with_folding_whitespace_in_p_is_accepted()
    {
        string b64 = DkimKeyTools.ExportPublicKeyBase64(TestKeys.Rsa2048);
        string folded = string.Join(" \r\n\t", Enumerable.Range(0, (b64.Length + 59) / 60).Select(i => b64.Substring(i * 60, Math.Min(60, b64.Length - (i * 60)))));
        Assert.True(DkimKeyRecord.TryParse("v=DKIM1; k=rsa; p=" + folded, out var r, out string? error), error);
        Assert.Equal(TestKeys.Rsa2048.ExportSubjectPublicKeyInfo(), r!.PublicKeySubjectPublicKeyInfo);
    }
}
