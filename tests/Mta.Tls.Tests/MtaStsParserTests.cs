using Mta.Dns;
using Mta.Tls.MtaSts;

namespace Mta.Tls.Tests;

public class MtaStsTxtParserTests
{
    [Theory]
    [InlineData("v=STSv1; id=20190429T010101", "20190429T010101")]
    [InlineData("v=STSv1;id=abc", "abc")]
    [InlineData("  v=STSv1 ;  id = abc123 ; ", "abc123")]
    [InlineData("v=STSv1; id=abc; future=ignored", "abc")]
    [InlineData("v=STSv1; id=0123456789012345678901234567890a", "0123456789012345678901234567890a")]
    public void Valid_records_parse(string text, string id)
    {
        Assert.True(MtaStsTxtParser.TryParse(text, out var record));
        Assert.Equal(id, record!.Id);
    }

    [Theory]
    [InlineData("")]
    [InlineData("v=STSv1")]
    [InlineData("v=STSv1;")]
    [InlineData("v=STSv2; id=abc")]
    [InlineData("id=abc; v=STSv1")]
    [InlineData("v=STSv1; id=")]
    [InlineData("v=STSv1; id=has space")]
    [InlineData("v=STSv1; id=with-dash")]
    [InlineData("v=STSv1; id=01234567890123456789012345678901a")]
    [InlineData("v=STSv1; id=abc; id=def")]
    [InlineData("v=STSv1; garbage")]
    [InlineData("=STSv1; id=abc")]
    public void Invalid_records_are_rejected(string text)
    {
        Assert.False(MtaStsTxtParser.TryParse(text, out var record));
        Assert.Null(record);
    }

    [Fact]
    public void Null_and_oversized_input_are_rejected()
    {
        Assert.False(MtaStsTxtParser.TryParse(null, out _));
        Assert.False(MtaStsTxtParser.TryParse("v=STSv1; id=abc; x=" + new string('a', 2000), out _));
    }

    [Fact]
    public void Select_ignores_unrelated_txt_records()
    {
        var records = new[] { new TxtRecord("_mta-sts.example.com", 60, "something else"), new TxtRecord("_mta-sts.example.com", 60, "v=STSv1; id=x1") };
        Assert.Equal("x1", MtaStsTxtParser.Select(records)!.Id);
    }

    [Fact]
    public void Select_returns_nothing_for_multiple_sts_records()
    {
        var records = new[] { new TxtRecord("n", 60, "v=STSv1; id=a"), new TxtRecord("n", 60, "v=STSv1; id=b") };
        Assert.Null(MtaStsTxtParser.Select(records));
    }

    [Fact]
    public void Select_returns_nothing_for_single_invalid_record()
    {
        Assert.Null(MtaStsTxtParser.Select([new TxtRecord("n", 60, "v=STSv1; id=bad id")]));
        Assert.Null(MtaStsTxtParser.Select([]));
    }
}

public class MtaStsPolicyParserTests
{
    private const string Good = "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n";

    [Fact]
    public void Parses_a_crlf_policy()
    {
        Assert.True(MtaStsPolicyParser.TryParse(Good, out var p, out string? error), error);
        Assert.Equal(MtaStsMode.Enforce, p!.Mode);
        Assert.Equal(["mail.example.com", "*.example.net"], p.MxPatterns);
        Assert.Equal(604800, p.MaxAgeSeconds);
        Assert.Equal(["version: STSv1", "mode: enforce", "mx: mail.example.com", "mx: *.example.net", "max_age: 604800"], p.PolicyLines);
    }

    [Fact]
    public void Parses_lf_only_policy_and_mixed_endings_and_missing_final_newline()
    {
        Assert.True(MtaStsPolicyParser.TryParse("version: STSv1\nmode: testing\r\nmx: a.example.com\nmax_age: 86400", out var p, out _));
        Assert.Equal(MtaStsMode.Testing, p!.Mode);
    }

    [Fact]
    public void Is_tolerant_of_case_whitespace_blank_lines_unknown_keys_and_bom()
    {
        const string text = "﻿Version:STSv1\n\n  MODE :   Enforce  \nmx:\tMail.Example.COM.\nfuture_key: whatever\nmax_age:  60\n\n";
        Assert.True(MtaStsPolicyParser.TryParse(text, out var p, out string? error), error);
        Assert.Equal(MtaStsMode.Enforce, p!.Mode);
        Assert.Equal(["mail.example.com"], p.MxPatterns);
    }

    [Fact]
    public void Mode_none_does_not_need_mx()
    {
        Assert.True(MtaStsPolicyParser.TryParse("version: STSv1\nmode: none\nmax_age: 0\n", out var p, out _));
        Assert.Equal(MtaStsMode.None, p!.Mode);
        Assert.Empty(p.MxPatterns);
        Assert.Equal(0, p.MaxAgeSeconds);
    }

    [Theory]
    [InlineData("31557600", 31557600)]
    [InlineData("31557601", 31557600)]
    [InlineData("99999999999", 31557600)]
    [InlineData("99999999999999999999", 31557600)]
    [InlineData("0", 0)]
    [InlineData("0000000000042", 42)]
    public void Max_age_is_clamped(string value, int expected)
    {
        Assert.True(MtaStsPolicyParser.TryParse($"version: STSv1\nmode: testing\nmx: a.example.com\nmax_age: {value}\n", out var p, out string? error), error);
        Assert.Equal(expected, p!.MaxAgeSeconds);
    }

    [Theory]
    [InlineData("")]
    [InlineData("version: STSv1\nmode: enforce\nmx: a.example.com\n")]                                   // no max_age
    [InlineData("mode: enforce\nmx: a.example.com\nmax_age: 1\n")]                                       // no version
    [InlineData("version: STSv1\nmx: a.example.com\nmax_age: 1\n")]                                      // no mode
    [InlineData("version: STSv1\nmode: enforce\nmax_age: 1\n")]                                          // enforce without mx
    [InlineData("version: STSv1\nmode: testing\nmax_age: 1\n")]                                          // testing without mx
    [InlineData("version: STSv2\nmode: enforce\nmx: a.example.com\nmax_age: 1\n")]                      // wrong version
    [InlineData("version: STSv1\nversion: STSv1\nmode: none\nmax_age: 1\n")]                            // duplicate version
    [InlineData("version: STSv1\nmode: enforce\nmode: testing\nmx: a.example.com\nmax_age: 1\n")]       // duplicate mode
    [InlineData("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 1\nmax_age: 2\n")]          // duplicate max_age
    [InlineData("version: STSv1\nmode: strict\nmx: a.example.com\nmax_age: 1\n")]                       // bad mode
    [InlineData("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: -1\n")]                     // negative
    [InlineData("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 1.5\n")]                    // not an integer
    [InlineData("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: \n")]                       // empty
    [InlineData("version: STSv1\nmode: enforce\nmx: not a host\nmax_age: 1\n")]                         // bad mx
    [InlineData("version: STSv1\nmode: enforce\nmx: *.*.example.com\nmax_age: 1\n")]                    // double wildcard
    [InlineData("version: STSv1\nmode: enforce\nmx: mail.*.example.com\nmax_age: 1\n")]                 // inner wildcard
    [InlineData("version: STSv1\nmode: enforce\nmx: *\nmax_age: 1\n")]                                  // bare wildcard
    [InlineData("version: STSv1\nmode: enforce\nmx: 192.0.2.1\nmax_age: 1\n")]                          // IP literal
    [InlineData("version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 1\njunk without colon\n")]  // malformed line
    [InlineData(":value\nversion: STSv1\n")]                                                             // empty key
    public void Invalid_policies_are_rejected(string text)
    {
        Assert.False(MtaStsPolicyParser.TryParse(text, out var p, out string? error));
        Assert.Null(p);
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void Too_many_mx_lines_make_the_policy_invalid()
    {
        var lines = new List<string> { "version: STSv1", "mode: enforce", "max_age: 100" };
        lines.AddRange(Enumerable.Range(0, MtaStsPolicyParser.MaxMxPatterns + 1).Select(i => $"mx: m{i}.example.com"));
        Assert.False(MtaStsPolicyParser.TryParse(string.Join("\n", lines), out _, out _));
        lines.RemoveAt(lines.Count - 1);
        Assert.True(MtaStsPolicyParser.TryParse(string.Join("\n", lines), out var p, out _));
        Assert.Equal(MtaStsPolicyParser.MaxMxPatterns, p!.MxPatterns.Count);
    }

    [Fact]
    public void Oversized_input_is_rejected()
    {
        string text = Good + "# " + new string('x', MtaStsPolicyParser.MaxPolicyBytes);
        Assert.False(MtaStsPolicyParser.TryParse(text, out _, out string? error));
        Assert.Equal("policy too large", error);
    }

    [Fact]
    public void Byte_overload_rejects_invalid_utf8_and_null_text_is_handled()
    {
        Assert.False(MtaStsPolicyParser.TryParse(new byte[] { 0xFF, 0xFE, 0xFD }, out _, out string? error));
        Assert.Contains("UTF-8", error);
        Assert.False(MtaStsPolicyParser.TryParse((string?)null, out _, out _));
        Assert.True(MtaStsPolicyParser.TryParse(System.Text.Encoding.UTF8.GetBytes(Good), out _, out _));
    }

    [Fact]
    public void Idn_mx_names_are_stored_as_a_labels()
    {
        Assert.True(MtaStsPolicyParser.TryParse("version: STSv1\nmode: enforce\nmx: münchen.example.com\nmax_age: 1\n", out var p, out string? error), error);
        Assert.Equal(["xn--mnchen-3ya.example.com"], p!.MxPatterns);
    }
}

public class MtaStsMxMatchingTests
{
    [Theory]
    [InlineData("mail.example.com", "mail.example.com", true)]
    [InlineData("mail.example.com", "MAIL.Example.COM", true)]
    [InlineData("mail.example.com", "mail.example.com.", true)]
    [InlineData("mail.example.com", "mail2.example.com", false)]
    [InlineData("mail.example.com", "xmail.example.com", false)]
    [InlineData("mail.example.com", "mail.example.com.evil.net", false)]
    [InlineData("*.example.com", "mail.example.com", true)]
    [InlineData("*.example.com", "MX1.EXAMPLE.COM.", true)]
    [InlineData("*.example.com", "example.com", false)]
    [InlineData("*.example.com", "a.b.example.com", false)]
    [InlineData("*.example.com", "mail.example.com.evil.net", false)]
    [InlineData("*.example.com", "badexample.com", false)]
    [InlineData("*.example.com", ".example.com", false)]
    [InlineData("*.example.com", "", false)]
    [InlineData("*.example.com", "mail.example.org", false)]
    [InlineData("mail.example.com", "not a host", false)]
    [InlineData("mail.example.com", "192.0.2.1", false)]
    public void Matches_follows_rfc_8461_section_4_1(string pattern, string host, bool expected)
    {
        Assert.Equal(expected, MtaStsMxMatcher.Matches(pattern, host));
    }

    private static MtaStsPolicy Policy(MtaStsMode mode, params string[] mx)
    {
        string text = $"version: STSv1\nmode: {mode.ToString().ToLowerInvariant()}\n{string.Concat(mx.Select(m => "mx: " + m + "\n"))}max_age: 3600\n";
        Assert.True(MtaStsPolicyParser.TryParse(text, out var p, out string? err), err);
        return p!;
    }

    [Fact]
    public void IsMxAllowed_checks_all_patterns()
    {
        var p = Policy(MtaStsMode.Enforce, "mail.example.com", "*.example.net");
        Assert.True(p.IsMxAllowed("mail.example.com"));
        Assert.True(MtaStsEvaluation.IsMxAllowed(p, "mx1.example.net"));
        Assert.False(MtaStsEvaluation.IsMxAllowed(p, "other.example.com"));
        Assert.False(MtaStsEvaluation.IsMxAllowed(p, "example.net"));
    }

    [Fact]
    public void Mode_none_allows_everything()
    {
        var p = Policy(MtaStsMode.None);
        Assert.True(MtaStsEvaluation.IsMxAllowed(p, "anything.example.org"));
    }

    [Fact]
    public void Evaluate_reports_requirements_per_mode()
    {
        var enforce = MtaStsEvaluation.Evaluate(Policy(MtaStsMode.Enforce, "mail.example.com"), "Mail.Example.com.");
        Assert.True(enforce.MxAllowed);
        Assert.True(enforce.Enforced);
        Assert.True(enforce.RequireTls);
        Assert.True(enforce.RequireValidCertificate);
        Assert.False(enforce.ValidateButDoNotEnforce);
        Assert.Equal("mail.example.com", enforce.ExpectedCertificateName);

        var testing = MtaStsEvaluation.Evaluate(Policy(MtaStsMode.Testing, "mail.example.com"), "other.example.com");
        Assert.False(testing.MxAllowed);
        Assert.False(testing.Enforced);
        Assert.False(testing.RequireTls);
        Assert.True(testing.ValidateButDoNotEnforce);

        var none = MtaStsEvaluation.Evaluate(Policy(MtaStsMode.None), "x.example.com");
        Assert.True(none.MxAllowed);
        Assert.False(none.RequireTls);
        Assert.False(none.ValidateButDoNotEnforce);
    }
}
