using System.Security.Cryptography;
using System.Text;

namespace Mta.Dkim.Tests;

public class CanonicalizationTests
{
    // RFC 6376 section 3.4.5 worked example.
    private const string RfcBody = " C \r\nD \t E\r\n\r\n\r\n";

    [Fact]
    public void Rfc_example_relaxed_headers()
    {
        Assert.Equal("a:X\r\n", Canon.Header("A: X\r\n", relaxed: true));
        Assert.Equal("b:Y Z\r\n", Canon.Header("B : Y\t\r\n\tZ  \r\n", relaxed: true));
    }

    [Fact]
    public void Rfc_example_simple_headers_are_unchanged()
    {
        Assert.Equal("A: X\r\n", Canon.Header("A: X\r\n", relaxed: false));
        Assert.Equal("B : Y\t\r\n\tZ  \r\n", Canon.Header("B : Y\t\r\n\tZ  \r\n", relaxed: false));
    }

    [Fact]
    public void Rfc_example_bodies()
    {
        Assert.Equal(" C\r\nD E\r\n", Canon.Body(RfcBody, relaxed: true));
        Assert.Equal(" C \r\nD \t E\r\n", Canon.Body(RfcBody, relaxed: false));
    }

    [Theory]
    [InlineData("Subject: Hello   World  \r\n", "subject:Hello World\r\n")]
    [InlineData("SuBjEcT:x\r\n", "subject:x\r\n")]
    [InlineData("Subject: line1\r\n line2\r\n\tline3\r\n", "subject:line1 line2 line3\r\n")]
    [InlineData("X-Empty:\r\n", "x-empty:\r\n")]
    [InlineData("X-Empty:   \r\n", "x-empty:\r\n")]
    [InlineData("X-Empty: \r\n \r\n\t\r\n", "x-empty:\r\n")]
    [InlineData("X:\r\n abc\r\n", "x:abc\r\n")]
    [InlineData("X: a\tb\r\n", "x:a b\r\n")]
    [InlineData("X: a \t \t b\r\n", "x:a b\r\n")]
    [InlineData("X   :   a\r\n", "x:a\r\n")]
    [InlineData("X: a  \r\n  \r\n b\r\n", "x:a b\r\n")]
    [InlineData("X: trailing   ", "x:trailing\r\n")]
    [InlineData("Message-ID: <a@b>\r\n", "message-id:<a@b>\r\n")]
    [InlineData("X: a:b : c\r\n", "x:a:b : c\r\n")]
    public void Relaxed_header_cases(string input, string expected)
    {
        Assert.Equal(expected, Canon.Header(input, relaxed: true));
        Assert.Equal(expected, Reference.RelaxedHeader(input));
    }

    [Fact]
    public void Simple_header_without_trailing_crlf_gets_one_only_on_request()
    {
        Assert.Equal("X: a\r\n", Canon.Header("X: a", relaxed: false));
        Assert.Equal("X: a", Canon.Header("X: a", relaxed: false, appendCrlf: false));
        Assert.Equal("x:a", Canon.Header("X: a\r\n", relaxed: true, appendCrlf: false));
    }

    [Theory]
    [InlineData("", "\r\n", "")]                                  // empty body: simple becomes CRLF, relaxed stays empty
    [InlineData("\r\n", "\r\n", "")]
    [InlineData("\r\n\r\n\r\n", "\r\n", "")]
    [InlineData("abc", "abc\r\n", "abc\r\n")]                    // missing final CRLF is added
    [InlineData("abc\r\n", "abc\r\n", "abc\r\n")]
    [InlineData("abc\r\n\r\n\r\n", "abc\r\n", "abc\r\n")]        // trailing blank lines stripped
    [InlineData("abc\r\n\r\ndef\r\n\r\n", "abc\r\n\r\ndef\r\n", "abc\r\n\r\ndef\r\n")]
    [InlineData("\r\nabc\r\n", "\r\nabc\r\n", "\r\nabc\r\n")]    // leading blank lines are kept
    [InlineData(" abc \r\n", " abc \r\n", " abc\r\n")]
    [InlineData("a  b\t\tc\r\n", "a  b\t\tc\r\n", "a b c\r\n")]
    [InlineData("abc   ", "abc   \r\n", "abc\r\n")]              // trailing WSP, no CRLF
    [InlineData("abc\r\n   \r\n", "abc\r\n   \r\n", "abc\r\n")]  // WSP-only line is blank only in relaxed
    [InlineData("   \r\n", "   \r\n", "")]
    [InlineData("   ", "   \r\n", "")]
    [InlineData("\t", "\t\r\n", "")]
    [InlineData("a\r\n \r\n\r\n", "a\r\n \r\n", "a\r\n")]
    [InlineData(" \t a \t \r\n", " \t a \t \r\n", " a\r\n")]
    public void Body_cases(string input, string simple, string relaxed)
    {
        Assert.Equal(simple, Canon.Body(input, relaxed: false));
        Assert.Equal(relaxed, Canon.Body(input, relaxed: true));
        Assert.Equal(simple, Reference.Body(input, relaxed: false));
        Assert.Equal(relaxed, Reference.Body(input, relaxed: true));
    }

    [Fact]
    public void Known_body_hashes()
    {
        // RFC 6376 / RFC 8463 sample body: bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=
        string body = "Hi.\r\n\r\nWe lost the game. Are you hungry yet?\r\n\r\nJoe.\r\n";
        Span<byte> hash = stackalloc byte[32];
        foreach (bool relaxed in new[] { true, false })
        {
            DkimVerifier.HashBody(Msg.Bytes(body), relaxed, long.MaxValue, hash, out long total);
            Assert.Equal("2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=", Convert.ToBase64String(hash));
            Assert.Equal(body.Length, total);
        }

        // Empty body: relaxed hashes nothing, simple hashes a single CRLF.
        Span<byte> empty = stackalloc byte[32];
        DkimVerifier.HashBody([], relaxed: true, long.MaxValue, empty, out _);
        Assert.Equal("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", Convert.ToBase64String(empty));
        DkimVerifier.HashBody([], relaxed: false, long.MaxValue, empty, out _);
        Assert.Equal("frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=", Convert.ToBase64String(empty));
    }

    [Fact]
    public void Body_length_limit_truncates_the_canonical_stream_and_counts_the_whole_body()
    {
        string body = "abcdef\r\nghijkl\r\n";
        Span<byte> limited = stackalloc byte[32];
        DkimVerifier.HashBody(Msg.Bytes(body), true, 4, limited, out long total);
        Assert.Equal(body.Length, total);
        Assert.Equal(Convert.ToBase64String(SHA256.HashData("abcd"u8)), Convert.ToBase64String(limited));

        DkimVerifier.HashBody(Msg.Bytes(body), true, 0, limited, out _);
        Assert.Equal(Convert.ToBase64String(SHA256.HashData([])), Convert.ToBase64String(limited));

        // A limit that cuts in the middle of the data written by one canonicalization step.
        DkimVerifier.HashBody(Msg.Bytes(body), true, 9, limited, out _);
        Assert.Equal(Convert.ToBase64String(SHA256.HashData("abcdef\r\ng"u8)), Convert.ToBase64String(limited));
    }

    [Fact]
    public void Randomised_differential_against_the_naive_reference()
    {
        var rng = new Random(20261012);
        string[] tokens = ["a", "bc", " ", "\t", "  ", "\r\n", "\r\n\r\n", " \r\n", "\t \r\n", "x y", "\r"];
        for (int iter = 0; iter < 3000; iter++)
        {
            var sb = new StringBuilder();
            int n = rng.Next(0, 60);
            for (int i = 0; i < n; i++) { sb.Append(tokens[rng.Next(tokens.Length)]); }
            // Occasionally make the body long enough to cross the sink buffer boundaries.
            if (iter % 50 == 0) { for (int i = 0; i < 400; i++) { sb.Append(tokens[rng.Next(tokens.Length)]); } }
            string body = sb.ToString();
            Assert.Equal(Reference.Body(body, true), Canon.Body(body, true));
            Assert.Equal(Reference.Body(body, false), Canon.Body(body, false));
        }
    }

    [Fact]
    public void Randomised_header_differential_against_the_naive_reference()
    {
        var rng = new Random(424242);
        string[] ws = ["", " ", "\t", "  ", " \t "];
        string[] words = ["a", "Hello", "x:y", "<id@host>", "\"q\"", "é"];
        for (int iter = 0; iter < 3000; iter++)
        {
            var sb = new StringBuilder();
            sb.Append(rng.Next(2) == 0 ? "Subject" : "X-Weird-Name").Append(ws[rng.Next(ws.Length)]).Append(':').Append(ws[rng.Next(ws.Length)]);
            int n = rng.Next(0, 8);
            for (int i = 0; i < n; i++)
            {
                sb.Append(words[rng.Next(words.Length)]).Append(ws[rng.Next(ws.Length)]);
                if (rng.Next(4) == 0) { sb.Append("\r\n").Append(rng.Next(2) == 0 ? " " : "\t"); }
            }

            string field = sb.ToString() + "\r\n";
            Assert.Equal(Reference.RelaxedHeader(field), Canon.Header(field, true));
            Assert.Equal(Reference.SimpleHeader(field), Canon.Header(field, false));
        }
    }

    [Fact]
    public void Large_body_with_long_lines_matches_reference()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 2000; i++) { sb.Append("line ").Append(i).Append("   with  spaces \t\r\n"); }
        sb.Append(new string('z', 5000)).Append(" \r\n\r\n\r\n");
        string body = sb.ToString();
        Assert.Equal(Reference.Body(body, true), Canon.Body(body, true));
        Assert.Equal(Reference.Body(body, false), Canon.Body(body, false));
    }
}
