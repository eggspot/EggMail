using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Mta.Dkim.Internal;
using Xunit.Abstractions;

namespace Mta.Dkim.Tests;

public class SignerTests
{
    private readonly ITestOutputHelper _output;

    public SignerTests(ITestOutputHelper output) => _output = output;

    private static (string Name, string Value)[] Tags(string header)
    {
        var bytes = Msg.Bytes(header.TrimEnd('\r', '\n'));
        var entries = new TagEntry[40];
        Assert.True(TagListParser.TryParse(bytes, bytes.AsSpan().IndexOf((byte)':') + 1, entries, out int n, out string? error), error);
        var list = new (string, string)[n];
        for (int i = 0; i < n; i++)
        {
            list[i] = (Encoding.ASCII.GetString(bytes, entries[i].NameStart, entries[i].NameLength), TagListParser.CompactAscii(bytes.AsSpan(entries[i].ValueStart, entries[i].ValueLength)));
        }

        return list;
    }

    private static string Tag(string header, string name) => Tags(header).Single(t => t.Name == name).Value;

    [Fact]
    public void Header_has_the_expected_shape()
    {
        var signer = Msg.Signer();
        string header = signer.Sign(Msg.Bytes(Msg.Simple()));
        _output.WriteLine(header);

        Assert.StartsWith("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel;", header);
        Assert.EndsWith("\r\n", header);
        Assert.DoesNotContain("\r\n\r\n", header);
        Assert.Equal(Msg.Now.ToUnixTimeSeconds().ToString(), Tag(header, "t"));
        Assert.DoesNotContain(Tags(header), t => t.Name == "l");
        Assert.DoesNotContain(Tags(header), t => t.Name == "x");
        Assert.DoesNotContain(Tags(header), t => t.Name == "i");
        Assert.Equal(44, Tag(header, "bh").Length);
        Assert.Equal(344, Tag(header, "b").Length); // 2048-bit signature
        foreach (string line in header.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            Assert.True(line.Length <= 78, "line too long: " + line);
        }

        foreach (string line in header.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Skip(1))
        {
            Assert.Equal('\t', line[0]);
        }
    }

    [Fact]
    public void Signing_is_deterministic_for_a_fixed_clock()
    {
        var signer = Msg.Signer();
        byte[] message = Msg.Bytes(Msg.Simple());
        Assert.Equal(signer.Sign(message), signer.Sign(message));
        Assert.Equal(signer.Sign(message), Encoding.ASCII.GetString(signer.SignToBytes(message).Span));
    }

    [Fact]
    public void The_prepended_overload_is_the_signature_field_followed_by_the_message()
    {
        var signer = Msg.Signer();
        byte[] message = Msg.Bytes(Msg.Simple());
        byte[] rented = signer.SignPrepended(message, out int length);
        try
        {
            byte[] expected = [.. signer.SignToBytes(message).ToArray(), .. message];
            Assert.Equal(expected.Length, length);
            Assert.Equal(expected, rented.AsSpan(0, length).ToArray());
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(rented);
        }
    }

    [Fact]
    public void Writer_overload_matches_string_overload()
    {
        var signer = Msg.Signer();
        byte[] message = Msg.Bytes(Msg.Simple());
        var writer = new ArrayBufferWriter<byte>();
        int n = signer.Sign(message, writer);
        Assert.Equal(n, writer.WrittenCount);
        Assert.Equal(signer.Sign(message), Encoding.ASCII.GetString(writer.WrittenSpan));
    }

    [Fact]
    public void Default_headers_are_oversigned()
    {
        var signer = Msg.Signer();
        string header = signer.Sign(Msg.Bytes(Msg.Simple()));
        var h = Tag(header, "h").Split(':');
        _output.WriteLine(string.Join(":", h));

        // Present headers appear twice (one real instance plus one oversigned), absent ones once.
        Assert.Equal(2, h.Count(n => n.Equals("From", StringComparison.OrdinalIgnoreCase)));
        Assert.Equal(2, h.Count(n => n.Equals("Subject", StringComparison.OrdinalIgnoreCase)));
        Assert.Equal(2, h.Count(n => n.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)));
        Assert.Equal(1, h.Count(n => n.Equals("Cc", StringComparison.OrdinalIgnoreCase)));
        Assert.Equal(1, h.Count(n => n.Equals("List-Unsubscribe", StringComparison.OrdinalIgnoreCase)));
        Assert.DoesNotContain(h, n => n.Equals("Received", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Oversigning_can_be_disabled()
    {
        var signer = Msg.Signer(oversign: false);
        string header = signer.Sign(Msg.Bytes(Msg.Simple()));
        var h = Tag(header, "h").Split(':');
        Assert.Single(h, n => n.Equals("From", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(h, n => n.Equals("Cc", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Repeated_header_instances_are_all_listed_bottom_up()
    {
        string message = "Comments: first\r\nComments: second\r\n" + Msg.Simple();
        var signer = Msg.Signer(headers: ["From", "Comments"], oversign: false);
        string header = signer.Sign(Msg.Bytes(message));
        Assert.Equal("From:Comments:Comments", Tag(header, "h"));
    }

    [Fact]
    public void From_is_always_signed_even_if_not_listed()
    {
        var signer = Msg.Signer(headers: ["Subject"], oversign: false);
        string header = signer.Sign(Msg.Bytes(Msg.Simple()));
        Assert.Equal("From:Subject", Tag(header, "h"));
    }

    [Fact]
    public void Header_names_are_deduplicated_ignoring_case()
    {
        var signer = Msg.Signer(headers: ["subject", "Subject", "SUBJECT"], oversign: false);
        string header = signer.Sign(Msg.Bytes(Msg.Simple()));
        Assert.Equal("From:subject", Tag(header, "h"));
    }

    [Theory]
    [InlineData(DkimCanonicalization.Relaxed, DkimCanonicalization.Relaxed, "relaxed/relaxed")]
    [InlineData(DkimCanonicalization.Simple, DkimCanonicalization.Simple, "simple/simple")]
    [InlineData(DkimCanonicalization.Relaxed, DkimCanonicalization.Simple, "relaxed/simple")]
    [InlineData(DkimCanonicalization.Simple, DkimCanonicalization.Relaxed, "simple/relaxed")]
    public void Canonicalization_is_configurable(DkimCanonicalization header, DkimCanonicalization body, string expected)
    {
        var signer = Msg.Signer(header: header, body: body);
        Assert.Equal(expected, Tag(signer.Sign(Msg.Bytes(Msg.Simple())), "c"));
    }

    [Fact]
    public void Expiration_and_identity_are_emitted()
    {
        var signer = Msg.Signer(lifetime: TimeSpan.FromHours(1), identity: "news@mail.example.com");
        string header = signer.Sign(Msg.Bytes(Msg.Simple()));
        Assert.Equal((Msg.Now.ToUnixTimeSeconds() + 3600).ToString(), Tag(header, "x"));
        Assert.Equal("news@mail.example.com", Tag(header, "i"));
    }

    [Fact]
    public void Identity_is_quoted_printable_encoded()
    {
        var signer = Msg.Signer(identity: "a;b=c@example.com");
        Assert.Equal("a=3Bb=3Dc@example.com", Tag(signer.Sign(Msg.Bytes(Msg.Simple())), "i"));
    }

    [Fact]
    public void Timestamp_can_be_omitted()
    {
        var signer = new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "sel", IncludeTimestamp = false }, TestKeys.Rsa2048);
        Assert.DoesNotContain(Tags(signer.Sign(Msg.Bytes(Msg.Simple()))), t => t.Name == "t");
    }

    [Fact]
    public void Domain_is_normalized_to_lower_case()
    {
        var signer = Msg.Signer(domain: "Example.COM.");
        Assert.Equal("example.com", signer.Domain);
        Assert.Equal("example.com", Tag(signer.Sign(Msg.Bytes(Msg.Simple())), "d"));
    }

    [Fact]
    public void Message_without_from_is_rejected()
    {
        var signer = Msg.Signer();
        var ex = Assert.Throws<DkimException>(() => signer.Sign(Msg.Bytes("Subject: x\r\n\r\nbody\r\n")));
        Assert.Contains("From", ex.Message);
    }

    [Fact]
    public void Message_with_too_many_headers_is_rejected()
    {
        var sb = new StringBuilder("From: a@example.com\r\n");
        for (int i = 0; i < 1100; i++) { sb.Append("X-H: v\r\n"); }
        sb.Append("\r\nbody\r\n");
        Assert.Throws<DkimException>(() => Msg.Signer().Sign(Msg.Bytes(sb.ToString())));
    }

    [Fact]
    public void More_signed_header_instances_than_a_verifier_accepts_are_rejected_when_signing()
    {
        string message = string.Concat(Enumerable.Repeat("Comments: x\r\n", 600)) + Msg.Simple();
        var signer = Msg.Signer(headers: ["From", "Comments"]);
        Assert.Throws<DkimException>(() => signer.Sign(Msg.Bytes(message)));

        string fewer = string.Concat(Enumerable.Repeat("Comments: x\r\n", 200)) + Msg.Simple();
        Assert.StartsWith("DKIM-Signature:", signer.Sign(Msg.Bytes(fewer)));
    }

    [Fact]
    public void Message_with_only_headers_and_no_blank_line_can_be_signed()
    {
        var signer = Msg.Signer();
        string header = signer.Sign(Msg.Bytes("From: a@example.com\r\nSubject: x"));
        Assert.StartsWith("DKIM-Signature:", header);
    }

    [Fact]
    public void Invalid_options_are_rejected()
    {
        RSA key = TestKeys.Rsa2048;
        Assert.Throws<DkimException>(() => new DkimSigner(new DkimSignerOptions { Domain = "not a domain", Selector = "s" }, key));
        Assert.Throws<DkimException>(() => new DkimSigner(new DkimSignerOptions { Domain = "localhost", Selector = "s" }, key));
        Assert.Throws<DkimException>(() => new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "bad;sel" }, key));
        Assert.Throws<DkimException>(() => new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "" }, key));
        Assert.Throws<DkimException>(() => new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "s", Identity = "a@other.org" }, key));
        Assert.Throws<DkimException>(() => new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "s", Identity = "a@notexample.com" }, key));
        Assert.Throws<DkimException>(() => new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "s", SignatureLifetime = TimeSpan.Zero }, key));
        Assert.Throws<DkimException>(() => new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "s", SignedHeaders = ["Bad:Name"] }, key));
        Assert.Throws<DkimException>(() => new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "s", SignedHeaders = ["Bad Name"] }, key));
        Assert.Throws<ArgumentNullException>(() => new DkimSigner(null!, key));
        Assert.Throws<ArgumentNullException>(() => new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "s" }, null!));
    }

    [Fact]
    public void Identity_in_a_subdomain_is_accepted()
    {
        _ = Msg.Signer(identity: "@sub.mail.example.com");
    }

    [Fact]
    public void Public_key_only_cannot_sign()
    {
        using var pub = RSA.Create();
        pub.ImportSubjectPublicKeyInfo(TestKeys.Rsa2048.ExportSubjectPublicKeyInfo(), out _);
        Assert.Throws<DkimException>(() => new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "s" }, pub));
    }

    [Fact]
    public void Keys_below_1024_bits_are_rejected()
    {
        RSA weak;
        try { weak = RSA.Create(512); }
        catch (CryptographicException) { return; } // some platforms (macOS) cannot even create such a key
        using var _ = weak;
        Assert.Throws<DkimException>(() => new DkimSigner(new DkimSignerOptions { Domain = "example.com", Selector = "s" }, weak));
    }

    [Fact]
    public void Signer_from_pem_and_der_owns_its_key_and_signs()
    {
        string pem = DkimKeyTools.ExportPrivateKeyPem(TestKeys.Rsa2048);
        var options = new DkimSignerOptions { Domain = "example.com", Selector = "sel", Clock = new FixedClock(Msg.Now) };
        using var fromPem = DkimSigner.FromPem(options, pem);
        using var fromDer = DkimSigner.FromDer(options, DkimKeyTools.ExportPrivateKeyDer(TestKeys.Rsa2048));
        byte[] message = Msg.Bytes(Msg.Simple());
        Assert.Equal(Msg.Signer().Sign(message), fromPem.Sign(message));
        Assert.Equal(fromPem.Sign(message), fromDer.Sign(message));
        Assert.Equal(2048, fromPem.KeyBits);
        Assert.Equal("sel", fromPem.Selector);
    }

    [Fact]
    public void Invalid_pem_is_reported_as_dkim_exception()
    {
        var options = new DkimSignerOptions { Domain = "example.com", Selector = "sel" };
        Assert.Throws<DkimException>(() => DkimSigner.FromPem(options, "not a pem"));
        Assert.Throws<DkimException>(() => DkimSigner.FromDer(options, new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void Multiple_signers_for_multiple_domains_prepend_independent_signatures()
    {
        var a = Msg.Signer(domain: "example.com", selector: "a");
        var b = Msg.Signer(key: TestKeys.Rsa2048Other, domain: "example.org", selector: "b");
        string message = Msg.Simple();
        string signed = b.Sign(Msg.Bytes(a.Sign(Msg.Bytes(message)) + message)) + a.Sign(Msg.Bytes(message)) + message;
        Assert.StartsWith("DKIM-Signature:", signed);
        Assert.Equal(2, signed.Split("DKIM-Signature:").Length - 1);
    }

    [Fact]
    public void Signing_from_many_threads_is_safe()
    {
        var signer = Msg.Signer();
        var dns = Msg.Dns(TestKeys.Rsa2048);
        var verifier = Msg.Verifier(dns);
        var failures = new List<string>();
        Parallel.For(0, 64, new ParallelOptions { MaxDegreeOfParallelism = 8 }, i =>
        {
            string body = "Body number " + i + "\r\n";
            string m = Msg.Simple(body);
            string signed = Msg.Sign(signer, m);
            var r = verifier.VerifyAsync(Msg.Bytes(signed)).AsTask().GetAwaiter().GetResult();
            if (r.Count != 1 || r[0].Status != DkimStatus.Pass) { lock (failures) { failures.Add(i + ": " + r[0].Reason); } }
        });
        Assert.Empty(failures);
    }
}
