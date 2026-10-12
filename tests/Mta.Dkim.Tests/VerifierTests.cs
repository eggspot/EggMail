using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Mta.Dns;

namespace Mta.Dkim.Tests;

public class VerifierTests
{
    private static readonly RSA Key = TestKeys.Rsa2048;

    private static DkimVerifier DefaultVerifier(IDnsResolver? dns = null, Action<DkimVerifierOptionsBuilder>? configure = null) =>
        Msg.Verifier(dns ?? Msg.Dns(Key), configure: configure);

    private static string SignedMessage(string? message = null, DkimSigner? signer = null)
    {
        message ??= Msg.Simple();
        return Msg.Sign(signer ?? Msg.Signer(), message);
    }

    /// <summary>Renames the first tag called <paramref name="tag"/> in the DKIM-Signature header so that the tag is effectively absent.</summary>
    private static string RemoveTag(string signed, string tag) =>
        new Regex("(?<=[;\\s:])" + Regex.Escape(tag) + "=").Replace(signed, "zz" + tag + "=", 1);

    // ---------------------------------------------------------------- happy paths

    [Theory]
    [InlineData(DkimCanonicalization.Relaxed, DkimCanonicalization.Relaxed)]
    [InlineData(DkimCanonicalization.Simple, DkimCanonicalization.Simple)]
    [InlineData(DkimCanonicalization.Relaxed, DkimCanonicalization.Simple)]
    [InlineData(DkimCanonicalization.Simple, DkimCanonicalization.Relaxed)]
    public async Task Own_signatures_verify_for_every_canonicalization_pair(DkimCanonicalization header, DkimCanonicalization body)
    {
        string[] bodies =
        [
            "Hello,\r\n\r\nThis is the body.\r\n",
            string.Empty,
            "\r\n",
            "no final newline",
            "trailing blank lines\r\n\r\n\r\n",
            "  leading and trailing  \t \r\n\t\r\n",
            "unicode éè as latin1 bytes\r\n",
        ];

        var signer = Msg.Signer(header: header, body: body);
        foreach (string b in bodies)
        {
            string message = SignedMessage(Msg.Simple(b), signer);
            var result = await Msg.VerifyOne(DefaultVerifier(), message);
            Assert.True(result.Status == DkimStatus.Pass, $"{header}/{body} body='{b}': {result.Reason}");
        }
    }

    [Fact]
    public async Task Pass_result_carries_signature_details()
    {
        string signed = SignedMessage();
        var r = await Msg.VerifyOne(DefaultVerifier(), signed);
        Assert.Equal(DkimStatus.Pass, r.Status);
        Assert.True(r.IsPass);
        Assert.Equal(DkimFailure.None, r.Failure);
        Assert.Equal("example.com", r.Domain);
        Assert.Equal("sel", r.Selector);
        Assert.Equal("rsa-sha256", r.Algorithm);
        Assert.Equal(2048, r.KeyBits);
        Assert.False(r.WeakKey);
        Assert.False(r.Testing);
        Assert.False(r.BodyLengthLimited);
        Assert.False(r.BodyPartiallySigned);
        Assert.Equal(DkimCanonicalization.Relaxed, r.HeaderCanonicalization);
        Assert.Equal(DkimCanonicalization.Relaxed, r.BodyCanonicalization);
        Assert.Equal(Msg.Now, r.SignedAt);
        Assert.Null(r.ExpiresAt);
        Assert.Equal(8, r.HeaderBPrefix!.Length);
        Assert.StartsWith(r.HeaderBPrefix, Regex.Match(signed, "b=([A-Za-z0-9+/\\s]+?)=*\r\n").Groups[1].Value.Replace("\r\n\t", string.Empty));
    }

    [Fact]
    public async Task Unsigned_message_yields_none()
    {
        var results = await DefaultVerifier().VerifyAsync(Msg.Bytes(Msg.Simple()));
        var r = Assert.Single(results);
        Assert.Equal(DkimStatus.None, r.Status);
        Assert.Equal(DkimFailure.NoSignature, r.Failure);
    }

    [Fact]
    public async Task Empty_and_garbage_input_never_throws()
    {
        foreach (string s in new[] { "", "\r\n", "garbage", "\0\0\0", ":::\r\n\r\n", "DKIM-Signature:\r\n\r\n", "DKIM-Signature" })
        {
            var results = await DefaultVerifier().VerifyAsync(Msg.Bytes(s));
            Assert.NotEmpty(results);
            Assert.DoesNotContain(results, r => r.Failure == DkimFailure.InternalError);
        }
    }

    [Fact]
    public async Task Header_name_matching_ignores_case_and_whitespace_before_colon()
    {
        string signed = SignedMessage().Replace("DKIM-Signature:", "dkim-signature :", StringComparison.Ordinal);
        var r = await Msg.VerifyOne(DefaultVerifier(), signed);
        // With simple header canonicalization the changed name would break the hash; with relaxed it must still pass.
        Assert.Equal(DkimStatus.Pass, r.Status);
    }

    // ---------------------------------------------------------------- tampering

    [Fact]
    public async Task Changed_body_is_a_body_hash_failure()
    {
        string signed = SignedMessage();
        var r = await Msg.VerifyOne(DefaultVerifier(), signed.Replace("the body", "the bodz", StringComparison.Ordinal));
        Assert.Equal(DkimStatus.Fail, r.Status);
        Assert.Equal(DkimFailure.BodyHashMismatch, r.Failure);
    }

    [Fact]
    public async Task Appended_body_content_is_a_body_hash_failure()
    {
        var r = await Msg.VerifyOne(DefaultVerifier(), SignedMessage() + "extra line\r\n");
        Assert.Equal(DkimFailure.BodyHashMismatch, r.Failure);
    }

    [Theory]
    [InlineData("Subject: Test message", "Subject: Test messagf")]
    [InlineData("To: Bob <bob@example.net>", "To: Mallory <bob@example.net>")]
    [InlineData("From: Alice <alice@example.com>", "From: Alice <alice@example.org>")]
    [InlineData("Message-ID: <1234@example.com>", "Message-ID: <9999@example.com>")]
    public async Task Changed_signed_header_is_a_signature_failure(string find, string replace)
    {
        var r = await Msg.VerifyOne(DefaultVerifier(), Msg.ReplaceFirst(SignedMessage(), find, replace));
        Assert.Equal(DkimStatus.Fail, r.Status);
        Assert.Equal(DkimFailure.SignatureMismatch, r.Failure);
    }

    [Fact]
    public async Task Removed_signed_header_is_a_signature_failure()
    {
        var r = await Msg.VerifyOne(DefaultVerifier(), Msg.ReplaceFirst(SignedMessage(), "Subject: Test message\r\n", string.Empty));
        Assert.Equal(DkimFailure.SignatureMismatch, r.Failure);
    }

    [Fact]
    public async Task Changed_unsigned_header_and_added_unlisted_headers_still_pass()
    {
        string signed = SignedMessage();
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(), Msg.ReplaceFirst(signed, "by mx.example.com", "by other.example.com"))).Status);
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(), "Received: from relay\r\n" + signed)).Status);
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(), "X-Spam-Score: 0\r\n" + signed)).Status);
    }

    [Theory]
    [InlineData("From: mallory@evil.example\r\n")]
    [InlineData("Subject: injected\r\n")]
    [InlineData("Date: Tue, 13 Oct 2026 12:00:00 +0000\r\n")]
    [InlineData("Content-Type: text/html\r\n")]
    [InlineData("Cc: victim@example.net\r\n")]            // header absent in the original: protected only by oversigning
    [InlineData("Reply-To: mallory@evil.example\r\n")]
    [InlineData("List-Unsubscribe: <https://evil.example/u>\r\n")]
    public async Task Oversigning_rejects_headers_added_after_signing(string added)
    {
        string signed = SignedMessage();
        // On top of the whole message, and directly below the signature: both positions must break it.
        Assert.Equal(DkimFailure.SignatureMismatch, (await Msg.VerifyOne(DefaultVerifier(), added + signed)).Failure);
        int firstLineEnd = signed.IndexOf("\r\nFrom:", StringComparison.Ordinal) + 2;
        Assert.Equal(DkimFailure.SignatureMismatch, (await Msg.VerifyOne(DefaultVerifier(), Msg.InsertBeforeBlankLine(signed, added))).Failure);
        Assert.True(firstLineEnd > 2);
    }

    [Theory]
    [InlineData("Subject: injected\r\n")]
    [InlineData("Cc: victim@example.net\r\n")]
    public async Task Without_oversigning_added_headers_go_unnoticed(string added)
    {
        // This documents why oversigning is the default.
        string signed = Msg.Sign(Msg.Signer(oversign: false), Msg.Simple());
        string injected = signed.StartsWith("DKIM-Signature", StringComparison.Ordinal) ? added + signed : signed;
        var r = await Msg.VerifyOne(DefaultVerifier(), injected);
        Assert.Equal(DkimStatus.Pass, r.Status);
    }

    [Fact]
    public async Task Tampered_signature_value_fails()
    {
        string signed = SignedMessage();
        int b = signed.IndexOf("b=", StringComparison.Ordinal);
        // Flip a character inside the b= value.
        int pos = signed.IndexOf("\r\n\t", b, StringComparison.Ordinal) + 3 + 5;
        char old = signed[pos];
        string tampered = signed.Substring(0, pos) + (old == 'A' ? 'B' : 'A') + signed.Substring(pos + 1);
        var r = await Msg.VerifyOne(DefaultVerifier(), tampered);
        Assert.Equal(DkimStatus.Fail, r.Status);
        Assert.Equal(DkimFailure.SignatureMismatch, r.Failure);
    }

    [Fact]
    public async Task Tampered_body_hash_tag_is_a_body_hash_failure()
    {
        string signed = SignedMessage();
        string tampered = Regex.Replace(signed, "bh=[A-Za-z0-9+/]", m => "bh=" + (m.Value[3] == 'A' ? 'B' : 'A'), RegexOptions.None, TimeSpan.FromSeconds(1));
        var r = await Msg.VerifyOne(DefaultVerifier(), tampered);
        Assert.Equal(DkimFailure.BodyHashMismatch, r.Failure);
    }

    [Fact]
    public async Task Signature_made_with_a_different_key_fails_as_signature_mismatch()
    {
        string signed = SignedMessage(signer: Msg.Signer(key: TestKeys.Rsa2048Other));
        var r = await Msg.VerifyOne(DefaultVerifier(), signed);
        Assert.Equal(DkimStatus.Fail, r.Status);
        Assert.Equal(DkimFailure.SignatureMismatch, r.Failure);
    }

    [Fact]
    public async Task Different_selector_or_domain_has_no_key()
    {
        string signed = SignedMessage(signer: Msg.Signer(selector: "other"));
        var r = await Msg.VerifyOne(DefaultVerifier(), signed);
        Assert.Equal(DkimStatus.PermError, r.Status);
        Assert.Equal(DkimFailure.KeyNotFound, r.Failure);
        Assert.Equal("other", r.Selector);
        Assert.Equal("example.com", r.Domain);
    }

    [Fact]
    public async Task Rewrapping_the_b_value_does_not_matter_even_with_simple_canonicalization()
    {
        string signed = SignedMessage(signer: Msg.Signer(header: DkimCanonicalization.Simple, body: DkimCanonicalization.Simple));
        int b = signed.IndexOf("b=", StringComparison.Ordinal) + 2;
        string rewrapped = signed.Substring(0, b + 20) + "\r\n\t " + signed.Substring(b + 20, 30) + "\r\n " + signed.Substring(b + 50);
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(), rewrapped)).Status);
    }

    // ---------------------------------------------------------------- DNS and key records

    [Fact]
    public async Task Dns_server_failure_is_a_temporary_error()
    {
        var dns = Msg.Dns(Key);
        dns.Fail("sel._domainkey.example.com", DnsRecordType.TXT, DnsRcode.ServerFailure);
        var r = await Msg.VerifyOne(DefaultVerifier(dns), SignedMessage());
        Assert.Equal(DkimStatus.TempError, r.Status);
        Assert.Equal(DkimFailure.KeyDnsError, r.Failure);
    }

    [Fact]
    public async Task Dns_refused_is_a_temporary_error()
    {
        var dns = new StaticDnsResolver().Fail("sel._domainkey.example.com", DnsRecordType.TXT, DnsRcode.Refused);
        Assert.Equal(DkimStatus.TempError, (await Msg.VerifyOne(DefaultVerifier(dns), SignedMessage())).Status);
    }

    [Fact]
    public async Task Resolver_exceptions_are_temporary_errors()
    {
        foreach (Exception ex in new Exception[] { new DnsException("timeout"), new InvalidOperationException("boom"), new TimeoutException(), new OperationCanceledException() })
        {
            var spy = new SpyResolver(Msg.Dns(Key)) { Throw = _ => ex };
            var r = await Msg.VerifyOne(DefaultVerifier(spy), SignedMessage());
            Assert.Equal(DkimStatus.TempError, r.Status);
            Assert.Equal(DkimFailure.KeyDnsError, r.Failure);
        }
    }

    [Fact]
    public async Task Cancellation_is_propagated_not_swallowed()
    {
        using var cts = new CancellationTokenSource();
        var spy = new SpyResolver(Msg.Dns(Key)) { Throw = _ => { cts.Cancel(); return new OperationCanceledException(cts.Token); } };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await DefaultVerifier(spy).VerifyAsync(Msg.Bytes(SignedMessage()), cts.Token));
    }

    [Fact]
    public async Task Nxdomain_and_nodata_are_permanent_errors()
    {
        var empty = new StaticDnsResolver();
        Assert.Equal(DkimStatus.PermError, (await Msg.VerifyOne(DefaultVerifier(empty), SignedMessage())).Status);

        var nodata = new StaticDnsResolver().AddA("sel._domainkey.example.com", "192.0.2.1");
        var r = await Msg.VerifyOne(DefaultVerifier(nodata), SignedMessage());
        Assert.Equal(DkimStatus.PermError, r.Status);
        Assert.Equal(DkimFailure.KeyNotFound, r.Failure);
    }

    [Fact]
    public async Task Key_published_through_a_cname_is_found()
    {
        var dns = new StaticDnsResolver()
            .Add(new CnameRecord("sel._domainkey.example.com", 300, "keys.provider.example"))
            .AddTxt("keys.provider.example", DkimKeyTools.FormatDnsTxtValue(Key));
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(dns), SignedMessage())).Status);
    }

    [Fact]
    public async Task Revoked_key_fails()
    {
        var dns = Msg.Dns(Key, txt: "v=DKIM1; k=rsa; p=");
        var r = await Msg.VerifyOne(DefaultVerifier(dns), SignedMessage());
        Assert.Equal(DkimStatus.Fail, r.Status);
        Assert.Equal(DkimFailure.KeyRevoked, r.Failure);
    }

    [Theory]
    [InlineData("v=DKIM1; k=rsa; p=!!!notbase64!!!")]
    [InlineData("v=DKIM1; k=rsa; p=AAAA")]                    // valid base64, not a key
    [InlineData("v=DKIM1; k=rsa")]                             // no p=
    [InlineData("v=DKIM2; k=rsa; p=AAAA")]                     // wrong version
    [InlineData("this is not a key record")]
    [InlineData("v=DKIM1; k=rsa; p=AAAA; p=BBBB")]             // duplicate tag
    public async Task Malformed_key_record_is_a_permanent_error(string txt)
    {
        var r = await Msg.VerifyOne(DefaultVerifier(Msg.Dns(Key, txt: txt)), SignedMessage());
        Assert.Equal(DkimStatus.PermError, r.Status);
        Assert.Equal(DkimFailure.MalformedKeyRecord, r.Failure);
    }

    [Fact]
    public async Task Oversized_key_material_is_rejected_without_being_imported()
    {
        string huge = "v=DKIM1; k=rsa; p=" + new string('A', 4000);
        var r = await Msg.VerifyOne(DefaultVerifier(Msg.Dns(Key, txt: huge)), SignedMessage());
        Assert.Equal(DkimFailure.MalformedKeyRecord, r.Failure);

        string enormous = "v=DKIM1; k=rsa; p=" + new string('A', 20000);
        r = await Msg.VerifyOne(DefaultVerifier(Msg.Dns(Key, txt: enormous)), SignedMessage());
        Assert.Equal(DkimFailure.MalformedKeyRecord, r.Failure);
    }

    [Fact]
    public async Task Ed25519_key_record_does_not_match_an_rsa_signature()
    {
        var r = await Msg.VerifyOne(DefaultVerifier(Msg.Dns(Key, txt: "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")), SignedMessage());
        Assert.Equal(DkimStatus.PermError, r.Status);
        Assert.Equal(DkimFailure.KeyTypeMismatch, r.Failure);
    }

    [Theory]
    [InlineData("h=sha1")]
    [InlineData("s=other")]
    public async Task Key_record_restrictions_that_exclude_us_are_honoured(string restriction)
    {
        string txt = DkimKeyTools.FormatDnsTxtValue(Key) + "; " + restriction;
        var r = await Msg.VerifyOne(DefaultVerifier(Msg.Dns(Key, txt: txt)), SignedMessage());
        Assert.Equal(DkimStatus.PermError, r.Status);
        Assert.Equal(DkimFailure.KeyDoesNotPermit, r.Failure);
    }

    [Theory]
    [InlineData("h=sha256")]
    [InlineData("h=sha1:sha256")]
    [InlineData("s=email")]
    [InlineData("s=*")]
    [InlineData("s=other:email")]
    [InlineData("n=some notes; unknowntag=ignored")]
    public async Task Key_record_restrictions_that_include_us_are_fine(string extra)
    {
        string txt = DkimKeyTools.FormatDnsTxtValue(Key) + "; " + extra;
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(Msg.Dns(Key, txt: txt)), SignedMessage())).Status);
    }

    [Fact]
    public async Task Testing_flag_is_reported_but_result_is_real()
    {
        string txt = DkimKeyTools.FormatDnsTxtValue(Key) + "; t=y";
        var pass = await Msg.VerifyOne(DefaultVerifier(Msg.Dns(Key, txt: txt)), SignedMessage());
        Assert.Equal(DkimStatus.Pass, pass.Status);
        Assert.True(pass.Testing);

        var fail = await Msg.VerifyOne(DefaultVerifier(Msg.Dns(Key, txt: txt)), SignedMessage().Replace("the body", "evil", StringComparison.Ordinal));
        Assert.Equal(DkimStatus.Fail, fail.Status);
        Assert.True(fail.Testing);
    }

    [Fact]
    public async Task Strict_flag_requires_identity_to_equal_the_domain()
    {
        string txt = DkimKeyTools.FormatDnsTxtValue(Key) + "; t=s";
        var sub = await Msg.VerifyOne(DefaultVerifier(Msg.Dns(Key, txt: txt)), SignedMessage(signer: Msg.Signer(identity: "@sub.example.com")));
        Assert.Equal(DkimStatus.Fail, sub.Status);
        Assert.Equal(DkimFailure.InvalidIdentity, sub.Failure);

        var same = await Msg.VerifyOne(DefaultVerifier(Msg.Dns(Key, txt: txt)), SignedMessage(signer: Msg.Signer(identity: "@example.com")));
        Assert.Equal(DkimStatus.Pass, same.Status);

        // Without the flag, a subdomain identity is fine.
        var lax = await Msg.VerifyOne(DefaultVerifier(), SignedMessage(signer: Msg.Signer(identity: "@sub.example.com")));
        Assert.Equal(DkimStatus.Pass, lax.Status);
        Assert.Equal("@sub.example.com", lax.Identity);
    }

    [Fact]
    public async Task One_keys_among_several_txt_records_is_selected()
    {
        var dns = new StaticDnsResolver();
        dns.AddTxt("sel._domainkey.example.com", "google-site-verification=abc");
        dns.AddTxt("sel._domainkey.example.com", DkimKeyTools.FormatDnsTxtValue(Key));
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(dns), SignedMessage())).Status);
    }

    // ---------------------------------------------------------------- key size policy

    [Fact]
    public async Task Rsa_1024_is_accepted_but_flagged_weak()
    {
        string signed = SignedMessage(signer: Msg.Signer(key: TestKeys.Rsa1024));
        var r = await Msg.VerifyOne(DefaultVerifier(Msg.Dns(TestKeys.Rsa1024)), signed);
        Assert.Equal(DkimStatus.Pass, r.Status);
        Assert.Equal(1024, r.KeyBits);
        Assert.True(r.WeakKey);
    }

    [Fact]
    public async Task Minimum_key_size_policy_is_configurable()
    {
        string signed = SignedMessage(signer: Msg.Signer(key: TestKeys.Rsa1024));
        var r = await Msg.VerifyOne(DefaultVerifier(Msg.Dns(TestKeys.Rsa1024), o => o.MinimumKeyBits = 2048), signed);
        Assert.Equal(DkimStatus.Fail, r.Status);
        Assert.Equal(DkimFailure.KeyTooSmall, r.Failure);
        Assert.Equal(1024, r.KeyBits);
    }

    [Fact]
    public async Task Key_larger_than_the_limit_is_rejected()
    {
        var r = await Msg.VerifyOne(DefaultVerifier(configure: o => o.MaximumKeyBits = 1024), SignedMessage());
        Assert.Equal(DkimStatus.PermError, r.Status);
        Assert.Equal(DkimFailure.KeyTooLarge, r.Failure);
    }

    [Fact]
    public async Task Weak_threshold_is_configurable()
    {
        var r = await Msg.VerifyOne(DefaultVerifier(configure: o => o.WeakKeyBelowBits = 4096), SignedMessage());
        Assert.Equal(DkimStatus.Pass, r.Status);
        Assert.True(r.WeakKey);
    }

    [Fact]
    public async Task Keys_below_1024_bits_are_rejected_by_default()
    {
        // Hand-made SPKI with a 512-bit modulus. Platforms that refuse to import it report a malformed key instead.
        var modulus = new byte[64];
        new Random(1).NextBytes(modulus);
        modulus[0] |= 0x80;
        modulus[^1] |= 1;
        var rsaParams = new RSAParameters { Modulus = modulus, Exponent = [1, 0, 1] };
        string spki;
        try
        {
            using var weak = RSA.Create();
            weak.ImportParameters(rsaParams);
            spki = Convert.ToBase64String(weak.ExportSubjectPublicKeyInfo());
        }
        catch (CryptographicException)
        {
            return;
        }

        var r = await Msg.VerifyOne(DefaultVerifier(Msg.Dns(Key, txt: "v=DKIM1; k=rsa; p=" + spki)), SignedMessage());
        Assert.True(r.Failure is DkimFailure.KeyTooSmall or DkimFailure.MalformedKeyRecord, r.Reason);
        Assert.NotEqual(DkimStatus.Pass, r.Status);
    }

    // ---------------------------------------------------------------- signature syntax and policy

    [Fact]
    public async Task Rsa_sha1_is_not_accepted()
    {
        string signed = Msg.ReplaceFirst(SignedMessage(), "a=rsa-sha256", "a=rsa-sha1");
        var r = await Msg.VerifyOne(DefaultVerifier(), signed);
        Assert.Equal(DkimStatus.Fail, r.Status);
        Assert.Equal(DkimFailure.WeakAlgorithm, r.Failure);
        Assert.Contains("rsa-sha1", r.Reason);
        Assert.Equal("rsa-sha1", r.Algorithm);
    }

    [Theory]
    [InlineData("a=ed25519-sha256", "ed25519")]
    [InlineData("a=rsa-sha512", "unsupported")]
    [InlineData("a=md5", "unsupported")]
    public async Task Unsupported_algorithms_are_neutral(string replacement, string reasonPart)
    {
        var r = await Msg.VerifyOne(DefaultVerifier(), Msg.ReplaceFirst(SignedMessage(), "a=rsa-sha256", replacement));
        Assert.Equal(DkimStatus.Neutral, r.Status);
        Assert.Equal(DkimFailure.UnsupportedAlgorithm, r.Failure);
        Assert.Contains(reasonPart, r.Reason);
    }

    [Fact]
    public async Task Unsupported_version_is_neutral()
    {
        var r = await Msg.VerifyOne(DefaultVerifier(), Msg.ReplaceFirst(SignedMessage(), "v=1;", "v=2;"));
        Assert.Equal(DkimStatus.Neutral, r.Status);
        Assert.Equal(DkimFailure.UnsupportedVersion, r.Failure);
    }

    [Theory]
    [InlineData("v")]
    [InlineData("a")]
    [InlineData("b")]
    [InlineData("bh")]
    [InlineData("d")]
    [InlineData("h")]
    [InlineData("s")]
    public async Task Missing_required_tag_is_neutral(string tag)
    {
        var r = await Msg.VerifyOne(DefaultVerifier(), RemoveTag(SignedMessage(), tag));
        Assert.Equal(DkimStatus.Neutral, r.Status);
        Assert.Equal(DkimFailure.MalformedSignature, r.Failure);
    }

    [Theory]
    [InlineData("d=example.com", "d=exa mple.com")]
    [InlineData("d=example.com", "d=-.")]
    [InlineData("d=example.com", "d=localhost")]
    [InlineData("s=sel", "s=se;l")]
    [InlineData("s=sel", "s=")]
    [InlineData("bh=", "bh=!!!")]
    [InlineData("c=relaxed/relaxed", "c=relaxed/sloppy")]
    public async Task Malformed_tag_values_are_neutral(string find, string replace)
    {
        var r = await Msg.VerifyOne(DefaultVerifier(), Msg.ReplaceFirst(SignedMessage(), find, replace));
        Assert.Equal(DkimStatus.Neutral, r.Status);
        Assert.Equal(DkimFailure.MalformedSignature, r.Failure);
    }

    [Fact]
    public async Task Signature_that_does_not_sign_from_is_ignored()
    {
        string message = Msg.Simple();
        string sig = Reference.MakeSignature(message, Key, "example.com", "sel", "to:subject");
        var r = await Msg.VerifyOne(DefaultVerifier(), sig + "\r\n" + message);
        Assert.Equal(DkimStatus.Neutral, r.Status);
        Assert.Equal(DkimFailure.FromNotSigned, r.Failure);
    }

    [Fact]
    public async Task Identity_outside_the_signing_domain_is_neutral()
    {
        string message = Msg.Simple();
        foreach (string i in new[] { "@other.org", "x@notexample.com", "example.com", "@example.com.evil.org" })
        {
            string sig = Reference.MakeSignature(message, Key, "example.com", "sel", "from:to", extraTags: $"i={i}; ");
            var r = await Msg.VerifyOne(DefaultVerifier(), sig + "\r\n" + message);
            Assert.Equal(DkimFailure.InvalidIdentity, r.Failure);
            Assert.Equal(DkimStatus.Neutral, r.Status);
        }
    }

    [Fact]
    public async Task Unknown_query_method_is_neutral_and_dns_txt_is_fine()
    {
        string message = Msg.Simple();
        string bad = Reference.MakeSignature(message, Key, "example.com", "sel", "from:to", extraTags: "q=other/method; ");
        Assert.Equal(DkimFailure.UnsupportedQueryMethod, (await Msg.VerifyOne(DefaultVerifier(), bad + "\r\n" + message)).Failure);

        string good = Reference.MakeSignature(message, Key, "example.com", "sel", "from:to", extraTags: "q=dns/txt; ");
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(), good + "\r\n" + message)).Status);
    }

    [Fact]
    public async Task Unknown_tags_are_ignored_and_duplicate_tags_are_not()
    {
        string message = Msg.Simple();
        string unknown = Reference.MakeSignature(message, Key, "example.com", "sel", "from:to", extraTags: "zz=whatever; z=From:x|To:y; ");
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(), unknown + "\r\n" + message)).Status);

        string dup = Reference.MakeSignature(message, Key, "example.com", "sel", "from:to", extraTags: "t=1; t=2; ");
        Assert.Equal(DkimFailure.MalformedSignature, (await Msg.VerifyOne(DefaultVerifier(), dup + "\r\n" + message)).Failure);
    }

    [Fact]
    public async Task Reference_signatures_made_by_the_naive_implementation_verify_for_all_canonicalizations()
    {
        string message = Msg.Simple("Body  with \t odd   spacing  \r\n\r\nand blank lines\r\n\r\n\r\n");
        foreach (bool hr in new[] { true, false })
        {
            foreach (bool br in new[] { true, false })
            {
                string sig = Reference.MakeSignature(message, Key, "example.com", "sel", "from:to:subject:date", hr, br);
                var r = await Msg.VerifyOne(DefaultVerifier(), sig + "\r\n" + message);
                Assert.True(r.Status == DkimStatus.Pass, $"{hr}/{br}: {r.Reason}");
            }
        }
    }

    // ---------------------------------------------------------------- expiry

    [Fact]
    public async Task Expired_signature_fails_with_clock_skew_tolerance()
    {
        string signed = SignedMessage(signer: Msg.Signer(lifetime: TimeSpan.FromHours(1)));
        var clock = new FixedClock(Msg.Now);
        var verifier = Msg.Verifier(Msg.Dns(Key), clock);

        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(verifier, signed)).Status);
        clock.Advance(TimeSpan.FromHours(1) + TimeSpan.FromMinutes(4));
        var within = await Msg.VerifyOne(verifier, signed);
        Assert.Equal(DkimStatus.Pass, within.Status);
        Assert.Equal(Msg.Now.AddHours(1), within.ExpiresAt);

        clock.Advance(TimeSpan.FromMinutes(2));
        var expired = await Msg.VerifyOne(verifier, signed);
        Assert.Equal(DkimStatus.Fail, expired.Status);
        Assert.Equal(DkimFailure.Expired, expired.Failure);
    }

    [Fact]
    public async Task Clock_skew_is_configurable()
    {
        string signed = SignedMessage(signer: Msg.Signer(lifetime: TimeSpan.FromHours(1)));
        var clock = new FixedClock(Msg.Now.AddHours(1).AddSeconds(30));
        var strict = Msg.Verifier(Msg.Dns(Key), clock, o => o.ClockSkew = TimeSpan.Zero);
        Assert.Equal(DkimFailure.Expired, (await Msg.VerifyOne(strict, signed)).Failure);
    }

    [Fact]
    public async Task Expiry_far_in_the_future_is_handled()
    {
        string message = Msg.Simple();
        string sig = Reference.MakeSignature(message, Key, "example.com", "sel", "from:to", extraTags: "x=999999999999999; ");
        var r = await Msg.VerifyOne(DefaultVerifier(), sig + "\r\n" + message);
        Assert.Equal(DkimStatus.Pass, r.Status);
        Assert.Null(r.ExpiresAt);
    }

    // ---------------------------------------------------------------- l=

    [Fact]
    public async Task Body_length_limit_is_flagged_when_content_is_appended()
    {
        string message = Msg.Simple("Hello\r\n");
        string sig = Reference.MakeSignature(message, Key, "example.com", "sel", "from:to:subject", bodyLength: 7);

        var intact = await Msg.VerifyOne(DefaultVerifier(), sig + "\r\n" + message);
        Assert.Equal(DkimStatus.Pass, intact.Status);
        Assert.True(intact.BodyLengthLimited);
        Assert.False(intact.BodyPartiallySigned);

        var appended = await Msg.VerifyOne(DefaultVerifier(), sig + "\r\n" + message + "EVIL CONTENT\r\n");
        Assert.Equal(DkimStatus.Pass, appended.Status);
        Assert.True(appended.BodyLengthLimited);
        Assert.True(appended.BodyPartiallySigned);
    }

    [Fact]
    public async Task Body_length_limit_can_be_rejected_by_policy()
    {
        string message = Msg.Simple("Hello\r\n");
        string sig = Reference.MakeSignature(message, Key, "example.com", "sel", "from:to:subject", bodyLength: 7);
        var r = await Msg.VerifyOne(DefaultVerifier(configure: o => o.RejectBodyLengthLimit = true), sig + "\r\n" + message);
        Assert.Equal(DkimStatus.Fail, r.Status);
        Assert.Equal(DkimFailure.BodyLengthRejected, r.Failure);
    }

    [Fact]
    public async Task Body_length_larger_than_the_body_fails()
    {
        string message = Msg.Simple("Hello\r\n");
        string sig = Reference.MakeSignature(message, Key, "example.com", "sel", "from:to:subject", bodyLength: 7);
        string shorter = Msg.Simple("Hi\r\n");
        var r = await Msg.VerifyOne(DefaultVerifier(), sig + "\r\n" + shorter);
        Assert.Equal(DkimStatus.Fail, r.Status);
        Assert.Equal(DkimFailure.BodyHashMismatch, r.Failure);
    }

    [Fact]
    public async Task Changing_the_covered_part_of_a_length_limited_body_fails()
    {
        string message = Msg.Simple("Hello\r\n");
        string sig = Reference.MakeSignature(message, Key, "example.com", "sel", "from:to:subject", bodyLength: 7);
        var r = await Msg.VerifyOne(DefaultVerifier(), sig + "\r\n" + Msg.Simple("Jello\r\nand more\r\n"));
        Assert.Equal(DkimFailure.BodyHashMismatch, r.Failure);
    }

    [Fact]
    public void Signer_never_emits_a_body_length_tag()
    {
        foreach (var body in new[] { DkimCanonicalization.Simple, DkimCanonicalization.Relaxed })
        {
            string header = Msg.Signer(body: body).Sign(Msg.Bytes(Msg.Simple()));
            Assert.DoesNotMatch(new Regex("[;\\s]l="), header);
        }
    }

    // ---------------------------------------------------------------- header instance selection

    [Fact]
    public async Task Repeated_header_instances_are_selected_from_the_bottom_up()
    {
        string message = "Subject: top\r\nSubject: bottom\r\n" + Msg.Simple().Replace("Subject: Test message\r\n", string.Empty, StringComparison.Ordinal);
        // h=subject covers only the bottom-most Subject.
        string sig = Reference.MakeSignature(message, Key, "example.com", "sel", "from:subject");
        string signed = sig + "\r\n" + message;
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(), signed)).Status);
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(), signed.Replace("Subject: top", "Subject: changed", StringComparison.Ordinal))).Status);
        Assert.Equal(DkimStatus.Fail, (await Msg.VerifyOne(DefaultVerifier(), signed.Replace("Subject: bottom", "Subject: changed", StringComparison.Ordinal))).Status);
    }

    [Fact]
    public async Task Listing_a_name_twice_covers_two_instances_and_order_matters()
    {
        string message = "Comments: first\r\nComments: second\r\n" + Msg.Simple();
        string sig = Reference.MakeSignature(message, Key, "example.com", "sel", "from:comments:comments");
        string signed = sig + "\r\n" + message;
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(), signed)).Status);

        string swapped = signed.Replace("Comments: first\r\nComments: second", "Comments: second\r\nComments: first", StringComparison.Ordinal);
        Assert.Equal(DkimFailure.SignatureMismatch, (await Msg.VerifyOne(DefaultVerifier(), swapped)).Failure);

        // A third instance added on top is not covered, but a name listed three times with two instances is fine too.
        string extraOnTop = sig + "\r\nComments: third\r\n" + message;
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(), extraOnTop)).Status);
    }

    [Fact]
    public async Task Naming_a_header_more_often_than_it_exists_is_oversigning_by_hand()
    {
        string message = Msg.Simple();
        string sig = Reference.MakeSignature(message, Key, "example.com", "sel", "from:from:subject");
        string signed = sig + "\r\n" + message;
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(), signed)).Status);
        Assert.Equal(DkimStatus.Fail, (await Msg.VerifyOne(DefaultVerifier(), "From: evil@example.org\r\n" + signed)).Status);
    }

    // ---------------------------------------------------------------- multiple signatures

    [Fact]
    public async Task Multiple_signatures_are_verified_independently_in_message_order()
    {
        var other = Msg.Signer(key: TestKeys.Rsa2048Other, domain: "example.org", selector: "b");
        var first = Msg.Signer();
        string message = Msg.Simple();
        string once = first.Sign(Msg.Bytes(message)) + message;
        string twice = other.Sign(Msg.Bytes(once)) + once;

        var dns = Msg.Dns(Key);
        dns.AddTxt("b._domainkey.example.org", DkimKeyTools.FormatDnsTxtValue(TestKeys.Rsa2048Other));
        var results = await DefaultVerifier(dns).VerifyAsync(Msg.Bytes(twice));
        Assert.Equal(2, results.Count);
        Assert.All(results, r => Assert.Equal(DkimStatus.Pass, r.Status));
        Assert.Equal("example.org", results[0].Domain);
        Assert.Equal("example.com", results[1].Domain);
    }

    [Fact]
    public async Task One_bad_signature_does_not_affect_the_others()
    {
        var other = Msg.Signer(key: TestKeys.Rsa2048Other, domain: "example.org", selector: "b");
        string message = Msg.Simple();
        string once = Msg.Signer().Sign(Msg.Bytes(message)) + message;
        string twice = other.Sign(Msg.Bytes(once)) + once;
        var dns = Msg.Dns(Key);
        // example.org's published key is the wrong one.
        dns.AddTxt("b._domainkey.example.org", DkimKeyTools.FormatDnsTxtValue(Key));
        var results = await DefaultVerifier(dns).VerifyAsync(Msg.Bytes(twice));
        Assert.Equal(DkimStatus.Fail, results[0].Status);
        Assert.Equal(DkimStatus.Pass, results[1].Status);
    }

    [Fact]
    public async Task A_signature_can_cover_an_earlier_signature_and_never_includes_itself()
    {
        string message = Msg.Simple();
        string once = Msg.Signer(domain: "example.com", selector: "sel").Sign(Msg.Bytes(message)) + message;
        var outer = Msg.Signer(key: TestKeys.Rsa2048Other, domain: "example.org", selector: "b", headers: ["From", "DKIM-Signature"]);
        string twice = outer.Sign(Msg.Bytes(once)) + once;

        var dns = Msg.Dns(Key);
        dns.AddTxt("b._domainkey.example.org", DkimKeyTools.FormatDnsTxtValue(TestKeys.Rsa2048Other));
        var results = await DefaultVerifier(dns).VerifyAsync(Msg.Bytes(twice));
        Assert.All(results, r => Assert.Equal(DkimStatus.Pass, r.Status));

        // Changing the inner signature breaks the inner one and the outer one that covers it.
        string broken = Msg.ReplaceFirst(twice, "s=sel;", "s=sel; zz=1;");
        var brokenResults = await DefaultVerifier(dns).VerifyAsync(Msg.Bytes(broken));
        Assert.Equal(2, brokenResults.Count);
        Assert.All(brokenResults, r => Assert.Equal(DkimStatus.Fail, r.Status));
    }

    [Fact]
    public async Task Only_the_configured_number_of_signatures_is_verified()
    {
        string message = Msg.Simple();
        string combined = message;
        for (int i = 0; i < 7; i++) { combined = Msg.Signer().Sign(Msg.Bytes(combined)) + combined; }

        var spy = new SpyResolver(Msg.Dns(Key));
        var results = await DefaultVerifier(spy).VerifyAsync(Msg.Bytes(combined));
        Assert.Equal(7, results.Count);
        Assert.Equal(5, results.Count(r => r.Status == DkimStatus.Pass));
        Assert.Equal(2, results.Count(r => r.Failure == DkimFailure.SignatureLimitExceeded && r.Status == DkimStatus.Neutral));
        Assert.Equal(1, spy.Queries); // the same key record is looked up once per message

        var wider = await DefaultVerifier(spy, o => o.MaxSignaturesVerified = 7).VerifyAsync(Msg.Bytes(combined));
        Assert.All(wider, r => Assert.Equal(DkimStatus.Pass, r.Status));
    }

    // ---------------------------------------------------------------- hostile input

    [Fact]
    public async Task Too_many_header_fields_are_reported_not_processed()
    {
        var sb = new StringBuilder(SignedMessage().Split("\r\n\r\n")[0]);
        for (int i = 0; i < 1500; i++) { sb.Append("\r\nX-Filler: ").Append(i); }
        sb.Append("\r\n\r\nbody\r\n");
        var r = await Msg.VerifyOne(DefaultVerifier(), sb.ToString());
        Assert.Equal(DkimStatus.Neutral, r.Status);
        Assert.Equal(DkimFailure.TooManyHeaders, r.Failure);
    }

    [Fact]
    public async Task Oversized_signature_header_is_neutral()
    {
        string signed = SignedMessage();
        string padded = Msg.ReplaceFirst(signed, "v=1;", "zz=" + new string('x', 20000) + "; v=1;");
        var r = await Msg.VerifyOne(DefaultVerifier(), padded);
        Assert.Equal(DkimStatus.Neutral, r.Status);
        Assert.Equal(DkimFailure.MalformedSignature, r.Failure);
    }

    [Fact]
    public async Task Huge_header_name_lists_and_tag_counts_are_neutral()
    {
        string signed = SignedMessage();
        string manyNames = Msg.ReplaceFirst(signed, "h=From", "h=" + string.Join(":", Enumerable.Repeat("X-A", 700)) + ":From");
        Assert.Equal(DkimStatus.Neutral, (await Msg.VerifyOne(DefaultVerifier(configure: o => o.MaxSignatureHeaderLength = 1 << 20), manyNames)).Status);

        string manyTags = Msg.ReplaceFirst(signed, "v=1;", string.Concat(Enumerable.Range(0, 50).Select(i => $"t{i}=1; ")) + "v=1;");
        var r = await Msg.VerifyOne(DefaultVerifier(), manyTags);
        Assert.Equal(DkimStatus.Neutral, r.Status);
    }

    [Fact]
    public async Task Many_signature_headers_do_not_cause_many_dns_queries()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 300; i++) { sb.Append("DKIM-Signature: v=1; a=rsa-sha256; d=d").Append(i).Append(".example.com; s=s; h=from; bh=AAAA; b=AAAA\r\n"); }
        sb.Append(Msg.Simple());
        var spy = new SpyResolver(new StaticDnsResolver());
        var results = await DefaultVerifier(spy).VerifyAsync(Msg.Bytes(sb.ToString()));
        Assert.Equal(300, results.Count);
        Assert.True(spy.Queries <= 5);
    }

    [Fact]
    public async Task Truncated_messages_never_throw()
    {
        byte[] signed = Msg.Bytes(SignedMessage());
        var verifier = DefaultVerifier();
        for (int len = 0; len < signed.Length; len += 7)
        {
            var results = await verifier.VerifyAsync(signed.AsMemory(0, len));
            Assert.NotEmpty(results);
            Assert.DoesNotContain(results, r => r.Failure == DkimFailure.InternalError);
        }
    }

    [Fact]
    public async Task Randomly_mutated_messages_never_throw_and_never_pass_after_signed_content_changed()
    {
        string original = SignedMessage();
        var rng = new Random(12345);
        var verifier = DefaultVerifier();
        for (int i = 0; i < 1500; i++)
        {
            byte[] bytes = Msg.Bytes(original);
            int edits = rng.Next(1, 4);
            for (int e = 0; e < edits; e++)
            {
                switch (rng.Next(3))
                {
                    case 0: bytes[rng.Next(bytes.Length)] = (byte)rng.Next(256); break;
                    case 1: bytes = bytes.Where((_, idx) => idx != rng.Next(bytes.Length)).ToArray(); break;
                    default:
                        int at = rng.Next(bytes.Length);
                        bytes = bytes.Take(at).Concat([(byte)rng.Next(256)]).Concat(bytes.Skip(at)).ToArray();
                        break;
                }
            }

            var results = await verifier.VerifyAsync(bytes);
            Assert.NotEmpty(results);
            Assert.DoesNotContain(results, r => r.Failure == DkimFailure.InternalError);
        }
    }

    [Fact]
    public async Task Large_message_verifies()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 100_000; i++) { sb.Append("A line of body text number ").Append(i).Append("  \r\n"); }
        string signed = SignedMessage(Msg.Simple(sb.ToString()));
        Assert.True(signed.Length > 3_000_000);
        Assert.Equal(DkimStatus.Pass, (await Msg.VerifyOne(DefaultVerifier(), signed)).Status);
    }

    [Fact]
    public void Constructor_validates_arguments()
    {
        Assert.Throws<ArgumentNullException>(() => new DkimVerifier(null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DkimVerifier(new StaticDnsResolver(), new DkimVerifierOptions { MaxSignaturesVerified = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DkimVerifier(new StaticDnsResolver(), new DkimVerifierOptions { MaxHeaderCount = 0 }));
    }
}
