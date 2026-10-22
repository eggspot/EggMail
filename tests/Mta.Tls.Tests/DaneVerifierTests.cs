using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mta.Dns;
using Mta.Tls.Dane;
using Mta.Tls.Tests.Support;

namespace Mta.Tls.Tests;

public static class Tlsa
{
    public static TlsaRecord For(X509Certificate2 cert, byte usage, byte selector, byte matching, string name = "_25._tcp.mx.example.com")
    {
        byte[] selected = selector == 0 ? cert.RawData : cert.PublicKey.ExportSubjectPublicKeyInfo();
        byte[] data = matching switch
        {
            0 => selected,
            1 => SHA256.HashData(selected),
            2 => SHA512.HashData(selected),
            _ => throw new ArgumentOutOfRangeException(nameof(matching)),
        };
        return new TlsaRecord(name, 300, usage, selector, matching, data);
    }
}

public class DaneVerifierTests
{
    private const string Mx = "mx.example.com";

    private sealed class Pki
    {
        private static readonly Lazy<Pki> SharedDefault = new(() => new Pki());
        private static readonly Lazy<Pki> SharedOtherDefault = new(() => new Pki());

        /// <summary>A default chain shared by tests that only read it (key generation is the slow part).</summary>
        public static Pki Shared => SharedDefault.Value;

        public static Pki SharedOther => SharedOtherDefault.Value;

        public IssuedCertificate Root { get; }
        public IssuedCertificate Intermediate { get; }
        public IssuedCertificate Leaf { get; }

        public Pki(bool rsa = false, string[]? names = null, DateTimeOffset? leafNotBefore = null, DateTimeOffset? leafNotAfter = null)
        {
            Root = TestPki.CreateRoot(rsa: rsa);
            Intermediate = TestPki.CreateIntermediate(Root, rsa: rsa);
            Leaf = TestPki.CreateLeaf(Intermediate, names ?? [Mx], rsa: rsa, notBefore: leafNotBefore, notAfter: leafNotAfter);
        }

        public X509Certificate2[] FullChain => [Leaf.Public, Intermediate.Public, Root.Public];

        public X509Certificate2[] WithoutRoot => [Leaf.Public, Intermediate.Public];
    }

    private static DaneVerificationResult Verify(Pki pki, IEnumerable<TlsaRecord> records, X509Certificate2[]? chain = null, string host = Mx, DaneVerifyOptions? options = null) =>
        DaneVerifier.Verify(records.ToArray(), pki.Leaf.Public, chain ?? pki.FullChain, host, options);

    public static IEnumerable<object[]> AllSelectorMatchingCombinations() =>
        from selector in new byte[] { 0, 1 }
        from matching in new byte[] { 0, 1, 2 }
        select new object[] { selector, matching };

    // ---- DANE-EE (usage 3) ----

    [Theory]
    [MemberData(nameof(AllSelectorMatchingCombinations))]
    public void DaneEE_matches_the_leaf_for_every_selector_and_matching_type(byte selector, byte matching)
    {
        var pki = Pki.Shared;
        var result = Verify(pki, [Tlsa.For(pki.Leaf.Public, 3, selector, matching)]);

        Assert.True(result.Success);
        Assert.Null(result.Failure);
        Assert.Equal(3, result.Match!.Usage);
        Assert.Equal(selector, result.Match.Selector);
        Assert.Equal(matching, result.Match.MatchingType);
    }

    [Theory]
    [MemberData(nameof(AllSelectorMatchingCombinations))]
    public void DaneEE_does_not_match_a_different_certificate(byte selector, byte matching)
    {
        var pki = Pki.Shared;
        var other = Pki.SharedOther;
        var result = Verify(pki, [Tlsa.For(other.Leaf.Public, 3, selector, matching)]);

        Assert.False(result.Success);
        Assert.Equal(TlsResultType.ValidationFailure, result.Failure);
    }

    [Fact]
    public void DaneEE_ignores_the_host_name_and_the_validity_period()
    {
        var expired = new Pki(names: ["something-else.example.net"], leafNotBefore: DateTimeOffset.UtcNow.AddDays(-30), leafNotAfter: DateTimeOffset.UtcNow.AddDays(-1));
        var result = Verify(expired, [Tlsa.For(expired.Leaf.Public, 3, 1, 1)]);
        Assert.True(result.Success);
    }

    [Fact]
    public void DaneEE_with_a_self_signed_untrusted_leaf_is_fine()
    {
        var self = TestPki.CreateSelfSignedLeaf(["whatever.example.org"]);
        var result = DaneVerifier.Verify([Tlsa.For(self.Public, 3, 1, 1)], self.Public, [self.Public], Mx);
        Assert.True(result.Success);
    }

    [Fact]
    public void DaneEE_matches_if_any_of_several_records_match()
    {
        var pki = new Pki();
        var other = new Pki();
        var result = Verify(pki, [Tlsa.For(other.Leaf.Public, 3, 1, 1), Tlsa.For(pki.Leaf.Public, 3, 0, 2)]);
        Assert.True(result.Success);
        Assert.Equal(2, result.Match!.MatchingType);
    }

    // ---- DANE-TA (usage 2) ----

    [Fact]
    public void A_bare_key_on_an_unknown_curve_is_skipped_and_the_next_record_still_anchors()
    {
        // Found by the dane fuzz target: the key's curve identifier is damaged, ECDsa refuses it with PlatformNotSupportedException (on
        // macOS; other platforms may say CryptographicException), and that escaped the verifier, so the record after it was never tried.
        var pki = Pki.Shared;
        byte[] spki = pki.Intermediate.Public.PublicKey.ExportSubjectPublicKeyInfo();
        int curveOid = spki.AsSpan().IndexOf((ReadOnlySpan<byte>)[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);
        Assert.True(curveOid >= 0, "the test PKI is expected to use P-256");
        spki[curveOid + 3] ^= 0xC5;
        var hostile = new TlsaRecord("_25._tcp.mx.example.com", 300, 2, 1, 0, spki);

        var result = Verify(pki, [hostile, Tlsa.For(pki.Intermediate.Public, 2, 1, 1)]);

        Assert.True(result.Success, string.Join("; ", result.Notes));
        Assert.Equal(1, result.Match!.MatchingType);
    }

    [Theory]
    [MemberData(nameof(AllSelectorMatchingCombinations))]
    public void DaneTA_with_the_root_presented_in_the_chain(byte selector, byte matching)
    {
        var pki = Pki.Shared;
        var result = Verify(pki, [Tlsa.For(pki.Root.Public, 2, selector, matching)]);
        Assert.True(result.Success, string.Join("; ", result.Notes));
        Assert.Equal(2, result.Match!.Usage);
    }

    [Theory]
    [MemberData(nameof(AllSelectorMatchingCombinations))]
    public void DaneTA_with_an_intermediate_as_anchor(byte selector, byte matching)
    {
        var pki = Pki.Shared;
        var result = Verify(pki, [Tlsa.For(pki.Intermediate.Public, 2, selector, matching)], pki.WithoutRoot);
        Assert.True(result.Success, string.Join("; ", result.Notes));
    }

    [Fact]
    public void DaneTA_with_the_certificate_in_dns_does_not_need_it_presented()
    {
        var pki = new Pki();
        var result = Verify(pki, [Tlsa.For(pki.Root.Public, 2, 0, 0)], pki.WithoutRoot);
        Assert.True(result.Success, string.Join("; ", result.Notes));
    }

    [Fact]
    public void DaneTA_with_a_bare_public_key_in_dns_does_not_need_the_certificate_presented()
    {
        var pki = new Pki();
        var result = Verify(pki, [Tlsa.For(pki.Root.Public, 2, 1, 0)], pki.WithoutRoot);
        Assert.True(result.Success, string.Join("; ", result.Notes));
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 1)]
    [InlineData(0, 2)]
    [InlineData(1, 2)]
    public void DaneTA_hash_of_an_anchor_that_is_not_presented_cannot_anchor(byte selector, byte matching)
    {
        var pki = Pki.Shared;
        var result = Verify(pki, [Tlsa.For(pki.Root.Public, 2, selector, matching)], pki.WithoutRoot);
        Assert.False(result.Success);
        Assert.Equal(TlsResultType.ValidationFailure, result.Failure);
    }

    [Fact]
    public void DaneTA_works_with_rsa_chains()
    {
        var pki = new Pki(rsa: true);
        var result = Verify(pki, [Tlsa.For(pki.Root.Public, 2, 1, 1)]);
        Assert.True(result.Success, string.Join("; ", result.Notes));
    }

    [Fact]
    public void DaneTA_works_with_mixed_rsa_root_and_ecdsa_leaf()
    {
        var root = TestPki.CreateRoot(rsa: true);
        var leaf = TestPki.CreateLeaf(root, [Mx], rsa: false);
        var result = DaneVerifier.Verify([Tlsa.For(root.Public, 2, 1, 1)], leaf.Public, [leaf.Public, root.Public], Mx);
        Assert.True(result.Success, string.Join("; ", result.Notes));
    }

    [Fact]
    public void DaneTA_with_the_leaf_itself_as_anchor_is_accepted_when_the_name_matches()
    {
        var self = TestPki.CreateSelfSignedLeaf([Mx]);
        var result = DaneVerifier.Verify([Tlsa.For(self.Public, 2, 1, 1)], self.Public, [self.Public], Mx);
        Assert.True(result.Success);
    }

    [Fact]
    public void DaneTA_requires_the_name_to_match()
    {
        var pki = new Pki(names: ["other.example.org"]);
        var result = Verify(pki, [Tlsa.For(pki.Root.Public, 2, 1, 1)]);
        Assert.False(result.Success);
        Assert.Equal(TlsResultType.CertificateHostMismatch, result.Failure);
    }

    [Fact]
    public void DaneTA_accepts_additional_reference_names_for_cnamed_mx_hosts()
    {
        var pki = new Pki(names: ["real.example.org"]);
        var options = new DaneVerifyOptions { AdditionalReferenceNames = ["real.example.org"] };
        var result = Verify(pki, [Tlsa.For(pki.Root.Public, 2, 1, 1)], options: options);
        Assert.True(result.Success);
    }

    [Fact]
    public void DaneTA_accepts_a_single_label_wildcard_certificate()
    {
        var pki = new Pki(names: ["*.example.com"]);
        Assert.True(Verify(pki, [Tlsa.For(pki.Root.Public, 2, 1, 1)]).Success);
        Assert.False(Verify(pki, [Tlsa.For(pki.Root.Public, 2, 1, 1)], host: "a.b.example.com").Success);
    }

    [Fact]
    public void DaneTA_does_not_use_the_common_name()
    {
        var root = TestPki.CreateRoot();
        var leaf = TestPki.CreateLeaf(root, [], commonName: Mx);
        var result = DaneVerifier.Verify([Tlsa.For(root.Public, 2, 1, 1)], leaf.Public, [leaf.Public, root.Public], Mx);
        Assert.False(result.Success);
        Assert.Equal(TlsResultType.CertificateHostMismatch, result.Failure);
    }

    [Fact]
    public void DaneTA_rejects_an_expired_leaf_unless_the_clock_says_otherwise()
    {
        var pki = new Pki(leafNotBefore: DateTimeOffset.UtcNow.AddDays(-30), leafNotAfter: DateTimeOffset.UtcNow.AddDays(-1));
        var records = new[] { Tlsa.For(pki.Root.Public, 2, 1, 1) };

        var now = Verify(pki, records);
        Assert.False(now.Success);
        Assert.Equal(TlsResultType.CertificateExpired, now.Failure);

        var earlier = Verify(pki, records, options: new DaneVerifyOptions { Now = DateTimeOffset.UtcNow.AddDays(-10) });
        Assert.True(earlier.Success);
    }

    [Fact]
    public void DaneTA_rejects_a_not_yet_valid_leaf()
    {
        var pki = new Pki(leafNotBefore: DateTimeOffset.UtcNow.AddDays(1), leafNotAfter: DateTimeOffset.UtcNow.AddDays(30));
        var result = Verify(pki, [Tlsa.For(pki.Root.Public, 2, 1, 1)]);
        Assert.Equal(TlsResultType.CertificateExpired, result.Failure);
    }

    [Fact]
    public void DaneTA_rejects_a_leaf_signed_by_a_different_ca_even_when_the_names_agree()
    {
        var pki = new Pki();
        var rogueRoot = TestPki.CreateRoot("Rogue Root");
        var rogueLeaf = TestPki.CreateLeaf(rogueRoot, [Mx]);
        var result = DaneVerifier.Verify([Tlsa.For(pki.Root.Public, 2, 1, 1)], rogueLeaf.Public, [rogueLeaf.Public, rogueRoot.Public, pki.Root.Public], Mx);
        Assert.False(result.Success);
    }

    [Fact]
    public void DaneTA_rejects_a_forged_issuer_name_with_a_bad_signature()
    {
        // Same subject name as the real intermediate, but a different key: the signature on the leaf will not verify.
        var pki = new Pki();
        var fakeIntermediate = TestPki.CreateIntermediate(pki.Root, "Test Intermediate CA");
        var result = DaneVerifier.Verify([Tlsa.For(pki.Root.Public, 2, 1, 1)], pki.Leaf.Public, [pki.Leaf.Public, fakeIntermediate.Public, pki.Root.Public], Mx);
        Assert.False(result.Success);
    }

    [Fact]
    public void DaneTA_rejects_an_issuer_that_is_not_a_ca()
    {
        var root = TestPki.CreateRoot();
        var notCa = TestPki.CreateIntermediate(root, "Not A CA", isCa: false);
        var leaf = TestPki.CreateLeaf(notCa, [Mx]);
        var result = DaneVerifier.Verify([Tlsa.For(root.Public, 2, 1, 1)], leaf.Public, [leaf.Public, notCa.Public, root.Public], Mx);
        Assert.False(result.Success);
    }

    [Fact]
    public void DaneTA_stops_on_hostile_chains_with_many_certificates()
    {
        var pki = new Pki();
        var chain = new List<X509Certificate2> { pki.Leaf.Public };
        for (int i = 0; i < 60; i++)
        {
            chain.Add(TestPki.CreateIntermediate(pki.Root, "Test Intermediate CA").Public);
        }

        chain.Add(pki.Intermediate.Public);
        chain.Add(pki.Root.Public);
        var result = DaneVerifier.Verify([Tlsa.For(pki.Root.Public, 2, 1, 1)], pki.Leaf.Public, chain, Mx);
        // The real intermediate is beyond MaxChainCertificates, so anchoring fails, but the call returns promptly and cleanly.
        Assert.False(result.Success);
    }

    [Fact]
    public void Ee_record_wins_even_when_a_ta_record_fails()
    {
        var pki = new Pki(names: ["other.example.org"]);
        var result = Verify(pki, [Tlsa.For(pki.Root.Public, 2, 1, 1), Tlsa.For(pki.Leaf.Public, 3, 1, 1)]);
        Assert.True(result.Success);
        Assert.Equal(3, result.Match!.Usage);
    }

    // ---- record classification ----

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void Pkix_usages_are_ignored_for_smtp(byte usage)
    {
        var pki = new Pki();
        var result = Verify(pki, [Tlsa.For(pki.Leaf.Public, usage, 1, 1)]);
        Assert.False(result.Success);
        Assert.Equal(TlsResultType.TlsaInvalid, result.Failure);
        Assert.Contains(result.Notes, n => n.Contains("not used for SMTP"));
    }

    [Fact]
    public void Pkix_records_are_skipped_but_usable_records_still_work()
    {
        var pki = new Pki();
        var result = Verify(pki, [Tlsa.For(pki.Leaf.Public, 1, 1, 1), Tlsa.For(pki.Leaf.Public, 3, 1, 1)]);
        Assert.True(result.Success);
        Assert.Contains(result.Notes, n => n.Contains("not used for SMTP"));
    }

    [Theory]
    [InlineData(4, 1, 1, 32)]   // unknown usage
    [InlineData(3, 2, 1, 32)]   // unknown selector
    [InlineData(3, 1, 3, 32)]   // unknown matching type
    [InlineData(3, 1, 1, 31)]   // sha-256 with wrong length
    [InlineData(3, 1, 2, 32)]   // sha-512 with sha-256 length
    [InlineData(3, 1, 0, 0)]    // empty exact data
    public void Malformed_records_are_unusable(byte usage, byte selector, byte matching, int dataLength)
    {
        var pki = new Pki();
        var record = new TlsaRecord("_25._tcp.mx.example.com", 60, usage, selector, matching, new byte[dataLength]);
        Assert.False(TlsaRecordClassifier.IsUsable(record, out string? reason));
        Assert.NotNull(reason);
        var result = Verify(pki, [record]);
        Assert.False(result.Success);
        Assert.Equal(TlsResultType.TlsaInvalid, result.Failure);
    }

    [Fact]
    public void Empty_record_set_is_invalid()
    {
        var pki = new Pki();
        var result = Verify(pki, []);
        Assert.Equal(TlsResultType.TlsaInvalid, result.Failure);
    }

    [Fact]
    public void Only_a_ta_record_that_does_not_match_the_chain_is_a_validation_failure()
    {
        var pki = new Pki();
        var other = new Pki();
        var result = Verify(pki, [Tlsa.For(other.Root.Public, 2, 1, 1)]);
        Assert.Equal(TlsResultType.ValidationFailure, result.Failure);
        Assert.Contains(result.Notes, n => n.Contains("did not anchor") || n.Contains("no TLSA record matched"));
    }

    [Fact]
    public void Presentation_form_for_tls_rpt()
    {
        var record = new TlsaRecord("_25._tcp.mx.example.com", 60, 3, 1, 1, new byte[32]);
        string text = TlsaRecordClassifier.ToPresentation(record);
        Assert.StartsWith("_25._tcp.mx.example.com. IN TLSA ( 3 1 1 0000", text);
        Assert.EndsWith(" )", text);
    }

    [Fact]
    public void Arguments_are_validated()
    {
        var pki = new Pki();
        Assert.Throws<ArgumentNullException>(() => DaneVerifier.Verify(null!, pki.Leaf.Public, [], Mx));
        Assert.Throws<ArgumentNullException>(() => DaneVerifier.Verify([], null!, [], Mx));
        Assert.Throws<ArgumentNullException>(() => DaneVerifier.Verify([], pki.Leaf.Public, null!, Mx));
    }
}
