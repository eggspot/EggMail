using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mta.Dns;
using Mta.Tls.Dane;

namespace Mta.Fuzz;

/// <summary>
/// DANE verification of an MX's certificate chain against its TLSA records (RFC 7672). Both are attacker-controlled: the records come from
/// the destination's DNS zone and the extra chain certificates from the server. The chain itself is a fixed, real one made at start (a CA,
/// a leaf it signed, an expired leaf it signed and an unrelated self-signed certificate), so that the matching and path-building code runs
/// against real signatures.
/// <para>Input: a flags byte (bit 0: present the expired leaf; bits 1-2: which MX name is checked; bit 3: leave the CA out of the presented
/// chain), then records of <c>usage selector matching source length</c>. Source 0 takes <c>length</c> (two bytes) raw association bytes from
/// the input; 1, 2 and 3 derive the data from the leaf, the CA or the unrelated certificate with the record's selector and matching type,
/// and a non-zero length byte then tampers with it; 4 takes <c>length</c> (two bytes) bytes as one more DER certificate presented by the
/// server.</para>
/// <para>The main invariant: a fuzzer cannot forge a hash or a signature, so a verification that succeeds must rest on an untampered record
/// derived from the real chain (the leaf, or the CA for DANE-TA), and a DANE-TA success must also satisfy the name and validity checks.</para>
/// </summary>
internal static class DaneTarget
{
    private const int MaxRecords = 8;
    private static readonly DateTimeOffset Now = new(2026, 10, 13, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] MxNames = ["mx.example.com", "a.mx.example.net", "other.example", "b.a.mx.example.net"];
    private static readonly Lazy<Fixture> Shared = new(() => new Fixture());

    public static FuzzTarget Create() => new("dane", "DANE verifier (TLSA record use, matching, DANE-TA path building against hostile chains)", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 6000,
        MaxInputLength = 16 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        var fixture = Shared.Value;
        byte flags = input.Length > 0 ? input[0] : (byte)0;
        bool expiredLeaf = (flags & 1) != 0;
        string mxName = MxNames[(flags >> 1) & 3];
        var leaf = expiredLeaf ? fixture.ExpiredLeaf : fixture.Leaf;
        var chain = new List<X509Certificate2> { leaf };
        if ((flags & 8) == 0)
        {
            chain.Add(fixture.Ca);
        }

        var records = new List<TlsaRecord>();
        var trusted = new List<TlsaRecord>();   // untampered, derived from the leaf or the CA
        int i = 1;
        while (i + 5 <= input.Length && records.Count < MaxRecords)
        {
            byte usage = input[i], selector = input[i + 1], matching = input[i + 2], source = input[i + 3];
            i += 4;
            switch (source % 5)
            {
                case 0:
                {
                    byte[] data = TakeLengthPrefixed(input, ref i);
                    records.Add(new TlsaRecord("_25._tcp.mx.example.com", 300, usage, selector, matching, data));
                    break;
                }

                case 4:
                {
                    byte[] der = TakeLengthPrefixed(input, ref i);
                    try
                    {
                        chain.Add(X509CertificateLoader.LoadCertificate(der));
                    }
                    catch (CryptographicException)
                    {
                        // A server cannot present what TLS itself cannot decode.
                    }

                    break;
                }

                default:
                {
                    byte tamper = input[i++];
                    var from = (source % 5) switch { 1 => leaf, 2 => fixture.Ca, _ => fixture.Unrelated };
                    byte[] data = Derive(from, selector, matching);
                    if (tamper != 0 && data.Length > 0)
                    {
                        data[tamper % data.Length] ^= tamper;
                    }

                    var record = new TlsaRecord("_25._tcp.mx.example.com", 300, usage, selector, matching, data);
                    records.Add(record);
                    if (data.Length > 0 && (source % 5) is 1 or 2 && (tamper == 0 || StillCarriesTheKey(data, selector, matching, from)))
                    {
                        trusted.Add(record);
                    }

                    break;
                }
            }
        }

        var result = DaneVerifier.Verify(records, leaf, chain, mxName, new DaneVerifyOptions { Now = Now });
        Guard.Check(result.Notes.Count > 0, "a verification without any note");
        Guard.Check(result.Success == (result.Match is not null), "success and match disagree");
        Guard.Check(result.Success == (result.Failure is null), "success and failure disagree");

        bool anyUsable = records.Any(r => TlsaRecordClassifier.IsUsable(r, out _));
        if (!anyUsable)
        {
            Guard.Check(!result.Success && result.Failure == Mta.Tls.TlsResultType.TlsaInvalid, "no usable record must give tlsa-invalid");
        }

        foreach (var record in records)
        {
            _ = TlsaRecordClassifier.ToPresentation(record);
        }

        if (!result.Success)
        {
            return;
        }

        var match = result.Match!;
        Guard.Check(match.Usage is 2 or 3, $"matched a record of usage {match.Usage}");
        Guard.Check(
            trusted.Any(r => r.Usage == match.Usage && r.Selector == match.Selector && r.MatchingType == match.MatchingType && TlsaRecordClassifier.IsUsable(r, out _)),
            $"authenticated by a record that does not come from the real chain ({match.Usage} {match.Selector} {match.MatchingType})");
        if (match.Usage == 2)
        {
            Guard.Check(!expiredLeaf, "DANE-TA accepted an expired leaf");
            Guard.Check(mxName is "mx.example.com" or "a.mx.example.net", $"DANE-TA accepted a certificate for another name: {mxName}");
        }
    }

    /// <summary>
    /// Whether a tampered full certificate or bare key still names the real key (and, for a certificate, the real subject): a byte flipped in
    /// the certificate's own signature, for example, changes nothing a DANE-TA anchor carried in DNS is used for (RFC 7671 section 5.2.2).
    /// </summary>
    private static bool StillCarriesTheKey(byte[] data, byte selector, byte matching, X509Certificate2 source)
    {
        if (matching != 0)
        {
            return false;
        }

        byte[] realKey = source.PublicKey.ExportSubjectPublicKeyInfo();
        try
        {
            if (selector == 0)
            {
                using var certificate = X509CertificateLoader.LoadCertificate(data);
                return certificate.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(realKey)
                    && certificate.SubjectName.RawData.AsSpan().SequenceEqual(source.SubjectName.RawData);
            }

            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(data, out _);
            return key.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(realKey);
        }
        catch (Exception ex) when (ex is CryptographicException or NotSupportedException)   // an unknown curve is PlatformNotSupportedException
        {
            return false;
        }
    }

    private static byte[] TakeLengthPrefixed(ReadOnlySpan<byte> input, ref int i)
    {
        if (i + 2 > input.Length)
        {
            i = input.Length;
            return [];
        }

        int length = Math.Min((input[i] << 8) | input[i + 1], input.Length - i - 2);
        byte[] data = input.Slice(i + 2, length).ToArray();
        i += 2 + length;
        return data;
    }

    /// <summary>The association data a correct record for <paramref name="certificate"/> has (empty for an unknown selector or matching type).</summary>
    private static byte[] Derive(X509Certificate2 certificate, byte selector, byte matching)
    {
        byte[]? selected = selector switch
        {
            0 => certificate.RawData,
            1 => certificate.PublicKey.ExportSubjectPublicKeyInfo(),
            _ => null,
        };
        return (selected, matching) switch
        {
            (null, _) => [],
            (_, 0) => selected,
            (_, 1) => SHA256.HashData(selected),
            (_, 2) => SHA512.HashData(selected),
            _ => [],
        };
    }

    private static byte[] Record(byte usage, byte selector, byte matching, byte source, byte tamper = 0) => [usage, selector, matching, source, tamper];

    private static byte[] Raw(byte usage, byte selector, byte matching, byte source, byte[] data) =>
        [usage, selector, matching, source, (byte)(data.Length >> 8), (byte)data.Length, .. data];

    private static IReadOnlyList<byte[]> Seeds() =>
    [
        [0, .. Record(3, 1, 1, 1)],                                     // DANE-EE SPKI SHA-256 of the leaf
        [0, .. Record(3, 0, 0, 1)],                                     // DANE-EE full leaf certificate
        [0, .. Record(2, 1, 1, 2)],                                     // DANE-TA SPKI SHA-256 of the CA
        [8, .. Record(2, 0, 0, 2)],                                     // DANE-TA full CA certificate carried in DNS, CA not presented
        [8, .. Record(2, 1, 0, 2)],                                     // DANE-TA bare CA key carried in DNS
        [1, .. Record(2, 1, 2, 2)],                                     // expired leaf under DANE-TA: refused
        [1, .. Record(3, 1, 2, 1)],                                     // expired leaf under DANE-EE: accepted
        [4, .. Record(2, 1, 1, 2)],                                     // wrong MX name under DANE-TA
        [6, .. Record(2, 1, 1, 2)],                                     // wildcard does not cover two labels
        [2, .. Record(2, 1, 1, 2)],                                     // wildcard name
        [0, .. Record(3, 1, 1, 1, 7)],                                  // tampered hash
        [0, .. Record(3, 1, 1, 3), .. Record(2, 0, 0, 3)],              // the unrelated certificate as EE and TA
        [0, .. Record(1, 1, 1, 1), .. Record(0, 0, 1, 2), .. Record(9, 2, 3, 1)],   // PKIX usages and unknown values: tlsa-invalid
        [0, .. Raw(3, 1, 1, 0, new byte[31])],                          // a hash of the wrong length
        [0, .. Raw(2, 1, 0, 0, [0x30, 0x03, 0x02, 0x01, 0x00])],        // a hostile bare key
        [0, .. Raw(2, 0, 0, 0, [0x30, 0x82, 0xFF, 0xFF, 0x30])],        // a truncated certificate as a trust anchor
        [8, .. Raw(0, 0, 0, 4, [0x30, 0x82, 0x00, 0x00]), .. Record(2, 1, 1, 2)],   // junk presented as a chain certificate
    ];

    private static IReadOnlyList<byte[]> Tokens() =>
    [
        [3, 1, 1, 1, 0], [2, 1, 1, 2, 0], [2, 0, 0, 2, 0], [2, 1, 0, 2, 0], [3, 0, 0, 1, 0], [2, 1, 2, 2, 0], [0, 0, 0, 4, 0, 0], [0x30, 0x82], [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
        [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01], [0x05, 0x00], [0xFF], [0x00],
    ];

    private sealed class Fixture
    {
        public Fixture()
        {
            var notBefore = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
            var notAfter = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
            using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var caRequest = new CertificateRequest("CN=Fuzz DANE CA", caKey, HashAlgorithmName.SHA256);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            using var ca = caRequest.CreateSelfSigned(notBefore.AddYears(-6), notAfter.AddYears(5));   // wide enough to have issued the expired leaf
            Ca = X509CertificateLoader.LoadCertificate(ca.RawData);

            Leaf = MakeLeaf(ca, notBefore, notAfter, 1);
            ExpiredLeaf = MakeLeaf(ca, notBefore.AddYears(-2), notBefore.AddYears(-1), 2);

            using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var otherRequest = new CertificateRequest("CN=Fuzz DANE CA", otherKey, HashAlgorithmName.SHA256);   // same name, other key
            otherRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using var other = otherRequest.CreateSelfSigned(notBefore.AddYears(-6), notAfter.AddYears(5));
            Unrelated = X509CertificateLoader.LoadCertificate(other.RawData);
        }

        public X509Certificate2 Ca { get; }

        public X509Certificate2 Leaf { get; }

        public X509Certificate2 ExpiredLeaf { get; }

        public X509Certificate2 Unrelated { get; }

        private static X509Certificate2 MakeLeaf(X509Certificate2 issuer, DateTimeOffset notBefore, DateTimeOffset notAfter, byte serial)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=mx.example.com", key, HashAlgorithmName.SHA256);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("mx.example.com");
            names.AddDnsName("*.mx.example.net");
            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            using var signed = request.Create(issuer, notBefore, notAfter, [serial]);
            return X509CertificateLoader.LoadCertificate(signed.RawData);
        }
    }
}
