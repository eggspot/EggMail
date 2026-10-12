using System.Buffers;
using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Mta.Auth.AuthenticationResults;
using Mta.Core;

namespace Mta.Auth.Arc;

/// <summary>
/// Adds a new ARC set (RFC 8617 section 5.1) to a message: an ARC-Authentication-Results recording what this hop verified, an
/// ARC-Message-Signature over the message (<c>rsa-sha256</c>, relaxed/relaxed), and an ARC-Seal over the whole chain. One instance seals for one domain
/// and selector. Safe for concurrent use.
/// </summary>
/// <remarks>
/// <para>
/// Call it on the message exactly as it will leave this hop (all headers this hop adds, such as Received and Authentication-Results, already present),
/// then prepend <see cref="ArcSealResult.HeaderBytes"/>. The incoming chain result must come from <see cref="ArcValidator"/> run on the same message.
/// </para>
/// <para>
/// When the incoming chain failed, a set with <c>cv=fail</c> is added whose ARC-Seal covers only the new set (RFC 8617 section 5.1.1), unless a seal with
/// <c>cv=fail</c> is already the newest one, in which case nothing is added (section 5.1.2).
/// </para>
/// </remarks>
public sealed class ArcSealer : IDisposable
{
    private const int MaxSignedHeaderNames = ArcMessageSignatureHeader.MaxSignedHeaderNames;

    private readonly RSA _key;
    private readonly bool _ownsKey;
    private readonly IClock _clock;
    private readonly bool _oversign;
    private readonly int _maxHeaderCount;
    private readonly string[] _headerNames;
    private readonly string _domain;
    private readonly string _selector;

    /// <summary>Creates a sealer that uses (but does not own or dispose) <paramref name="privateKey"/>.</summary>
    /// <param name="options">Sealing domain, selector and header selection.</param>
    /// <param name="privateKey">An RSA private key of 1024 to 4096 bits (2048 recommended).</param>
    /// <exception cref="ArgumentException">The options or the key are unusable.</exception>
    public ArcSealer(ArcSealerOptions options, RSA privateKey)
        : this(options, privateKey, ownsKey: false)
    {
    }

    private ArcSealer(ArcSealerOptions options, RSA privateKey, bool ownsKey)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(privateKey);
        try
        {
            string domain = (options.Domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
            if (!ArcNames.IsValidDomain(domain)) { throw new ArgumentException("Domain is not a valid ASCII domain name.", nameof(options)); }
            string selector = options.Selector ?? string.Empty;
            if (!ArcNames.IsValidSelector(selector)) { throw new ArgumentException("Selector is not a valid DNS name.", nameof(options)); }
            if (options.MaxHeaderCount < 1) { throw new ArgumentOutOfRangeException(nameof(options), "MaxHeaderCount must be at least 1."); }

            int bits = privateKey.KeySize;
            if (bits < 1024 || bits > 4096) { throw new ArgumentException("RSA key size must be between 1024 and 4096 bits (2048 recommended).", nameof(privateKey)); }
            try
            {
                _ = privateKey.SignHash(new byte[32], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch (CryptographicException ex)
            {
                throw new ArgumentException("The RSA key cannot sign (is it a private key?).", nameof(privateKey), ex);
            }

            var names = new List<string>(21) { "From" };
            foreach (string raw in options.SignedHeaders ?? ArcSealerOptions.DefaultSignedHeaders)
            {
                string name = (raw ?? string.Empty).Trim();
                if (name.Length == 0 || !IsValidHeaderName(name)) { throw new ArgumentException("Invalid header name in SignedHeaders: '" + raw + "'.", nameof(options)); }
                if (name.StartsWith("arc-", StringComparison.OrdinalIgnoreCase)) { throw new ArgumentException("ARC headers cannot be listed in SignedHeaders.", nameof(options)); }
                if (!names.Exists(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase))) { names.Add(name); }
            }

            _key = privateKey;
            _ownsKey = ownsKey;
            _domain = domain;
            _selector = selector;
            _clock = options.Clock ?? SystemClock.Instance;
            _oversign = options.OversignHeaders;
            _maxHeaderCount = options.MaxHeaderCount;
            _headerNames = names.Select(n => n.ToLowerInvariant()).ToArray();
        }
        catch
        {
            if (ownsKey) { privateKey.Dispose(); }
            throw;
        }
    }

    /// <summary>The sealing domain, normalized to lower case.</summary>
    public string Domain => _domain;

    /// <summary>The selector.</summary>
    public string Selector => _selector;

    /// <summary>Creates a sealer from a PEM encoded private key (PKCS#8 or PKCS#1). The sealer owns the key.</summary>
    /// <param name="options">Sealing domain, selector and header selection.</param>
    /// <param name="privateKeyPem">The PEM text.</param>
    public static ArcSealer FromPem(ArcSealerOptions options, string privateKeyPem) =>
        new(options, Mta.Dkim.DkimKeyTools.LoadPrivateKeyPem(privateKeyPem), ownsKey: true);

    /// <summary>Seals using the Authentication-Results this hop computed, taken from a builder.</summary>
    /// <param name="rawMessage">The message as it will leave this hop, with CRLF line endings.</param>
    /// <param name="results">This hop's results (authserv-id, SPF, DKIM, DMARC, and the <c>arc=</c> result of the incoming chain).</param>
    /// <param name="incomingChain">The validation result of the chain the message arrived with.</param>
    public ArcSealResult Seal(ReadOnlySpan<byte> rawMessage, AuthenticationResultsBuilder results, ArcChainResult incomingChain)
    {
        ArgumentNullException.ThrowIfNull(results);
        return Seal(rawMessage, results.BuildFieldBody(), incomingChain);
    }

    /// <summary>Seals the message.</summary>
    /// <param name="rawMessage">The message as it will leave this hop, with CRLF line endings and a From header. It must not already carry the set being added.</param>
    /// <param name="authenticationResults">
    /// The Authentication-Results this hop computed, without the header name: <c>authserv-id; method=result ...</c>, as produced by
    /// <see cref="AuthenticationResultsBuilder.BuildFieldBody"/>. It becomes the body of the ARC-Authentication-Results.
    /// </param>
    /// <param name="incomingChain">The validation result of the chain the message arrived with (None when it carried none).</param>
    /// <exception cref="ArgumentException">
    /// The message has no From header or too many header fields, the Authentication-Results are not valid ASCII RFC 8601 syntax, or
    /// <paramref name="incomingChain"/> does not describe the message's ARC headers.
    /// </exception>
    public ArcSealResult Seal(ReadOnlySpan<byte> rawMessage, string authenticationResults, ArcChainResult incomingChain)
    {
        ArgumentNullException.ThrowIfNull(authenticationResults);
        ArgumentNullException.ThrowIfNull(incomingChain);
        string arBody = NormalizeAuthenticationResults(authenticationResults);

        var index = ArcHeaderIndex.Parse(rawMessage, _maxHeaderCount);
        try
        {
            if (index.TooManyFields) { throw new ArgumentException("The message has too many header fields to seal.", nameof(rawMessage)); }
            bool hasFrom = false;
            for (int i = 0; i < index.Count && !hasFrom; i++) { hasFrom = index.NameEquals(rawMessage, i, "from"u8); }
            if (!hasFrom) { throw new ArgumentException("The message has no From header.", nameof(rawMessage)); }

            ArcSet[] priorSets;
            int instance;
            ArcChainStatus cv;
            switch (incomingChain.Status)
            {
                case ArcChainStatus.None:
                    if (!ArcChainReader.TryScanInstances(rawMessage, in index, out int existing, out _) || existing != 0)
                    {
                        throw new ArgumentException("The chain result is None but the message carries ARC headers.", nameof(incomingChain));
                    }

                    priorSets = [];
                    instance = 1;
                    cv = ArcChainStatus.None;
                    break;

                case ArcChainStatus.Pass:
                    var read = ArcChainReader.Read(rawMessage, in index, int.MaxValue / 4, ArcHeaderNames.MaxInstance);
                    if (read.EarlyResult is not null || read.Sets.Length == 0 || read.Sets.Length != incomingChain.InstanceCount)
                    {
                        throw new ArgumentException("The chain result is Pass but does not match the ARC headers of the message.", nameof(incomingChain));
                    }

                    if (read.Sets.Length >= ArcHeaderNames.MaxInstance)
                    {
                        return ArcSealResult.NotSealed("the chain already has the maximum of " + ArcHeaderNames.MaxInstance + " ARC sets");
                    }

                    priorSets = read.Sets;
                    instance = read.Sets.Length + 1;
                    cv = ArcChainStatus.Pass;
                    break;

                default:
                    if (!ArcChainReader.TryScanInstances(rawMessage, in index, out int highest, out var highestSealStatus))
                    {
                        return ArcSealResult.NotSealed("the instance number of an ARC header cannot be read, so the next instance is unknown");
                    }

                    if (highestSealStatus == ArcChainStatus.Fail) { return ArcSealResult.NotSealed("the newest ARC-Seal already says cv=fail"); }
                    if (highest >= ArcHeaderNames.MaxInstance) { return ArcSealResult.NotSealed("the chain already has the maximum of " + ArcHeaderNames.MaxInstance + " ARC sets"); }
                    priorSets = [];
                    instance = highest + 1;
                    cv = ArcChainStatus.Fail;
                    break;
            }

            return SealCore(rawMessage, in index, priorSets, instance, cv, arBody);
        }
        finally
        {
            index.Dispose();
        }
    }

    /// <summary>Releases the key when the sealer owns it (created with <see cref="FromPem"/>).</summary>
    public void Dispose()
    {
        if (_ownsKey) { _key.Dispose(); }
    }

    private ArcSealResult SealCore(ReadOnlySpan<byte> message, in ArcHeaderIndex index, ArcSet[] priorSets, int instance, ArcChainStatus cv, string arBody)
    {
        var aar = new ArcBuffer(512);
        var ams = new ArcBuffer(1024);
        var seal = new ArcBuffer(768);
        var output = new ArcBuffer(2560);
        try
        {
            Span<char> number = stackalloc char[24];
            long now = _clock.UtcNow.ToUnixTimeSeconds();

            // ARC-Authentication-Results: i=N; authserv-id; results
            var aarWriter = new ArcHeaderWriter(ref aar);
            aarWriter.Raw("ARC-Authentication-Results:"u8);
            aarWriter.Token(Number("i=", instance, number, ';'));
            aarWriter.AuthenticationResultsBody(arBody);
            aarWriter.Raw("\r\n"u8);

            BuildMessageSignature(message, in index, instance, now, ref ams, number);
            BuildSeal(message, in index, priorSets, instance, cv, now, ref seal, aar.WrittenSpan, ams.WrittenSpan, number);

            output.Append(seal.WrittenSpan);
            output.Append(ams.WrittenSpan);
            output.Append(aar.WrittenSpan);
            return ArcSealResult.Sealed(instance, cv, output.WrittenSpan.ToArray());
        }
        finally
        {
            aar.Dispose();
            ams.Dispose();
            seal.Dispose();
            output.Dispose();
        }
    }

    private void BuildMessageSignature(ReadOnlySpan<byte> message, in ArcHeaderIndex index, int instance, long now, ref ArcBuffer output, Span<char> number)
    {
        var hList = new List<string>(24);
        for (int n = 0; n < _headerNames.Length; n++)
        {
            string name = _headerNames[n];
            for (int i = index.Count - 1; i >= 0; i--)
            {
                if (!index.NameEquals(message, i, name)) { continue; }
                if (hList.Count >= MaxSignedHeaderNames) { throw new ArgumentException("The message has too many instances of the signed headers.", nameof(message)); }
                hList.Add(name);
            }

            if (_oversign)
            {
                if (hList.Count >= MaxSignedHeaderNames) { throw new ArgumentException("The message has too many instances of the signed headers.", nameof(message)); }
                hList.Add(name);
            }
        }

        Span<byte> bodyHash = stackalloc byte[32];
        ArcCanonicalizer.HashBody(message.Slice(index.BodyOffset), relaxed: true, bodyHash);

        var writer = new ArcHeaderWriter(ref output);
        writer.Raw("ARC-Message-Signature:"u8);
        writer.Token(Number("i=", instance, number, ';'));
        writer.Token("a=rsa-sha256;");
        writer.Token("c=relaxed/relaxed;");
        writer.Token("d=" + _domain + ";");
        writer.Token("s=" + _selector + ";");
        writer.Token(Number("t=", now, number, ';'));
        writer.Token("h=");
        for (int i = 0; i < hList.Count; i++)
        {
            string segment = i < hList.Count - 1 ? hList[i] + ":" : hList[i];
            writer.Segment(segment);
        }

        writer.Raw(";"u8);

        Span<byte> bodyHashB64 = stackalloc byte[44];
        Base64.EncodeToUtf8(bodyHash, bodyHashB64, out _, out int bhLength);
        writer.Token("bh=");
        writer.Value(bodyHashB64.Slice(0, bhLength));
        writer.Raw(";"u8);
        writer.TokenKeepingRoom("b=", 12);

        // Hash the selected headers, then this header with an empty b= and no trailing CRLF, and sign.
        Span<byte> digest = stackalloc byte[32];
        ArcSignatureInput.HashMessageSignature(message, in index, hList, skipField: -1, relaxedHeaders: true, output.WrittenSpan, digest);
        AppendSignature(ref writer, digest);
        writer.Raw("\r\n"u8);
    }

    private void BuildSeal(
        ReadOnlySpan<byte> message,
        in ArcHeaderIndex index,
        ArcSet[] priorSets,
        int instance,
        ArcChainStatus cv,
        long now,
        ref ArcBuffer output,
        ReadOnlySpan<byte> aar,
        ReadOnlySpan<byte> ams,
        Span<char> number)
    {
        var writer = new ArcHeaderWriter(ref output);
        writer.Raw("ARC-Seal:"u8);
        writer.Token(Number("i=", instance, number, ';'));
        writer.Token("a=rsa-sha256;");
        writer.Token(cv switch { ArcChainStatus.Pass => "cv=pass;", ArcChainStatus.Fail => "cv=fail;", _ => "cv=none;" });
        writer.Token("d=" + _domain + ";");
        writer.Token("s=" + _selector + ";");
        writer.Token(Number("t=", now, number, ';'));
        writer.TokenKeepingRoom("b=", 12);

        Span<byte> digest = stackalloc byte[32];
        ArcSignatureInput.HashSeal(message, in index, priorSets, aar, ams, output.WrittenSpan, digest);
        AppendSignature(ref writer, digest);
        writer.Raw("\r\n"u8);
    }

    private void AppendSignature(ref ArcHeaderWriter writer, scoped ReadOnlySpan<byte> digest)
    {
        Span<byte> signature = stackalloc byte[512];
        if (!_key.TrySignHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, out int signatureLength))
        {
            throw new CryptographicException("Signing failed.");
        }

        Span<byte> signatureB64 = stackalloc byte[684];
        Base64.EncodeToUtf8(signature.Slice(0, signatureLength), signatureB64, out _, out int b64Length);
        writer.Value(signatureB64.Slice(0, b64Length));
    }

    private static ReadOnlySpan<char> Number(string prefix, long value, Span<char> scratch, char terminator)
    {
        prefix.CopyTo(scratch);
        value.TryFormat(scratch.Slice(prefix.Length), out int written, provider: CultureInfo.InvariantCulture);
        scratch[prefix.Length + written] = terminator;
        return scratch.Slice(0, prefix.Length + written + 1);
    }

    private static string NormalizeAuthenticationResults(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            if (c is '\r' or '\n') { continue; }
            if (c > 0x7E || (c < 0x20 && c != '\t')) { throw new ArgumentException("Authentication-Results must be printable ASCII.", nameof(value)); }
            sb.Append(c);
        }

        string body = sb.ToString().Trim(' ', '\t');
        if (!AuthenticationResultsHeader.TryParse(body, out _)) { throw new ArgumentException("Not a valid Authentication-Results value (authserv-id; method=result ...).", nameof(value)); }
        return body;
    }

    private static bool IsValidHeaderName(string name)
    {
        foreach (char c in name)
        {
            if (c <= 0x20 || c >= 0x7F || c == ':' || c == ';') { return false; }
        }

        return true;
    }
}
