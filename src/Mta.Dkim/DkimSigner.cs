using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Mta.Core;
using Mta.Dkim.Internal;

namespace Mta.Dkim;

/// <summary>
/// Creates DKIM-Signature headers (<c>rsa-sha256</c>, RFC 6376) for raw messages. One instance signs for one domain and selector; to sign for
/// several domains create several signers and prepend each header. The signer never emits <c>l=</c>. Safe for concurrent use.
/// </summary>
/// <remarks>
/// The input must be a complete message with CRLF line endings (as it is on the wire) containing a From header. The returned header
/// is folded, CRLF terminated and ready to prepend to the message. Allocation per call is the returned header plus a few small
/// objects; canonicalization and hashing are streamed over the input using pooled buffers.
/// </remarks>
public sealed class DkimSigner : IDisposable
{
    private const int MaxHeaderCount = 1024;
    private const int MaxLineLength = 78;

    private readonly RSA _key;
    private readonly bool _ownsKey;
    private readonly IClock _clock;
    private readonly bool _headerRelaxed;
    private readonly bool _bodyRelaxed;
    private readonly bool _oversign;
    private readonly bool _includeTimestamp;
    private readonly long? _lifetimeSeconds;
    private readonly string[] _headerNames;
    private readonly byte[][] _headerNameBytes;
    private readonly string[] _fixedTags;
    private readonly string? _identityTag;

    /// <summary>Creates a signer that uses (but does not own or dispose) <paramref name="privateKey"/>.</summary>
    public DkimSigner(DkimSignerOptions options, RSA privateKey)
        : this(options, privateKey, ownsKey: false)
    {
    }

    private DkimSigner(DkimSignerOptions options, RSA privateKey, bool ownsKey)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(privateKey);
        try
        {
            string domain = (options.Domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
            if (!DkimNames.IsValidDomain(domain)) { throw new DkimException("Domain is not a valid ASCII domain name."); }
            string selector = options.Selector ?? string.Empty;
            if (!DkimNames.IsValidSelector(selector)) { throw new DkimException("Selector is not a valid DNS name."); }

            int bits = privateKey.KeySize;
            if (bits < 1024 || bits > 4096) { throw new DkimException("RSA key size must be between 1024 and 4096 bits (2048 recommended)."); }
            try
            {
                _ = privateKey.SignHash(new byte[32], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch (CryptographicException ex)
            {
                throw new DkimException("The RSA key cannot sign (is it a private key?).", ex);
            }

            if (options.SignatureLifetime is { } life && life <= TimeSpan.Zero) { throw new DkimException("SignatureLifetime must be positive."); }

            _key = privateKey;
            _ownsKey = ownsKey;
            Domain = domain;
            Selector = selector;
            KeyBits = bits;
            _clock = options.Clock ?? SystemClock.Instance;
            _headerRelaxed = options.HeaderCanonicalization == DkimCanonicalization.Relaxed;
            _bodyRelaxed = options.BodyCanonicalization == DkimCanonicalization.Relaxed;
            _oversign = options.OversignHeaders;
            _includeTimestamp = options.IncludeTimestamp;
            _lifetimeSeconds = options.SignatureLifetime is { } l ? (long)l.TotalSeconds : null;

            var names = new List<string>(options.SignedHeaders?.Count + 1 ?? 21) { "From" };
            foreach (string raw in options.SignedHeaders ?? DkimSignerOptions.DefaultSignedHeaders)
            {
                string name = (raw ?? string.Empty).Trim();
                if (name.Length == 0 || !IsValidHeaderName(name)) { throw new DkimException("Invalid header name in SignedHeaders: '" + raw + "'."); }
                if (!names.Exists(n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase))) { names.Add(name); }
            }

            _headerNames = names.ToArray();
            _headerNameBytes = new byte[_headerNames.Length][];
            for (int i = 0; i < _headerNames.Length; i++) { _headerNameBytes[i] = Encoding.ASCII.GetBytes(_headerNames[i]); }

            _fixedTags =
            [
                "v=1;",
                "a=rsa-sha256;",
                "c=" + (_headerRelaxed ? "relaxed" : "simple") + "/" + (_bodyRelaxed ? "relaxed" : "simple") + ";",
                "d=" + domain + ";",
                "s=" + selector + ";",
            ];

            if (options.Identity is { } identity)
            {
                if (!DkimNames.IsIdentityWithin(identity, domain)) { throw new DkimException("Identity must be an address whose domain is the signing domain or one of its subdomains."); }
                _identityTag = "i=" + EncodeQuotedPrintable(identity) + ";";
            }
        }
        catch
        {
            if (ownsKey) { privateKey.Dispose(); }
            throw;
        }
    }

    /// <summary>The signing domain, normalized to lower case.</summary>
    public string Domain { get; }

    public string Selector { get; }

    /// <summary>Size of the signing key in bits.</summary>
    public int KeyBits { get; }

    /// <summary>Creates a signer from a PEM encoded private key (PKCS#8 <c>PRIVATE KEY</c> or PKCS#1 <c>RSA PRIVATE KEY</c>). The signer owns the key.</summary>
    public static DkimSigner FromPem(DkimSignerOptions options, string privateKeyPem) =>
        new(options, DkimKeyTools.LoadPrivateKeyPem(privateKeyPem), ownsKey: true);

    /// <summary>Creates a signer from a DER encoded PKCS#8 (or PKCS#1) private key. The signer owns the key.</summary>
    public static DkimSigner FromDer(DkimSignerOptions options, ReadOnlySpan<byte> privateKeyDer) =>
        new(options, DkimKeyTools.LoadPrivateKeyDer(privateKeyDer), ownsKey: true);

    /// <summary>Signs the message and returns the complete <c>DKIM-Signature: ...</c> header, folded and CRLF terminated.</summary>
    /// <exception cref="DkimException">The message has no From header or too many header fields.</exception>
    public string Sign(ReadOnlySpan<byte> rawMessage)
    {
        var buffer = new PooledBuffer(1024);
        try
        {
            SignCore(rawMessage, ref buffer);
            return Encoding.ASCII.GetString(buffer.WrittenSpan);
        }
        finally
        {
            buffer.Dispose();
        }
    }

    /// <summary>Like <see cref="Sign(ReadOnlySpan{byte})"/> but returns the header as ASCII bytes.</summary>
    public ReadOnlyMemory<byte> SignToBytes(ReadOnlySpan<byte> rawMessage)
    {
        var buffer = new PooledBuffer(1024);
        try
        {
            SignCore(rawMessage, ref buffer);
            return buffer.WrittenSpan.ToArray();
        }
        finally
        {
            buffer.Dispose();
        }
    }

    /// <summary>
    /// Signs the message and returns an array rented from <see cref="ArrayPool{T}.Shared"/> that holds the <c>DKIM-Signature</c> field followed by the message
    /// itself (<paramref name="length"/> bytes of it): what goes on the wire for a signed message, built without the separate array of the field that
    /// <see cref="SignToBytes"/> returns. The caller returns the array to the pool.
    /// </summary>
    public byte[] SignPrepended(ReadOnlySpan<byte> rawMessage, out int length)
    {
        var buffer = new PooledBuffer(1024);
        try
        {
            SignCore(rawMessage, ref buffer);
            var signature = buffer.WrittenSpan;
            byte[] rented = ArrayPool<byte>.Shared.Rent(signature.Length + rawMessage.Length);
            signature.CopyTo(rented);
            rawMessage.CopyTo(rented.AsSpan(signature.Length));
            length = signature.Length + rawMessage.Length;
            return rented;
        }
        finally
        {
            buffer.Dispose();
        }
    }

    /// <summary>Signs the message and writes the header into <paramref name="output"/> without any intermediate string or array. Returns the number of bytes written.</summary>
    public int Sign(ReadOnlySpan<byte> rawMessage, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var buffer = new PooledBuffer(1024);
        try
        {
            SignCore(rawMessage, ref buffer);
            var written = buffer.WrittenSpan;
            written.CopyTo(output.GetSpan(written.Length));
            output.Advance(written.Length);
            return written.Length;
        }
        finally
        {
            buffer.Dispose();
        }
    }

    public void Dispose()
    {
        if (_ownsKey) { _key.Dispose(); }
    }

    private void SignCore(ReadOnlySpan<byte> message, ref PooledBuffer output)
    {
        var table = HeaderTable.Parse(message, MaxHeaderCount);
        var hList = new PooledBuffer(256);
        IncrementalHash? hash = null;
        try
        {
            if (table.TooManyFields) { throw new DkimException("The message has too many header fields to sign."); }

            bool hasFrom = false;
            for (int i = 0; i < table.Count && !hasFrom; i++) { hasFrom = table.NameEquals(message, i, "from"u8); }
            if (!hasFrom) { throw new DkimException("The message has no From header; DKIM requires From to be signed."); }

            hash = Sha256Pool.Rent();
            Span<byte> scratch = stackalloc byte[1024];
            Span<byte> bodyHash = stackalloc byte[32];

            var bodySink = new HashSink(hash, scratch);
            Canonicalizer.WriteBody(message.Slice(table.BodyOffset), _bodyRelaxed, ref bodySink);
            bodySink.Flush();
            hash.GetHashAndReset(bodyHash);

            // Select and canonicalize the signed header instances, bottom-up per name, listing each in h=.
            var headerSink = new HashSink(hash, scratch);
            int listed = 0;
            for (int n = 0; n < _headerNames.Length; n++)
            {
                var nameBytes = _headerNameBytes[n];
                for (int i = table.Count - 1; i >= 0; i--)
                {
                    if (!table.NameEquals(message, i, nameBytes)) { continue; }
                    if (++listed > DkimSignatureHeader.MaxSignedHeaderNames) { throw new DkimException("The message has too many instances of the signed headers."); }
                    Canonicalizer.WriteHeader(table.Raw(message, i), _headerRelaxed, appendCrlf: true, ref headerSink);
                    if (hList.Length > 0) { hList.Append((byte)':'); }
                    hList.Append(nameBytes);
                }

                if (_oversign)
                {
                    // One more instance than exists: a verifier finds nothing for it, so adding such a header later breaks the signature.
                    if (++listed > DkimSignatureHeader.MaxSignedHeaderNames) { throw new DkimException("The message has too many instances of the signed headers."); }
                    if (hList.Length > 0) { hList.Append((byte)':'); }
                    hList.Append(nameBytes);
                }
            }

            // Build the signature header up to and including "b=", folded.
            var writer = new SignatureWriter(ref output);
            writer.Raw("DKIM-Signature:"u8);
            foreach (string tag in _fixedTags) { writer.Token(tag); }
            Span<char> number = stackalloc char[24];
            long now = _clock.UtcNow.ToUnixTimeSeconds();
            if (_includeTimestamp) { writer.Token(Number("t=", now, number)); }
            if (_lifetimeSeconds is long life) { writer.Token(Number("x=", now + life, number)); }
            if (_identityTag is not null) { writer.Token(_identityTag); }

            writer.Token("h=");
            var names = hList.WrittenSpan;
            while (true)
            {
                int colon = names.IndexOf((byte)':');
                var segment = colon < 0 ? names : names.Slice(0, colon + 1);
                writer.Segment(segment);
                if (colon < 0) { break; }
                names = names.Slice(colon + 1);
            }

            writer.Raw(";"u8);

            Span<byte> bodyHashB64 = stackalloc byte[44];
            Base64.EncodeToUtf8(bodyHash, bodyHashB64, out _, out int bhLength);
            writer.Token("bh=");
            writer.Value(bodyHashB64.Slice(0, bhLength));
            writer.Raw(";"u8);

            writer.TokenKeepingRoom("b=", 12);

            // Hash the signature header (without b= value, without trailing CRLF) last, then sign.
            Canonicalizer.WriteHeader(output.WrittenSpan, _headerRelaxed, appendCrlf: false, ref headerSink);
            headerSink.Flush();
            Span<byte> digest = stackalloc byte[32];
            Sha256Pool.FinishAndReturn(hash, digest);
            hash = null;

            Span<byte> signature = stackalloc byte[512];
            if (!_key.TrySignHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, out int signatureLength))
            {
                throw new DkimException("Signing failed.");
            }

            Span<byte> signatureB64 = stackalloc byte[684];
            Base64.EncodeToUtf8(signature.Slice(0, signatureLength), signatureB64, out _, out int b64Length);
            writer.Value(signatureB64.Slice(0, b64Length));
            writer.Raw("\r\n"u8);
        }
        finally
        {
            hList.Dispose();
            table.Dispose();
        }
    }

    private static ReadOnlySpan<char> Number(string prefix, long value, Span<char> scratch)
    {
        prefix.CopyTo(scratch);
        value.TryFormat(scratch.Slice(prefix.Length), out int written);
        scratch[prefix.Length + written] = ';';
        return scratch.Slice(0, prefix.Length + written + 1);
    }

    private static bool IsValidHeaderName(string name)
    {
        foreach (char c in name)
        {
            if (c <= 0x20 || c >= 0x7F || c == ':' || c == ';') { return false; }
        }

        return true;
    }

    internal static string EncodeQuotedPrintable(string value)
    {
        var sb = new StringBuilder(value.Length + 8);
        foreach (byte b in Encoding.UTF8.GetBytes(value))
        {
            if (b is >= 0x21 and <= 0x7E && b != (byte)';' && b != (byte)'=' && b != (byte)'|')
            {
                sb.Append((char)b);
            }
            else
            {
                sb.Append('=').Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
            }
        }

        return sb.ToString();
    }
}
