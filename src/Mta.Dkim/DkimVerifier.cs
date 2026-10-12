using System.Buffers;
using System.Security.Cryptography;
using Mta.Dkim.Internal;
using Mta.Dns;

namespace Mta.Dkim;

/// <summary>
/// Verifies the DKIM signatures of a message (RFC 6376 with the RFC 8301 algorithm and key size rules: <c>rsa-sha256</c> only,
/// keys of at least 1024 bits). Safe for concurrent use. <see cref="VerifyAsync"/> never throws for bad input; hostile input
/// is bounded by <see cref="DkimVerifierOptions"/>.
/// </summary>
public sealed class DkimVerifier
{
    private readonly IDnsResolver _dns;
    private readonly DkimVerifierOptions _options;

    public DkimVerifier(IDnsResolver dns, DkimVerifierOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(dns);
        _dns = dns;
        _options = options ?? new DkimVerifierOptions();
        if (_options.MaxSignaturesVerified < 1) { throw new ArgumentOutOfRangeException(nameof(options), "MaxSignaturesVerified must be at least 1."); }
        if (_options.MaxHeaderCount < 1) { throw new ArgumentOutOfRangeException(nameof(options), "MaxHeaderCount must be at least 1."); }
    }

    /// <summary>
    /// Verifies every DKIM-Signature header (up to <see cref="DkimVerifierOptions.MaxSignaturesVerified"/>) independently and returns one result per
    /// header, in message order. A message without any signature yields a single <see cref="DkimStatus.None"/> result.
    /// The message must use CRLF line endings, as it does on the wire.
    /// </summary>
    public async ValueTask<IReadOnlyList<DkimVerificationResult>> VerifyAsync(ReadOnlyMemory<byte> rawMessage, CancellationToken cancellationToken = default)
    {
        try
        {
            return await VerifyCoreAsync(rawMessage, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Last line of defence: verification must never take the caller down. The exception type is reported, never its message.
            return [new DkimVerificationResult(DkimStatus.TempError, "internal error during verification (" + ex.GetType().Name + ")", DkimFailure.InternalError)];
        }
    }

    private async ValueTask<IReadOnlyList<DkimVerificationResult>> VerifyCoreAsync(ReadOnlyMemory<byte> message, CancellationToken ct)
    {
        var table = HeaderTable.Parse(message.Span, _options.MaxHeaderCount);
        Dictionary<string, KeyLookup>? keys = null;
        try
        {
            if (table.TooManyFields)
            {
                return [new DkimVerificationResult(DkimStatus.Neutral, "message has too many header fields", DkimFailure.TooManyHeaders)];
            }

            List<int>? signatureFields = null;
            for (int i = 0; i < table.Count; i++)
            {
                if (table.NameEquals(message.Span, i, "dkim-signature"u8))
                {
                    (signatureFields ??= []).Add(i);
                }
            }

            if (signatureFields is null)
            {
                return [new DkimVerificationResult(DkimStatus.None, "message is not signed", DkimFailure.NoSignature)];
            }

            var results = new List<DkimVerificationResult>(signatureFields.Count);
            var bodyHashes = new BodyHashCache();
            int verified = 0;
            foreach (int fieldIndex in signatureFields)
            {
                if (verified >= _options.MaxSignaturesVerified)
                {
                    results.Add(new DkimVerificationResult(DkimStatus.Neutral, "signature not verified: more than " + _options.MaxSignaturesVerified + " signatures", DkimFailure.SignatureLimitExceeded));
                    continue;
                }

                verified++;
                var sig = ParseSignature(message.Span, in table, fieldIndex, out var early);
                if (early is not null)
                {
                    results.Add(early);
                    continue;
                }

                var key = await GetKeyAsync(sig.Domain!, sig.Selector!, keys ??= new Dictionary<string, KeyLookup>(StringComparer.OrdinalIgnoreCase), ct).ConfigureAwait(false);
                results.Add(key.Error is not null ? Build(sig, key.Error.Status, key.Error.Failure, key.Error.Reason, key) : Check(message.Span, in table, fieldIndex, sig, key, bodyHashes));
            }

            return results;
        }
        finally
        {
            table.Dispose();
            if (keys is not null)
            {
                foreach (var k in keys.Values) { k.Rsa?.Dispose(); }
            }
        }
    }

    private DkimSignatureHeader ParseSignature(ReadOnlySpan<byte> message, in HeaderTable table, int fieldIndex, out DkimVerificationResult? early)
    {
        var raw = table.Raw(message, fieldIndex);
        if (raw.Length >= 2 && raw[^2] == (byte)'\r' && raw[^1] == (byte)'\n') { raw = raw.Slice(0, raw.Length - 2); }
        var sig = DkimSignatureHeader.Parse(raw, table[fieldIndex].ColonOffset, _options.MaxSignatureHeaderLength);
        early = null;
        if (sig.HasError)
        {
            early = Build(sig, sig.ErrorStatus, sig.ErrorFailure, sig.ErrorReason!, null);
            return sig;
        }

        if (_options.RejectBodyLengthLimit && sig.BodyLength is not null)
        {
            early = Build(sig, DkimStatus.Fail, DkimFailure.BodyLengthRejected, "signatures with l= are rejected by policy", null);
            return sig;
        }

        if (sig.Expiration is long expires)
        {
            long now = _options.Clock.UtcNow.ToUnixTimeSeconds();
            if (now > expires + (long)_options.ClockSkew.TotalSeconds)
            {
                early = Build(sig, DkimStatus.Fail, DkimFailure.Expired, "signature expired", null);
            }
        }

        return sig;
    }

    private async ValueTask<KeyLookup> GetKeyAsync(string domain, string selector, Dictionary<string, KeyLookup> cache, CancellationToken ct)
    {
        string name = selector + "._domainkey." + domain;
        if (cache.TryGetValue(name, out var cached)) { return cached; }

        var result = await LookupKeyAsync(name, ct).ConfigureAwait(false);
        cache[name] = result;
        return result;
    }

    private async ValueTask<KeyLookup> LookupKeyAsync(string name, CancellationToken ct)
    {
        DnsResponse response;
        try
        {
            response = await _dns.QueryAsync(name, DnsRecordType.TXT, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (DnsException)
        {
            return KeyLookup.Failed(DkimStatus.TempError, DkimFailure.KeyDnsError, "DNS lookup of the key failed");
        }
        catch (Exception)
        {
            return KeyLookup.Failed(DkimStatus.TempError, DkimFailure.KeyDnsError, "DNS lookup of the key failed");
        }

        if (response.Rcode == DnsRcode.NameError)
        {
            return KeyLookup.Failed(DkimStatus.PermError, DkimFailure.KeyNotFound, "no key record found (NXDOMAIN)");
        }

        if (response.Rcode != DnsRcode.NoError)
        {
            return KeyLookup.Failed(DkimStatus.TempError, DkimFailure.KeyDnsError, "DNS lookup of the key failed (" + response.Rcode + ")");
        }

        DkimKeyRecord? record = null;
        string? firstError = null;
        bool sawTxt = false;
        foreach (var answer in response.Answers)
        {
            if (answer is not TxtRecord txt) { continue; }
            sawTxt = true;
            if (DkimKeyRecord.TryParse(txt.Text, out var parsed, out string? error))
            {
                record = parsed;
                break;
            }

            firstError ??= error;
        }

        if (record is null)
        {
            return sawTxt
                ? KeyLookup.Failed(DkimStatus.PermError, DkimFailure.MalformedKeyRecord, "malformed key record: " + firstError)
                : KeyLookup.Failed(DkimStatus.PermError, DkimFailure.KeyNotFound, "no key record found");
        }

        if (record.IsRevoked)
        {
            return new KeyLookup(record, null, 0) { Error = new KeyError(DkimStatus.Fail, DkimFailure.KeyRevoked, "key revoked") };
        }

        if (record.KeyType != "rsa")
        {
            return new KeyLookup(record, null, 0) { Error = new KeyError(DkimStatus.PermError, DkimFailure.KeyTypeMismatch, "key type " + record.KeyType + " does not match rsa-sha256") };
        }

        if (!record.AllowsSha256 || !record.AllowsEmail)
        {
            return new KeyLookup(record, null, 0) { Error = new KeyError(DkimStatus.PermError, DkimFailure.KeyDoesNotPermit, "key record does not permit sha256 for email") };
        }

        RSA? rsa = null;
        try
        {
            rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(record.PublicKeySubjectPublicKeyInfo, out _);
            int bits = rsa.KeySize;
            if (bits < _options.MinimumKeyBits)
            {
                rsa.Dispose();
                return new KeyLookup(record, null, bits) { Error = new KeyError(DkimStatus.Fail, DkimFailure.KeyTooSmall, "key too small (" + bits + " bits, minimum " + _options.MinimumKeyBits + ")") };
            }

            if (bits > _options.MaximumKeyBits)
            {
                rsa.Dispose();
                return new KeyLookup(record, null, bits) { Error = new KeyError(DkimStatus.PermError, DkimFailure.KeyTooLarge, "key too large (" + bits + " bits, maximum " + _options.MaximumKeyBits + ")") };
            }

            return new KeyLookup(record, rsa, bits);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            rsa?.Dispose();
            return new KeyLookup(record, null, 0) { Error = new KeyError(DkimStatus.PermError, DkimFailure.MalformedKeyRecord, "invalid public key in key record") };
        }
    }

    private DkimVerificationResult Check(ReadOnlySpan<byte> message, in HeaderTable table, int fieldIndex, DkimSignatureHeader sig, KeyLookup key, BodyHashCache bodyHashes)
    {
        if (key.Record!.IsStrictIdentity && sig.Identity is not null
            && !sig.Identity.AsSpan(sig.Identity.LastIndexOf('@') + 1).Equals(sig.Domain, StringComparison.OrdinalIgnoreCase))
        {
            return Build(sig, DkimStatus.Fail, DkimFailure.InvalidIdentity, "key record requires i= to match d= exactly (t=s)", key);
        }

        // Body hash (cached across signatures with the same canonicalization and l=).
        var body = message.Slice(table.BodyOffset);
        long limit = sig.BodyLength ?? long.MaxValue;
        var cached = bodyHashes.Find(sig.BodyRelaxed, limit);
        if (cached is null)
        {
            var hash = new byte[32];
            HashBody(body, sig.BodyRelaxed, limit, hash, out long total);
            cached = bodyHashes.Add(sig.BodyRelaxed, limit, hash, total);
        }

        bool partial = sig.BodyLength is long l && l < cached.TotalCanonicalBytes;
        if (sig.BodyLength is long declared && declared > cached.TotalCanonicalBytes)
        {
            return Build(sig, DkimStatus.Fail, DkimFailure.BodyHashMismatch, "l= is larger than the body", key);
        }

        if (!CryptographicOperations.FixedTimeEquals(cached.Hash, sig.BodyHash))
        {
            return Build(sig, DkimStatus.Fail, DkimFailure.BodyHashMismatch, "body hash did not verify", key, partial);
        }

        // Header hash and RSA verification.
        var raw = table.Raw(message, fieldIndex);
        if (raw.Length >= 2 && raw[^2] == (byte)'\r' && raw[^1] == (byte)'\n') { raw = raw.Slice(0, raw.Length - 2); }
        Span<byte> headerHash = stackalloc byte[32];
        HashHeaders(message, in table, fieldIndex, raw, sig, headerHash);

        bool valid;
        try
        {
            valid = key.Rsa!.VerifyHash(headerHash, sig.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            valid = false;
        }

        // Does h= name every From instance of the message? If not, an extra From header may have been added above the signed one.
        int fromInMessage = 0;
        for (int i = 0; i < table.Count; i++)
        {
            if (table.NameEquals(message, i, "from"u8)) { fromInMessage++; }
        }

        int fromInSignature = 0;
        foreach (string name in sig.SignedHeaderNames)
        {
            if (name == "from") { fromInSignature++; }
        }

        bool allFromSigned = fromInMessage <= fromInSignature;

        return valid
            ? Build(sig, DkimStatus.Pass, DkimFailure.None, "signature verified", key, partial, allFromSigned)
            : Build(sig, DkimStatus.Fail, DkimFailure.SignatureMismatch, "signature did not verify", key, partial, allFromSigned);
    }

    internal static void HashBody(ReadOnlySpan<byte> body, bool relaxed, long limit, Span<byte> hash, out long totalCanonicalBytes)
    {
        var h = Sha256Pool.Rent();
        Span<byte> scratch = stackalloc byte[1024];
        var sink = new HashSink(h, scratch, limit);
        Canonicalizer.WriteBody(body, relaxed, ref sink);
        sink.Flush();
        totalCanonicalBytes = sink.TotalCanonicalBytes;
        Sha256Pool.FinishAndReturn(h, hash);
    }

    private static void HashHeaders(ReadOnlySpan<byte> message, in HeaderTable table, int signatureIndex, ReadOnlySpan<byte> signatureField, DkimSignatureHeader sig, Span<byte> hash)
    {
        var h = Sha256Pool.Rent();
        Span<byte> scratch = stackalloc byte[1024];
        var sink = new HashSink(h, scratch);
        var names = sig.SignedHeaderNames;
        Span<int> cursors = stackalloc int[names.Length];

        for (int i = 0; i < names.Length; i++)
        {
            // RFC 6376 section 5.4.2: instances of a repeated name are taken from the bottom of the header block upwards.
            int start = table.Count - 1;
            for (int j = i - 1; j >= 0; j--)
            {
                if (string.Equals(names[j], names[i], StringComparison.Ordinal))
                {
                    start = cursors[j] - 1;
                    break;
                }
            }

            int found = -1;
            for (int k = start; k >= 0; k--)
            {
                if (k != signatureIndex && table.NameEquals(message, k, names[i]))
                {
                    found = k;
                    break;
                }
            }

            cursors[i] = found;
            if (found >= 0)
            {
                Canonicalizer.WriteHeader(table.Raw(message, found), sig.HeaderRelaxed, appendCrlf: true, ref sink);
            }
        }

        // The signature header itself, with the b= value (and its surrounding whitespace) removed, and no trailing CRLF.
        int removed = sig.BValueEnd - sig.BValueStart;
        byte[]? rented = null;
        Span<byte> stripped = signatureField.Length - removed <= 2048
            ? stackalloc byte[signatureField.Length - removed]
            : (rented = ArrayPool<byte>.Shared.Rent(signatureField.Length - removed)).AsSpan(0, signatureField.Length - removed);
        try
        {
            signatureField.Slice(0, sig.BValueStart).CopyTo(stripped);
            signatureField.Slice(sig.BValueEnd).CopyTo(stripped.Slice(sig.BValueStart));
            Canonicalizer.WriteHeader(stripped, sig.HeaderRelaxed, appendCrlf: false, ref sink);
        }
        finally
        {
            if (rented is not null) { ArrayPool<byte>.Shared.Return(rented); }
        }

        sink.Flush();
        Sha256Pool.FinishAndReturn(h, hash);
    }

    private DkimVerificationResult Build(DkimSignatureHeader sig, DkimStatus status, DkimFailure failure, string reason, KeyLookup? key, bool bodyPartiallySigned = false, bool allFromHeadersSigned = false)
    {
        return new DkimVerificationResult(status, reason, failure)
        {
            Domain = sig.Domain,
            Selector = sig.Selector,
            Identity = sig.Identity,
            Algorithm = sig.Algorithm,
            HeaderBPrefix = sig.BPrefix,
            KeyBits = key?.Bits ?? 0,
            WeakKey = key is { Bits: > 0 } k && k.Bits < _options.WeakKeyBelowBits,
            Testing = key?.Record?.IsTesting ?? false,
            BodyLengthLimited = sig.BodyLength is not null,
            BodyPartiallySigned = bodyPartiallySigned,
            AllFromHeadersSigned = allFromHeadersSigned,
            HeaderCanonicalization = sig.Algorithm is null ? null : sig.HeaderRelaxed ? DkimCanonicalization.Relaxed : DkimCanonicalization.Simple,
            BodyCanonicalization = sig.Algorithm is null ? null : sig.BodyRelaxed ? DkimCanonicalization.Relaxed : DkimCanonicalization.Simple,
            SignedAt = ToTime(sig.Timestamp),
            ExpiresAt = ToTime(sig.Expiration),
        };
    }

    private static DateTimeOffset? ToTime(long? unixSeconds) =>
        unixSeconds is long s && s <= 253402300799L ? DateTimeOffset.FromUnixTimeSeconds(s) : null;

    private sealed record KeyError(DkimStatus Status, DkimFailure Failure, string Reason);

    private sealed class KeyLookup
    {
        public KeyLookup(DkimKeyRecord? record, RSA? rsa, int bits)
        {
            Record = record;
            Rsa = rsa;
            Bits = bits;
        }

        public DkimKeyRecord? Record { get; }

        public RSA? Rsa { get; }

        public int Bits { get; }

        public KeyError? Error { get; init; }

        public static KeyLookup Failed(DkimStatus status, DkimFailure failure, string reason) =>
            new(null, null, 0) { Error = new KeyError(status, failure, reason) };
    }

    private sealed class BodyHashCache
    {
        private readonly List<Entry> _entries = new(2);

        public Entry? Find(bool relaxed, long limit)
        {
            foreach (var e in _entries)
            {
                if (e.Relaxed == relaxed && e.Limit == limit) { return e; }
            }

            return null;
        }

        public Entry Add(bool relaxed, long limit, byte[] hash, long total)
        {
            var e = new Entry(relaxed, limit, hash, total);
            _entries.Add(e);
            return e;
        }

        public sealed record Entry(bool Relaxed, long Limit, byte[] Hash, long TotalCanonicalBytes);
    }
}
