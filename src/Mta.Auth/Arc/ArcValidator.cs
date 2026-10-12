using System.Buffers;
using System.Security.Cryptography;
using Mta.Dkim;
using Mta.Dns;

namespace Mta.Auth.Arc;

/// <summary>
/// Validates the Authenticated Received Chain of an inbound message (RFC 8617 section 5.2): the structure of the ARC sets, the chain validation
/// status values, the ARC-Message-Signature of the most recent set over the message as it arrived, and the ARC-Seal of every set. Only
/// <c>rsa-sha256</c> is supported. Safe for concurrent use. <see cref="ValidateAsync"/> never throws for bad input; hostile input is bounded by
/// <see cref="ArcValidatorOptions"/>.
/// </summary>
/// <remarks>
/// The message must use CRLF line endings, as it does on the wire. The validator performs one DNS TXT query per distinct
/// <c>selector._domainkey.domain</c> named in the chain (at most <see cref="ArcValidatorOptions.MaxKeyLookups"/>).
/// ARC-Message-Signature expiry (<c>x=</c>) is not enforced: a chain is routinely validated long after it was sealed.
/// </remarks>
public sealed class ArcValidator
{
    private readonly IDnsResolver _dns;
    private readonly ArcValidatorOptions _options;

    /// <summary>Creates a validator.</summary>
    /// <param name="dns">The resolver used to fetch the DKIM key records.</param>
    /// <param name="options">Limits; null for the defaults.</param>
    public ArcValidator(IDnsResolver dns, ArcValidatorOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(dns);
        _dns = dns;
        _options = options ?? new ArcValidatorOptions();
        if (_options.MaxInstances is < 1 or > ArcHeaderNames.MaxInstance) { throw new ArgumentOutOfRangeException(nameof(options), "MaxInstances must be between 1 and 50."); }
        if (_options.MaxHeaderCount < 1) { throw new ArgumentOutOfRangeException(nameof(options), "MaxHeaderCount must be at least 1."); }
        if (_options.MaxHeaderLength < 64) { throw new ArgumentOutOfRangeException(nameof(options), "MaxHeaderLength must be at least 64."); }
        if (_options.MaxKeyLookups < 1) { throw new ArgumentOutOfRangeException(nameof(options), "MaxKeyLookups must be at least 1."); }
    }

    /// <summary>Validates the ARC chain of the message.</summary>
    /// <param name="rawMessage">The complete message with CRLF line endings.</param>
    /// <param name="cancellationToken">Cancels pending DNS lookups.</param>
    /// <returns>None when the message carries no ARC headers, otherwise Pass or Fail.</returns>
    public async ValueTask<ArcChainResult> ValidateAsync(ReadOnlyMemory<byte> rawMessage, CancellationToken cancellationToken = default)
    {
        try
        {
            return await ValidateCoreAsync(rawMessage, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Last line of defence; the exception type is reported, never its message.
            return new ArcChainResult(ArcChainStatus.Fail, "internal error during validation (" + ex.GetType().Name + ")", ArcFailure.InternalError);
        }
    }

    private async ValueTask<ArcChainResult> ValidateCoreAsync(ReadOnlyMemory<byte> message, CancellationToken ct)
    {
        var index = ArcHeaderIndex.Parse(message.Span, _options.MaxHeaderCount);
        using var keys = new ArcKeyCache(_dns, _options);
        try
        {
            if (index.TooManyFields) { return new ArcChainResult(ArcChainStatus.Fail, "message has too many header fields", ArcFailure.TooManyHeaders); }

            var read = ArcChainReader.Read(message.Span, in index, _options.MaxHeaderLength, _options.MaxInstances);
            if (read.EarlyResult is { } early) { return early; }

            var sets = read.Sets;
            int count = sets.Length;
            var domains = new string[count];
            for (int i = 0; i < count; i++) { domains[i] = sets[i].Seal!.Domain; }

            ArcChainResult Failed(ArcFailure failure, string reason, int instance) =>
                new(ArcChainStatus.Fail, reason, failure) { FailedInstance = instance, InstanceCount = count, SealDomains = domains };

            // Cheap structural checks first: chain validation status values and algorithms.
            int upstreamFailure = 0;
            for (int i = 0; i < count; i++)
            {
                var seal = sets[i].Seal!;
                int instance = i + 1;
                if (instance == 1 && seal.ChainValidationStatus != ArcChainStatus.None) { return Failed(ArcFailure.InvalidChainValidationStatus, "the first ARC-Seal must have cv=none", instance); }
                if (instance > 1 && seal.ChainValidationStatus == ArcChainStatus.None) { return Failed(ArcFailure.InvalidChainValidationStatus, "cv=none is only allowed in the first ARC-Seal", instance); }
                if (seal.ChainValidationStatus == ArcChainStatus.Fail && upstreamFailure == 0) { upstreamFailure = instance; }
                if (seal.Algorithm != ArcHeaderNames.RsaSha256) { return Failed(ArcFailure.UnsupportedAlgorithm, "ARC-Seal algorithm " + Safe(seal.Algorithm) + " is not supported (rsa-sha256 only)", instance); }
                if (sets[i].MessageSignature!.Algorithm != ArcHeaderNames.RsaSha256) { return Failed(ArcFailure.UnsupportedAlgorithm, "ARC-Message-Signature algorithm " + Safe(sets[i].MessageSignature!.Algorithm) + " is not supported (rsa-sha256 only)", instance); }
            }

            if (upstreamFailure != 0) { return Failed(ArcFailure.ChainFailedUpstream, "an earlier hop recorded cv=fail", upstreamFailure); }

            var bodyHashes = new BodyHashes();

            // The ARC-Message-Signature of the most recent set must verify over the message as received.
            var newest = sets[count - 1];
            var amsKey = await keys.GetAsync(newest.MessageSignature!.Domain, newest.MessageSignature.Selector, ct).ConfigureAwait(false);
            if (amsKey.Rsa is null) { return Failed(amsKey.Failure, "ARC-Message-Signature key: " + amsKey.Reason, count); }
            var amsOutcome = VerifyMessageSignature(message.Span, in index, newest, amsKey.Rsa, bodyHashes);
            if (amsOutcome != ArcFailure.None)
            {
                return Failed(amsOutcome, amsOutcome == ArcFailure.BodyHashMismatch ? "ARC-Message-Signature body hash did not verify" : "ARC-Message-Signature did not verify", count);
            }

            // Every ARC-Seal, newest first, covers all ARC sets up to its own.
            for (int instance = count; instance >= 1; instance--)
            {
                var seal = sets[instance - 1].Seal!;
                var sealKey = await keys.GetAsync(seal.Domain, seal.Selector, ct).ConfigureAwait(false);
                if (sealKey.Rsa is null) { return Failed(sealKey.Failure, "ARC-Seal key: " + sealKey.Reason, instance); }
                if (!VerifySeal(message.Span, in index, sets, instance, sealKey.Rsa)) { return Failed(ArcFailure.SealMismatch, "ARC-Seal did not verify", instance); }
            }

            int? oldest = null;
            if (_options.ComputeOldestPass)
            {
                oldest = count;
                for (int instance = 1; instance < count; instance++)
                {
                    var set = sets[instance - 1];
                    var key = await keys.GetAsync(set.MessageSignature!.Domain, set.MessageSignature.Selector, ct).ConfigureAwait(false);
                    if (key.Rsa is not null && VerifyMessageSignature(message.Span, in index, set, key.Rsa, bodyHashes) == ArcFailure.None)
                    {
                        oldest = instance;
                        break;
                    }
                }
            }

            return new ArcChainResult(ArcChainStatus.Pass, "ARC chain verified")
            {
                InstanceCount = count,
                OldestPassingInstance = oldest,
                SealDomains = domains,
            };
        }
        finally
        {
            index.Dispose();
        }
    }

    private static string Safe(string text) => text.Length > 32 ? text.Substring(0, 32) + "..." : text;

    private static ArcFailure VerifyMessageSignature(ReadOnlySpan<byte> message, in ArcHeaderIndex index, ArcSet set, RSA rsa, BodyHashes bodyHashes)
    {
        var ams = set.MessageSignature!;
        bool relaxedBody = ams.BodyCanonicalization == DkimCanonicalization.Relaxed;
        var body = message.Slice(index.BodyOffset);
        var computed = bodyHashes.Get(body, relaxedBody);
        if (!CryptographicOperations.FixedTimeEquals(computed, ams.BodyHash.Span)) { return ArcFailure.BodyHashMismatch; }

        var raw = index.RawWithoutCrlf(message, set.MessageSignatureField);
        byte[] stripped = ArcSignatureInput.RentWithoutRange(raw, ams.SignatureValueStart, ams.SignatureValueEnd, out int strippedLength);
        try
        {
            Span<byte> digest = stackalloc byte[32];
            ArcSignatureInput.HashMessageSignature(
                message, in index, ams.SignedHeaderNames, set.MessageSignatureField,
                ams.HeaderCanonicalization == DkimCanonicalization.Relaxed, stripped.AsSpan(0, strippedLength), digest);
            return Verify(rsa, digest, ams.Signature.Span) ? ArcFailure.None : ArcFailure.MessageSignatureMismatch;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(stripped);
        }
    }

    private static bool VerifySeal(ReadOnlySpan<byte> message, in ArcHeaderIndex index, ArcSet[] sets, int instance, RSA rsa)
    {
        var set = sets[instance - 1];
        var seal = set.Seal!;
        var raw = index.RawWithoutCrlf(message, set.SealField);
        byte[] stripped = ArcSignatureInput.RentWithoutRange(raw, seal.SignatureValueStart, seal.SignatureValueEnd, out int strippedLength);
        try
        {
            Span<byte> digest = stackalloc byte[32];
            ArcSignatureInput.HashSeal(
                message, in index, sets.AsSpan(0, instance - 1),
                index.Raw(message, set.AuthenticationResultsField), index.Raw(message, set.MessageSignatureField), stripped.AsSpan(0, strippedLength), digest);
            return Verify(rsa, digest, seal.Signature.Span);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(stripped);
        }
    }

    private static bool Verify(RSA rsa, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        try
        {
            return rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>The body hash of the message for each of the two body canonicalizations, computed on first use.</summary>
    private sealed class BodyHashes
    {
        private byte[]? _simple;
        private byte[]? _relaxed;

        public ReadOnlySpan<byte> Get(ReadOnlySpan<byte> body, bool relaxed)
        {
            ref byte[]? slot = ref (relaxed ? ref _relaxed : ref _simple);
            if (slot is null)
            {
                var hash = new byte[32];
                ArcCanonicalizer.HashBody(body, relaxed, hash);
                slot = hash;
            }

            return slot;
        }
    }
}
