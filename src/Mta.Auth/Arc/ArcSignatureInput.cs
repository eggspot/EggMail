using System.Buffers;

namespace Mta.Auth.Arc;

/// <summary>Builds the exact byte sequences that the ARC signatures cover and hashes them with SHA-256. Used by both the validator and the sealer so they cannot drift apart.</summary>
internal static class ArcSignatureInput
{
    /// <summary>
    /// Hashes the input of an ARC-Message-Signature (RFC 8617 section 5.1.1, RFC 6376 section 3.7): the header instances named by <paramref name="names"/>
    /// (successive instances of a repeated name taken from the bottom of the header block upwards, none for a name with no instance left), then the
    /// signature header itself with an empty <c>b=</c> value and without a trailing CRLF.
    /// </summary>
    public static void HashMessageSignature(
        ReadOnlySpan<byte> message,
        in ArcHeaderIndex index,
        IReadOnlyList<string> names,
        int skipField,
        bool relaxedHeaders,
        ReadOnlySpan<byte> signatureHeaderWithoutValue,
        Span<byte> hash)
    {
        var h = ArcSha256.Rent();
        try
        {
            Span<byte> scratch = stackalloc byte[1024];
            var sink = new ArcHashSink(h, scratch);
            int[] cursorsRented = ArrayPool<int>.Shared.Rent(Math.Max(names.Count, 1));
            try
            {
                for (int i = 0; i < names.Count; i++)
                {
                    int start = index.Count - 1;
                    for (int j = i - 1; j >= 0; j--)
                    {
                        if (string.Equals(names[j], names[i], StringComparison.Ordinal))
                        {
                            start = cursorsRented[j] - 1;
                            break;
                        }
                    }

                    int found = -1;
                    for (int k = start; k >= 0; k--)
                    {
                        if (k != skipField && index.NameEquals(message, k, names[i]))
                        {
                            found = k;
                            break;
                        }
                    }

                    cursorsRented[i] = found;
                    if (found >= 0) { ArcCanonicalizer.WriteHeader(index.Raw(message, found), relaxedHeaders, appendCrlf: true, ref sink); }
                }
            }
            finally
            {
                ArrayPool<int>.Shared.Return(cursorsRented);
            }

            ArcCanonicalizer.WriteHeader(signatureHeaderWithoutValue, relaxedHeaders, appendCrlf: false, ref sink);
            sink.Flush();
        }
        catch
        {
            ArcSha256.Abandon(h);
            throw;
        }

        ArcSha256.FinishAndReturn(h, hash);
    }

    /// <summary>
    /// Hashes the input of an ARC-Seal (RFC 8617 section 5.1.1): for each ARC set in instance order the ARC-Authentication-Results, ARC-Message-Signature
    /// and ARC-Seal headers, relaxed canonicalization, each followed by CRLF except the final seal, which has an empty <c>b=</c> value and no CRLF.
    /// </summary>
    public static void HashSeal(
        ReadOnlySpan<byte> message,
        in ArcHeaderIndex index,
        ReadOnlySpan<ArcSet> priorSets,
        ReadOnlySpan<byte> authenticationResults,
        ReadOnlySpan<byte> messageSignature,
        ReadOnlySpan<byte> sealWithoutValue,
        Span<byte> hash)
    {
        var h = ArcSha256.Rent();
        try
        {
            Span<byte> scratch = stackalloc byte[1024];
            var sink = new ArcHashSink(h, scratch);
            foreach (var set in priorSets)
            {
                ArcCanonicalizer.WriteHeader(index.Raw(message, set.AuthenticationResultsField), relaxed: true, appendCrlf: true, ref sink);
                ArcCanonicalizer.WriteHeader(index.Raw(message, set.MessageSignatureField), relaxed: true, appendCrlf: true, ref sink);
                ArcCanonicalizer.WriteHeader(index.Raw(message, set.SealField), relaxed: true, appendCrlf: true, ref sink);
            }

            ArcCanonicalizer.WriteHeader(authenticationResults, relaxed: true, appendCrlf: true, ref sink);
            ArcCanonicalizer.WriteHeader(messageSignature, relaxed: true, appendCrlf: true, ref sink);
            ArcCanonicalizer.WriteHeader(sealWithoutValue, relaxed: true, appendCrlf: false, ref sink);
            sink.Flush();
        }
        catch
        {
            ArcSha256.Abandon(h);
            throw;
        }

        ArcSha256.FinishAndReturn(h, hash);
    }

    /// <summary>Copies <paramref name="field"/> into a pooled array with the bytes in [<paramref name="start"/>, <paramref name="end"/>) removed. Return the array to <see cref="ArrayPool{T}.Shared"/>.</summary>
    public static byte[] RentWithoutRange(ReadOnlySpan<byte> field, int start, int end, out int length)
    {
        length = field.Length - (end - start);
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(length, 1));
        field.Slice(0, start).CopyTo(rented);
        field.Slice(end).CopyTo(rented.AsSpan(start));
        return rented;
    }
}
