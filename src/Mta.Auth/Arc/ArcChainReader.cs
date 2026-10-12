namespace Mta.Auth.Arc;

/// <summary>The three headers of one ARC instance, with their positions in the header index.</summary>
internal sealed class ArcSet
{
    public ArcSet(int instance) => Instance = instance;

    public int Instance { get; }

    public int AuthenticationResultsField { get; set; } = -1;

    public int MessageSignatureField { get; set; } = -1;

    public int SealField { get; set; } = -1;

    public ArcAuthenticationResultsHeader? AuthenticationResults { get; set; }

    public ArcMessageSignatureHeader? MessageSignature { get; set; }

    public ArcSealHeader? Seal { get; set; }
}

/// <summary>The structural reading of the ARC headers of a message: either the ordered sets 1..N or an early result (none, or a structural failure).</summary>
internal sealed class ArcChainRead
{
    public ArcChainResult? EarlyResult { get; init; }

    public ArcSet[] Sets { get; init; } = [];
}

/// <summary>Finds the ARC headers of a message, parses them and checks the structure rules of RFC 8617 section 5.2 (no cryptography).</summary>
internal static class ArcChainReader
{
    private enum Kind { None, Seal, MessageSignature, AuthenticationResults }

    private static Kind Classify(ReadOnlySpan<byte> message, in ArcHeaderIndex index, int field)
    {
        if (index[field].NameLength is not (8 or 21 or 26)) { return Kind.None; }
        if (index.NameEquals(message, field, "arc-seal"u8)) { return Kind.Seal; }
        if (index.NameEquals(message, field, "arc-message-signature"u8)) { return Kind.MessageSignature; }
        if (index.NameEquals(message, field, "arc-authentication-results"u8)) { return Kind.AuthenticationResults; }
        return Kind.None;
    }

    public static ArcChainRead Read(ReadOnlySpan<byte> message, in ArcHeaderIndex index, int maxHeaderLength, int maxInstances)
    {
        var slots = new ArcSet?[maxInstances + 1];
        int highest = 0;
        int arcHeaders = 0;
        for (int field = 0; field < index.Count; field++)
        {
            var kind = Classify(message, in index, field);
            if (kind == Kind.None) { continue; }
            if (++arcHeaders > 3 * maxInstances) { return Fail(ArcFailure.TooManyInstances, "more than " + maxInstances + " ARC sets", null); }

            var raw = index.RawWithoutCrlf(message, field);
            int valueOffset = index[field].ColonOffset + 1;
            int instance;
            ArcFailure failure;
            string? error;
            string label;
            ArcSet? set;
            switch (kind)
            {
                case Kind.Seal:
                    label = ArcHeaderNames.Seal;
                    if (!ArcSealHeader.TryParseField(raw, valueOffset, maxHeaderLength, out var seal, out failure, out error)) { return Fail(failure, label + ": " + error, null); }
                    instance = seal.Instance;
                    set = Slot(slots, instance, maxInstances, ref highest);
                    if (set is null) { return TooMany(maxInstances); }
                    if (set.SealField >= 0) { return Duplicate(label, instance); }
                    set.SealField = field;
                    set.Seal = seal;
                    break;
                case Kind.MessageSignature:
                    label = ArcHeaderNames.MessageSignature;
                    if (!ArcMessageSignatureHeader.TryParseField(raw, valueOffset, maxHeaderLength, out var ams, out failure, out error)) { return Fail(failure, label + ": " + error, null); }
                    instance = ams.Instance;
                    set = Slot(slots, instance, maxInstances, ref highest);
                    if (set is null) { return TooMany(maxInstances); }
                    if (set.MessageSignatureField >= 0) { return Duplicate(label, instance); }
                    set.MessageSignatureField = field;
                    set.MessageSignature = ams;
                    break;
                default:
                    label = ArcHeaderNames.AuthenticationResults;
                    if (!ArcAuthenticationResultsHeader.TryParseField(raw, valueOffset, maxHeaderLength, out var aar, out failure, out error)) { return Fail(failure, label + ": " + error, null); }
                    instance = aar.Instance;
                    set = Slot(slots, instance, maxInstances, ref highest);
                    if (set is null) { return TooMany(maxInstances); }
                    if (set.AuthenticationResultsField >= 0) { return Duplicate(label, instance); }
                    set.AuthenticationResultsField = field;
                    set.AuthenticationResults = aar;
                    break;
            }
        }

        if (arcHeaders == 0)
        {
            return new ArcChainRead { EarlyResult = new ArcChainResult(ArcChainStatus.None, "message has no ARC sets") };
        }

        var sets = new ArcSet[highest];
        for (int i = 1; i <= highest; i++)
        {
            var set = slots[i];
            if (set is null) { return Fail(ArcFailure.InstanceGap, "instance " + i + " is missing", i, highest); }
            if (set.Seal is null || set.MessageSignature is null || set.AuthenticationResults is null)
            {
                return Fail(ArcFailure.IncompleteSet, "instance " + i + " does not have exactly one ARC-Seal, ARC-Message-Signature and ARC-Authentication-Results", i, highest);
            }

            sets[i - 1] = set;
        }

        return new ArcChainRead { Sets = sets };
    }

    private static ArcSet? Slot(ArcSet?[] slots, int instance, int maxInstances, ref int highest)
    {
        if (instance > maxInstances) { return null; }
        var set = slots[instance] ??= new ArcSet(instance);
        if (instance > highest) { highest = instance; }
        return set;
    }

    private static ArcChainRead TooMany(int maxInstances) =>
        Fail(ArcFailure.TooManyInstances, "more than " + maxInstances + " ARC sets", null);

    private static ArcChainRead Duplicate(string label, int instance) =>
        Fail(ArcFailure.DuplicateInstance, label + " appears more than once for instance " + instance, instance);

    private static ArcChainRead Fail(ArcFailure failure, string reason, int? instance, int count = 0) =>
        new() { EarlyResult = new ArcChainResult(ArcChainStatus.Fail, reason, failure) { FailedInstance = instance, InstanceCount = count } };

    /// <summary>
    /// Lenient scan used by the sealer for a failed chain: reads only the instance numbers of all ARC headers (and the <c>cv</c> of the seal with
    /// the highest instance). Returns false when any ARC header has no readable instance number.
    /// </summary>
    public static bool TryScanInstances(ReadOnlySpan<byte> message, in ArcHeaderIndex index, out int highest, out ArcChainStatus? highestSealStatus)
    {
        highest = 0;
        highestSealStatus = null;
        Span<ArcTag> tags = stackalloc ArcTag[ArcTagList.MaxTags];
        for (int field = 0; field < index.Count; field++)
        {
            var kind = Classify(message, in index, field);
            if (kind == Kind.None) { continue; }

            var raw = index.RawWithoutCrlf(message, field);
            int valueOffset = index[field].ColonOffset + 1;
            int instance;
            ArcChainStatus? cv = null;
            if (kind == Kind.AuthenticationResults)
            {
                if (!ArcAuthenticationResultsHeader.TryParseField(raw, valueOffset, int.MaxValue, out var aar, out _, out _)) { return false; }
                instance = aar.Instance;
            }
            else
            {
                if (!ArcTagList.TryParse(raw, valueOffset, tags, out int count, out _)) { return false; }
                if (!ArcTagList.TryFind(raw, tags.Slice(0, count), "i"u8, out var i)) { return false; }
                if (!ArcHeaderParsing.TryInstance(ArcTagList.Value(raw, i), out instance, out _, out _)) { return false; }
                if (kind == Kind.Seal && ArcTagList.TryFind(raw, tags.Slice(0, count), "cv"u8, out var cvTag))
                {
                    string text = ArcTagList.CompactAscii(ArcTagList.Value(raw, cvTag));
                    cv = text.Equals("none", StringComparison.OrdinalIgnoreCase) ? ArcChainStatus.None
                        : text.Equals("pass", StringComparison.OrdinalIgnoreCase) ? ArcChainStatus.Pass
                        : text.Equals("fail", StringComparison.OrdinalIgnoreCase) ? ArcChainStatus.Fail
                        : null;
                }
            }

            if (instance > highest)
            {
                highest = instance;
                highestSealStatus = null;
            }

            if (kind == Kind.Seal && instance == highest && cv is not null) { highestSealStatus = cv; }
        }

        return true;
    }
}
