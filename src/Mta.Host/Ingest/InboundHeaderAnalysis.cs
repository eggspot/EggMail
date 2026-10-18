using System.Text;
using Mta.Auth.AuthenticationResults;
using Mta.Dsn;
using Mta.Mime;

namespace Mta.Host.Ingest;

/// <summary>
/// What the receive path reads from the header block of an inbound message before it stamps it (design sections 11.5 and 11.7): which header fields must go (a forged
/// <c>Authentication-Results</c> of ours, every <c>X-EggMail-*</c> field that is not a valid hop marker), how many <c>Received</c> fields there are, the From domains, and the subject.
/// The message is parsed once; <see cref="Compose"/> then writes the stored copy: our headers on top of the received bytes minus the removed fields.
/// </summary>
internal sealed class InboundHeaderAnalysis
{
    private const int MaxFromDomains = 3;
    private static readonly MimeLimits Limits = MimeLimits.Default;

    private readonly ReadOnlyMemory<byte> _original;
    private readonly List<(int Start, int Length)> _removed = [];

    private InboundHeaderAnalysis(ReadOnlyMemory<byte> original, HeaderList headers)
    {
        _original = original;
        Headers = headers;
    }

    public HeaderList Headers { get; }

    /// <summary>More header fields, or a larger header block, than the parser records: fields we would have to inspect (and maybe remove) could be hidden behind the limit, so the message is refused.</summary>
    public bool Oversized { get; private set; }

    /// <summary>
    /// The message starts with white space: its first line would be a continuation of a header field that does not exist, and the field we put in front of it (our <c>Authentication-Results</c>) would swallow
    /// that line as its own continuation, letting the sender write verdicts into our header. No real message starts like that; it is refused.
    /// </summary>
    public bool StartsWithWhiteSpace { get; private set; }

    /// <summary>A From field has a mailbox that does not parse (or the message has no From, an empty one or only groups): there is no identity whose policy could be applied.</summary>
    public bool FromUnusable => FromInvalid || FromDomains.Count == 0;

    private bool FromInvalid { get; set; }

    public int ReceivedCount { get; private set; }

    /// <summary>The distinct domains of the From field(s), lower-case, in order.</summary>
    public List<string> FromDomains { get; } = [];

    /// <summary>More From fields or domains than <see cref="MaxFromDomains"/>: no real message has that, and each one is a DMARC lookup.</summary>
    public bool TooManyFromDomains { get; private set; }

    public string? Subject { get; private set; }

    public bool HasRemovals => _removed.Count > 0;

    public int RemovedCount => _removed.Count;

    /// <summary>
    /// Parses <paramref name="original"/> (CRLF lines, as received) and decides what to remove. <paramref name="ownAuthservIds"/> are the identifiers an <c>Authentication-Results</c> header must not
    /// carry (ours); <paramref name="hops"/> verifies the signed forward marker (null: every marker is removed).
    /// </summary>
    public static InboundHeaderAnalysis Analyze(ReadOnlyMemory<byte> original, IReadOnlyCollection<string> ownAuthservIds, ForwardHopMarker? hops)
    {
        HeaderList headers = HeaderList.Parse(original, Limits);
        var analysis = new InboundHeaderAnalysis(original, headers);
        if (original.Length > 0 && original.Span[0] is (byte)' ' or (byte)'\t')
        {
            analysis.StartsWithWhiteSpace = true;
            return analysis;
        }

        if ((headers.Anomalies & (MimeAnomaly.TooManyHeaders | MimeAnomaly.HeaderBlockTooLarge)) != 0)
        {
            analysis.Oversized = true;
            return analysis;
        }

        var hopFields = new List<(int Index, int Hops, bool Valid)>();
        string? bodyHash = null;
        for (int i = 0; i < headers.Count; i++)
        {
            MimeHeader header = headers[i];

            // The name as a lenient consumer of the stored message might read it: control characters and white space dropped (a field named "X-EggMail-Dmarc<VT>:" is still ours), and a line without a colon
            // judged by what it looks like. Anything that reads as one of our names but is not exactly that name written properly is removed.
            string looksLike = Normalize(header);
            bool properName = !header.IsMalformed && header.NameBytes.Length > 0 && IsToken(NameOf(header));
            string name = header.IsMalformed ? string.Empty : NameOf(header);
            if (looksLike == "authentication-results" || looksLike.StartsWith("authentication-results", StringComparison.Ordinal) && header.IsMalformed)
            {
                if (!properName || !name.Equals(HeaderNames.AuthenticationResults, StringComparison.OrdinalIgnoreCase) || AuthenticationResultsPolicy.ShouldRemoveOnIngress(header.GetValue(), ownAuthservIds))
                {
                    analysis.Remove(header);
                }
            }
            else if (looksLike.StartsWith("x-eggmail-", StringComparison.Ordinal))
            {
                if (properName && name.Equals(ForwardHopMarker.HeaderName, StringComparison.OrdinalIgnoreCase) && hops is not null)
                {
                    bodyHash ??= ForwardHopMarker.BodyHash(headers.Body.Span);
                    bool valid = hops.TryVerify(header.GetValue(), bodyHash, out int count);
                    hopFields.Add((i, valid ? count : -1, valid));
                }
                else
                {
                    analysis.Remove(header);
                }
            }
            else if (header.IsMalformed)
            {
                continue;
            }
            else if (name.Equals(HeaderNames.Received, StringComparison.OrdinalIgnoreCase))
            {
                analysis.ReceivedCount++;
            }
            else if (name.Equals(HeaderNames.From, StringComparison.OrdinalIgnoreCase))
            {
                analysis.AddFrom(header);
            }
            else if (analysis.Subject is null && name.Equals(HeaderNames.Subject, StringComparison.OrdinalIgnoreCase))
            {
                analysis.Subject = CleanSubject(header);
            }
        }

        // Among the markers with a valid signature only the highest count is kept (the first one when several say the same); every other marker goes.
        int keep = -1, best = -1;
        foreach ((int index, int count, bool valid) in hopFields)
        {
            if (valid && count > best)
            {
                best = count;
                keep = index;
            }
        }

        foreach ((int index, _, _) in hopFields)
        {
            if (index != keep)
            {
                analysis.Remove(headers[index]);
            }
        }

        analysis._removed.Sort(static (a, b) => a.Start.CompareTo(b.Start));
        return analysis;
    }

    /// <summary>The field name as the sender wrote it, without the whitespace some senders put before the colon.</summary>
    public static string NameOf(MimeHeader header)
    {
        ReadOnlySpan<byte> name = header.NameBytes;
        while (name.Length > 0 && (name[^1] is (byte)' ' or (byte)'\t'))
        {
            name = name[..^1];
        }

        return Encoding.Latin1.GetString(name);
    }

    /// <summary>The text before the colon (the whole line when there is none) reduced to lower-case letters, digits and hyphens.</summary>
    private static string Normalize(MimeHeader header)
    {
        ReadOnlySpan<byte> raw = header.Raw.Span;
        int colon = raw.IndexOf((byte)':');
        ReadOnlySpan<byte> name = colon >= 0 ? raw[..colon] : raw;
        var sb = new StringBuilder(Math.Min(name.Length, 64));
        foreach (byte b in name)
        {
            if (sb.Length >= 64)
            {
                break;
            }

            if (b is >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9' or (byte)'-')
            {
                sb.Append((char)b);
            }
            else if (b is >= (byte)'A' and <= (byte)'Z')
            {
                sb.Append((char)(b | 0x20));
            }
        }

        return sb.ToString();
    }

    private static bool IsToken(string name)
    {
        foreach (char c in name)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c == '-'))
            {
                return false;
            }
        }

        return name.Length > 0;
    }

    private void Remove(MimeHeader header) => _removed.Add((header.Offset, header.LengthWithLineEnding));

    private void AddFrom(MimeHeader header)
    {
        if (TooManyFromDomains)
        {
            return;
        }

        AddressList list = AddressList.Parse(header, Limits);
        if (list.Count == 0)
        {
            FromInvalid = true;   // an empty From field
        }

        foreach (Mailbox mailbox in list.Mailboxes)
        {
            if (!mailbox.IsValid)
            {
                FromInvalid = true;
                continue;
            }

            string domain = mailbox.Address.Domain.ToLowerInvariant();
            if (!FromDomains.Contains(domain, StringComparer.Ordinal))
            {
                if (FromDomains.Count >= MaxFromDomains)
                {
                    TooManyFromDomains = true;
                    return;
                }

                FromDomains.Add(domain);
            }
        }
    }

    private static string? CleanSubject(MimeHeader header)
    {
        string decoded = header.GetDecodedValue(4096);
        var sb = new StringBuilder(Math.Min(decoded.Length, 256));
        foreach (char c in decoded)
        {
            if (sb.Length >= 256)
            {
                break;
            }

            // Control characters and the bidirectional controls (override, embedding, isolate and mark characters) become spaces: a subject is shown in lists and must not reorder the text around it.
            sb.Append(char.IsControl(c) || c is >= '\u202A' and <= '\u202E' or >= '\u2066' and <= '\u2069' or '\u200E' or '\u200F' or '\u061C' ? ' ' : c);
        }

        string subject = sb.ToString().Trim();
        if (subject.Length > 0 && char.IsHighSurrogate(subject[^1]))
        {
            subject = subject[..^1];
        }

        return subject.Length == 0 ? null : subject;
    }

    /// <summary>The stored copy: <paramref name="prefix"/> (the headers we add, CRLF terminated), then the received bytes without the removed fields.</summary>
    public byte[] Compose(ReadOnlySpan<byte> prefix)
    {
        // The received bytes must start on a line of their own: a prefix that stopped mid-line would let the first received line continue our last field.
        if (prefix.Length < 2 || prefix[^2] != (byte)'\r' || prefix[^1] != (byte)'\n')
        {
            throw new ArgumentException("The headers we add must end with CRLF.", nameof(prefix));
        }

        if (_original.Length > 0 && _original.Span[0] is (byte)' ' or (byte)'\t')
        {
            throw new InvalidOperationException("A message that starts with white space is refused before it is stored.");
        }

        int removedBytes = 0;
        foreach ((int _, int length) in _removed)
        {
            removedBytes += length;
        }

        var result = new byte[prefix.Length + _original.Length - removedBytes];
        prefix.CopyTo(result);
        int written = prefix.Length;
        int position = 0;
        ReadOnlySpan<byte> source = _original.Span;
        foreach ((int start, int length) in _removed)
        {
            source[position..start].CopyTo(result.AsSpan(written));
            written += start - position;
            position = start + length;
        }

        source[position..].CopyTo(result.AsSpan(written));
        return result;
    }
}
