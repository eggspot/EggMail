using System.Text;
using Mta.Auth.AuthenticationResults;
using Mta.Dsn;
using Mta.Mime;

namespace Mta.Host.Ingest;

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

    public bool Oversized { get; private set; }

    public bool StartsWithWhiteSpace { get; private set; }

    public bool FromUnusable => FromInvalid || FromDomains.Count == 0;

    private bool FromInvalid { get; set; }

    public int ReceivedCount { get; private set; }

    public List<string> FromDomains { get; } = [];

    public bool TooManyFromDomains { get; private set; }

    public string? Subject { get; private set; }

    public bool HasRemovals => _removed.Count > 0;

    public int RemovedCount => _removed.Count;

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

            string looksLike = NameAsALenientReaderSeesIt(header);
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

        int highestValidMarker = -1, highestValidCount = -1;
        foreach ((int index, int count, bool valid) in hopFields)
        {
            if (valid && count > highestValidCount)
            {
                highestValidCount = count;
                highestValidMarker = index;
            }
        }

        foreach ((int index, _, _) in hopFields)
        {
            if (index != highestValidMarker)
            {
                analysis.Remove(headers[index]);
            }
        }

        analysis._removed.Sort(static (a, b) => a.Start.CompareTo(b.Start));
        return analysis;
    }

    public static string NameOf(MimeHeader header)
    {
        ReadOnlySpan<byte> name = header.NameBytes;
        while (name.Length > 0 && (name[^1] is (byte)' ' or (byte)'\t'))
        {
            name = name[..^1];
        }

        return Encoding.Latin1.GetString(name);
    }

    private static string NameAsALenientReaderSeesIt(MimeHeader header)
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

        string value = header.GetValue(Limits.MaxHeaderValueBytes);
        AddressList list = AddressList.Parse(value, Limits);
        if (list.Count == 0)
        {
            FromInvalid = true;
        }

        var taken = new HashSet<string>(StringComparer.Ordinal);
        foreach (Mailbox mailbox in list.Mailboxes)
        {
            string domain;
            if (mailbox.IsValid)
            {
                domain = mailbox.Address.Domain.ToLowerInvariant();
            }
            else if (TryRecoverDomain(mailbox.AddrSpec, out string? recovered))
            {
                domain = recovered;
            }
            else if (IsPieceOfADisplayName(mailbox))
            {
                continue;
            }
            else
            {
                FromInvalid = true;
                continue;
            }

            taken.Add(domain);
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

        foreach (string candidate in FromAmbiguity.CandidateDomains(value))
        {
            if (!taken.Contains(candidate))
            {
                FromInvalid = true;
                break;
            }
        }
    }

    private static bool TryRecoverDomain(string addrSpec, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? domain)
    {
        domain = null;
        string? only = null;
        foreach (string candidate in FromAmbiguity.CandidateDomains(addrSpec))
        {
            if (only is not null && !string.Equals(only, candidate, StringComparison.Ordinal))
            {
                return false;
            }

            only = candidate;
        }

        if (only is null || !Mta.Host.Domains.DomainNames.TryNormalize(only, out string normalized))
        {
            return false;
        }

        domain = normalized.ToLowerInvariant();
        return true;
    }

    private static bool IsPieceOfADisplayName(Mailbox mailbox) => !mailbox.AddrSpec.Contains('@', StringComparison.Ordinal);

    private static bool IsControlOrBidirectionalFormatting(char c) =>
        char.IsControl(c) || c is >= '\u202A' and <= '\u202E' or >= '\u2066' and <= '\u2069' or '\u200E' or '\u200F' or '\u061C';

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

            sb.Append(IsControlOrBidirectionalFormatting(c) ? ' ' : c);
        }

        string subject = sb.ToString().Trim();
        if (subject.Length > 0 && char.IsHighSurrogate(subject[^1]))
        {
            subject = subject[..^1];
        }

        return subject.Length == 0 ? null : subject;
    }

    public byte[] Compose(ReadOnlySpan<byte> prefix)
    {
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

internal static class FromAmbiguity
{
    private const int MaxCandidates = 64;
    private const string UnterminatedQuoteOrComment = "?unterminated";

    private static readonly System.Buffers.SearchValues<char> RouteDomainLiteralCharacters = System.Buffers.SearchValues.Create("0123456789abcdefABCDEFIPv6:.");

    public static IEnumerable<string> CandidateDomains(string field)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<string>();
        int commentDepth = 0;
        bool quoted = false;
        for (int i = 0; i < field.Length && result.Count < MaxCandidates; i++)
        {
            char c = field[i];
            if (c == '\\' && (quoted || commentDepth > 0))
            {
                i++;
                continue;
            }

            if (quoted)
            {
                quoted = c != '"';
                continue;
            }

            if (commentDepth > 0)
            {
                commentDepth += c == '(' ? 1 : c == ')' ? -1 : 0;
                continue;
            }

            switch (c)
            {
                case '"':
                    quoted = true;
                    break;
                case '(':
                    commentDepth = 1;
                    break;
                case '<':
                    i = SkipRoute(field, i + 1) - 1;
                    break;
                case '@':
                    {
                        int start = SkipCfws(field, i + 1);
                        int end = start;
                        if (end < field.Length && field[end] == '[')
                        {
                            end = field.IndexOf(']', end) is var close and >= 0 ? close + 1 : field.Length;
                        }
                        else
                        {
                            while (end < field.Length && (char.IsAsciiLetterOrDigit(field[end]) || field[end] is '-' or '.' || field[end] > '\u007F'))
                            {
                                end++;
                            }
                        }

                        string name = field[start..end].TrimEnd('.');
                        string key = Mta.Core.EmailAddress.TryParse("postmaster@" + name, allowUtf8: true, out Mta.Core.EmailAddress parsed) && name.Length > 0
                            ? parsed.Domain.ToLowerInvariant()
                            : "?" + name.ToLowerInvariant();
                        if (seen.Add(key))
                        {
                            result.Add(key);
                        }

                        i = Math.Max(i, end - 1);
                        break;
                    }
            }
        }

        if (quoted || commentDepth > 0)
        {
            result.Add(UnterminatedQuoteOrComment);
        }

        return result;
    }

    private static int SkipCfws(string field, int position)
    {
        int i = position;
        while (i < field.Length)
        {
            if (field[i] is ' ' or '\t' or '\r' or '\n')
            {
                i++;
            }
            else if (field[i] == '(')
            {
                int depth = 0;
                while (i < field.Length)
                {
                    char c = field[i++];
                    if (c == '\\' && i < field.Length)
                    {
                        i++;
                    }
                    else if (c == '(')
                    {
                        depth++;
                    }
                    else if (c == ')' && --depth == 0)
                    {
                        break;
                    }
                }
            }
            else
            {
                break;
            }
        }

        return i;
    }

    private static int SkipRoute(string field, int position)
    {
        int i = SkipCfws(field, position);
        if (i >= field.Length || field[i] != '@')
        {
            return position;
        }

        char previous = '<';
        while (i < field.Length)
        {
            char c = field[i];
            if (c is ' ' or '\t' or '\r' or '\n' or '(')
            {
                i = SkipCfws(field, i);
                continue;
            }

            if (c == ':')
            {
                return i + 1;
            }

            if (c == '[' && previous == '@' && field.IndexOf(']', i) is var close and >= 0
                && field.AsSpan(i + 1, close - i - 1).IndexOfAnyExcept(RouteDomainLiteralCharacters) < 0)
            {
                previous = ']';
                i = close + 1;
                continue;
            }

            if ((c == '@' && previous is not ('<' or ',')) || c is '<' or '>' or '"' or '\\' or ';')
            {
                return position;
            }

            previous = c;
            i++;
        }

        return position;
    }
}
