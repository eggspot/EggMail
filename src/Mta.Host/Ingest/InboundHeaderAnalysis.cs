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

        string value = header.GetValue(Limits.MaxHeaderValueBytes);
        AddressList list = AddressList.Parse(value, Limits);
        if (list.Count == 0)
        {
            FromInvalid = true;   // an empty From field
        }

        // The domains the parser took as identities (a valid mailbox, or one recovered below).
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
                domain = recovered;   // a local part the strict parser refuses (john.@x, jo..hn@x) still names the domain whose policy applies
            }
            else if (!mailbox.AddrSpec.Contains('@', StringComparison.Ordinal))
            {
                continue;   // a piece of a display name split at an unquoted comma ("Doe, John <john@x>"): it claims no identity of its own; the check below still sees an "@" in it
            }
            else
            {
                FromInvalid = true;   // "@" signs from which no single domain can be read
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

        // Another parser may read this field differently (display names with an "@" in them, an angle bracket that is never closed, a second address after the first, a Q-encoded word with
        // a literal "@" in it, text after the address): every domain that stands after an unquoted "@" must be one that was evaluated. A field in which a domain appears that was not taken as the identity
        // has no identity we can vouch for, so it is unusable (design section 11.5, parser differential with Python's email.policy). Several mailboxes naming their own domains are fine: each is evaluated.
        foreach (string candidate in FromAmbiguity.CandidateDomains(value))
        {
            if (!taken.Contains(candidate))
            {
                FromInvalid = true;
                break;
            }
        }
    }

    /// <summary>
    /// The domain of a mailbox the strict parser refused, when every "@" outside quotes and comments is followed by the same plausible domain name (at least two labels): <c>john.@x.example</c>,
    /// <c>jo..hn@x.example</c>, <c>a@x.example@x.example</c>. "@" signs that lead to different domains read as different addresses to different parsers: no recovery.
    /// </summary>
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

/// <summary>Finds the domains a From field names after an "@" that is not inside a quoted string or a comment, the way a lenient reader of the field would.</summary>
internal static class FromAmbiguity
{
    private const int MaxCandidates = 64;

    // What may stand inside the brackets of a domain literal in a route (an IPv4 or IPv6 address, "IPv6:" and its colons); anything else is not skipped as a literal.
    private static readonly System.Buffers.SearchValues<char> DomainLiteralCharacters = System.Buffers.SearchValues.Create("0123456789abcdefABCDEFIPv6:.");

    /// <summary>
    /// The distinct domains (lower-case, A-label form when the text is a valid domain, otherwise the text prefixed with <c>?</c>; <c>?unterminated</c> when a quoted string or comment never ends) after each "@" of <paramref name="field"/> that is outside quotes and
    /// comments. An obsolete source route at the start of an angle address (<c>&lt;@a.example,@b.example:user@host&gt;</c>) is not an address and is skipped, but only when it is one: every "@" in it
    /// comes right after the "&lt;" or a ",". A backslash quotes the next character only inside a quoted string or a comment; outside them it is text (<c>ceo\@victim.example</c> names victim.example to
    /// Python's <c>email.policy</c>). At most 64 are collected.
    /// </summary>
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
                i++;   // a quoted pair: the next character is text. Outside quotes and comments a backslash is an ordinary character and the "@" after it still starts a domain.
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
                        // Folding white space and comments may stand between the "@" and the domain (RFC 5322 3.4.1: the domain is a dot-atom with CFWS around it).
                        int start = SkipCfws(field, i + 1);
                        int end = start;
                        if (end < field.Length && field[end] == '[')
                        {
                            end = field.IndexOf(']', end) is var close and >= 0 ? close + 1 : field.Length;   // a domain literal
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
            // A quoted string or a comment that never ends swallows the rest of the field for this reader and not for another one: whatever follows may be an address to somebody.
            result.Add("?unterminated");
        }

        return result;
    }

    // White space and balanced comments (with quoted pairs) from the position; the position of the first character after them. A comment that never ends swallows the rest.
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

    // After "<": an obsolete route ("@a.example, @b.example:", RFC 5322 4.4) is skipped up to its colon; anything else is not touched. It is a route only when every "@" in it comes right after the
    // "<" or a "," (white space and comments between them allowed): "<@evil.example,ceo@victim.example:x@evil.example>" is not one, and Python reads ceo@victim.example in it.
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
                && field.AsSpan(i + 1, close - i - 1).IndexOfAnyExcept(DomainLiteralCharacters) < 0)
            {
                previous = ']';
                i = close + 1;   // a domain literal, which may hold colons ("@[IPv6:2001:db8::1]")
                continue;
            }

            if ((c == '@' && previous is not ('<' or ',')) || c is '<' or '>' or '"' or '\\' or ';')
            {
                return position;   // not a route: every "@" from here on is read as an address
            }

            previous = c;
            i++;
        }

        return position;
    }
}
