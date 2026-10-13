using System.Collections;
using System.Text;
using Mta.Core;

namespace Mta.Mime;

/// <summary>An entry of an address header: a <see cref="Mailbox"/> or a <see cref="MailboxGroup"/>.</summary>
public abstract class AddressItem
{
    private protected AddressItem()
    {
    }
}

/// <summary>A mailbox: an optional display name and an address (RFC 5322 section 3.4).</summary>
public sealed class Mailbox : AddressItem
{
    /// <summary>Creates a valid mailbox. <paramref name="displayName"/> is the decoded, unquoted text.</summary>
    public Mailbox(string? displayName, EmailAddress address)
    {
        if (address.IsNull)
        {
            throw new ArgumentException("A mailbox needs a non-null address.", nameof(address));
        }

        DisplayName = string.IsNullOrEmpty(displayName) ? null : displayName;
        Address = address;
        AddrSpec = address.ToString();
        IsValid = true;
    }

    internal Mailbox(string? displayName, string addrSpec)
    {
        DisplayName = string.IsNullOrEmpty(displayName) ? null : displayName;
        AddrSpec = addrSpec;
        Address = default;
        IsValid = false;
    }

    /// <summary>Creates a mailbox from a display name and an address string (<c>user@example.com</c>).</summary>
    /// <exception cref="FormatException">The address is not valid.</exception>
    public static Mailbox Create(string? displayName, string address) =>
        new(displayName, EmailAddress.Parse(address, allowUtf8: true));

    /// <summary>Parses exactly one mailbox such as <c>Jane Doe &lt;jane@example.com&gt;</c>. Returns false for groups, lists and invalid addresses.</summary>
    public static bool TryParse(string? text, out Mailbox mailbox)
    {
        mailbox = null!;
        var list = AddressList.Parse(text);
        if (list.Count != 1 || list[0] is not Mailbox m || !m.IsValid)
        {
            return false;
        }

        mailbox = m;
        return true;
    }

    /// <summary>Parses exactly one mailbox.</summary>
    /// <exception cref="FormatException">The text is not exactly one valid mailbox.</exception>
    public static Mailbox Parse(string text) =>
        TryParse(text, out var m) ? m : throw new FormatException("Not a single valid mailbox: " + text);

    /// <summary>The decoded display name (RFC 2047 words decoded, quotes removed), or null.</summary>
    public string? DisplayName { get; }

    /// <summary>The parsed address; <c>default</c> (null address) when <see cref="IsValid"/> is false.</summary>
    public EmailAddress Address { get; }

    /// <summary>The address text as written (comments and folding removed), also for invalid addresses.</summary>
    public string AddrSpec { get; }

    /// <summary>True when <see cref="AddrSpec"/> parsed as a valid <see cref="EmailAddress"/>.</summary>
    public bool IsValid { get; }

    /// <summary>The domain of a valid address (lower-case A-label), or null. This is the "From domain" DMARC uses.</summary>
    public string? Domain => IsValid ? Address.Domain : null;

    /// <summary>
    /// Formats the mailbox for a header (unfolded): <c>Name &lt;local@domain&gt;</c>. Non-ASCII display names are RFC 2047
    /// encoded unless <paramref name="allowUtf8"/> (SMTPUTF8, RFC 6532) is set.
    /// </summary>
    /// <exception cref="HeaderInjectionException">The display name contains CR, LF or NUL.</exception>
    /// <exception cref="MessageBuildException">The address is invalid, or is international and <paramref name="allowUtf8"/> is false.</exception>
    public string ToHeaderValue(bool allowUtf8 = false)
    {
        if (!IsValid)
        {
            throw new MessageBuildException("Cannot format an invalid address: " + AddrSpec);
        }

        if (Address.IsInternational && !allowUtf8 && !IsAscii(Address.LocalPart))
        {
            throw new MessageBuildException("The address needs SMTPUTF8 (non-ASCII local part).");
        }

        string addr = Address.ToString();
        if (DisplayName is null)
        {
            return addr;
        }

        return FormatPhrase(DisplayName, allowUtf8) + " <" + addr + ">";
    }

    /// <inheritdoc />
    public override string ToString() => DisplayName is null ? AddrSpec : $"{DisplayName} <{AddrSpec}>";

    private static bool IsAscii(string s) => System.Text.Ascii.IsValid(s);

    internal static string FormatPhrase(string name, bool allowUtf8)
    {
        foreach (char c in name)
        {
            if (c is '\r' or '\n' or '\0')
            {
                throw new HeaderInjectionException("display name", "display name contains CR, LF or NUL");
            }
        }

        bool ascii = System.Text.Ascii.IsValid(name);
        if (!ascii && !allowUtf8)
        {
            return Rfc2047.EncodeWords(name);
        }

        if (name.Contains("=?", StringComparison.Ordinal))
        {
            return Rfc2047.EncodeWords(name);
        }

        bool atoms = name.Length > 0;
        foreach (char c in name)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c == ' ' || c > 0x7F || "!#$%&'*+-/=?^_`{|}~".Contains(c)))
            {
                atoms = false;
                break;
            }
        }

        if (atoms && !name.StartsWith(' ') && !name.EndsWith(' ') && !name.Contains("  ", StringComparison.Ordinal))
        {
            return name;
        }

        var sb = new StringBuilder(name.Length + 2);
        sb.Append('"');
        foreach (char c in name)
        {
            if (c is '"' or '\\')
            {
                sb.Append('\\');
            }

            sb.Append(c);
        }

        return sb.Append('"').ToString();
    }
}

/// <summary>A group such as <c>undisclosed-recipients:;</c> or <c>Team: a@x.org, b@y.org;</c>.</summary>
public sealed class MailboxGroup : AddressItem
{
    internal MailboxGroup(string name, IReadOnlyList<Mailbox> members)
    {
        Name = name;
        Members = members;
    }

    /// <summary>The group's display name.</summary>
    public string Name { get; }

    /// <summary>The group members (possibly none).</summary>
    public IReadOnlyList<Mailbox> Members { get; }
}

/// <summary>
/// The parsed value of an address header (From, To, Cc, Reply-To, Sender ...). Parsing is tolerant: comments, quoted
/// strings, groups, obsolete routes, missing angle brackets and encoded-word display names are handled; entries that
/// cannot be turned into an address are kept as invalid mailboxes and reported through <see cref="Anomalies"/>.
/// </summary>
public sealed class AddressList : IReadOnlyList<AddressItem>
{
    private readonly AddressItem[] _items;

    /// <summary>An empty list.</summary>
    public static AddressList Empty { get; } = new([], MimeAnomaly.None);

    private AddressList(AddressItem[] items, MimeAnomaly anomalies)
    {
        _items = items;
        Anomalies = anomalies;
    }

    /// <summary>Anomalies noticed while parsing.</summary>
    public MimeAnomaly Anomalies { get; }

    /// <inheritdoc />
    public int Count => _items.Length;

    /// <inheritdoc />
    public AddressItem this[int index] => _items[index];

    /// <summary>All mailboxes in order, with group members flattened in.</summary>
    public IEnumerable<Mailbox> Mailboxes
    {
        get
        {
            foreach (var a in _items)
            {
                if (a is Mailbox m)
                {
                    yield return m;
                }
                else if (a is MailboxGroup g)
                {
                    foreach (var gm in g.Members)
                    {
                        yield return gm;
                    }
                }
            }
        }
    }

    /// <summary>Number of mailboxes including group members.</summary>
    public int MailboxCount
    {
        get
        {
            int n = 0;
            foreach (var a in _items)
            {
                n += a is MailboxGroup g ? g.Members.Count : 1;
            }

            return n;
        }
    }

    /// <summary>
    /// Looks at the valid mailboxes (group members included, invalid entries skipped) and reports whether they all share one domain,
    /// without allocating. <paramref name="domain"/> is the lower-case domain of the first valid mailbox, also when the result is
    /// <see cref="CommonDomainResult.MultipleDomains"/>; it is null when there is no valid mailbox.
    /// </summary>
    public CommonDomainResult GetCommonDomain(out string? domain)
    {
        domain = null;
        bool differs = false;
        foreach (var item in _items)
        {
            if (item is Mailbox m)
            {
                Visit(m, ref domain, ref differs);
            }
            else if (item is MailboxGroup g)
            {
                foreach (var member in g.Members)
                {
                    Visit(member, ref domain, ref differs);
                }
            }
        }

        return domain is null ? CommonDomainResult.NoValidMailbox : differs ? CommonDomainResult.MultipleDomains : CommonDomainResult.Single;

        static void Visit(Mailbox mailbox, ref string? domain, ref bool differs)
        {
            if (!mailbox.IsValid)
            {
                return;
            }

            if (domain is null)
            {
                domain = mailbox.Address.Domain.ToLowerInvariant();
            }
            else if (!string.Equals(mailbox.Address.Domain, domain, StringComparison.OrdinalIgnoreCase))
            {
                differs = true;
            }
        }
    }

    /// <summary>Parses an address header value (the unfolded text; RFC 2047 words in display names are decoded).</summary>
    public static AddressList Parse(string? value, MimeLimits? limits = null) =>
        string.IsNullOrWhiteSpace(value) ? Empty : AddressParser.Parse(value, limits ?? MimeLimits.Default);

    /// <summary>Parses the value of a header field.</summary>
    public static AddressList Parse(MimeHeader header, MimeLimits? limits = null) =>
        Parse(header.GetValue((limits ?? MimeLimits.Default).MaxHeaderValueBytes), limits);

    /// <inheritdoc />
    public IEnumerator<AddressItem> GetEnumerator() => ((IEnumerable<AddressItem>)_items).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    internal static AddressList Create(AddressItem[] items, MimeAnomaly anomalies) => new(items, anomalies);
}

/// <summary>Outcome of <see cref="AddressList.GetCommonDomain"/>.</summary>
public enum CommonDomainResult
{
    /// <summary>There is no valid mailbox.</summary>
    NoValidMailbox,

    /// <summary>All valid mailboxes use the same domain (compared case-insensitively).</summary>
    Single,

    /// <summary>The valid mailboxes use more than one domain.</summary>
    MultipleDomains,
}

/// <summary>Tolerant RFC 5322 address-list parser. Every loop iteration consumes input, so it always terminates in linear time.</summary>
internal static class AddressParser
{
    public static AddressList Parse(string s, MimeLimits limits)
    {
        var items = new List<AddressItem>();
        var an = MimeAnomaly.None;
        int count = 0;
        int pos = 0;
        while (pos < s.Length)
        {
            FieldScanner.SkipCfws(s, ref pos);
            if (pos >= s.Length)
            {
                break;
            }

            if (s[pos] is ',' or ';')
            {
                pos++;
                continue;
            }

            if (count >= limits.MaxAddresses)
            {
                an |= MimeAnomaly.TooManyAddresses;
                break;
            }

            int colon = FindGroupColon(s, pos);
            if (colon >= 0)
            {
                string name = DecodeName(CollectPhrase(s.AsSpan(pos, colon - pos)), ref an);
                pos = colon + 1;
                var members = new List<Mailbox>();
                while (pos < s.Length)
                {
                    FieldScanner.SkipCfws(s, ref pos);
                    if (pos >= s.Length)
                    {
                        break;
                    }

                    if (s[pos] == ';')
                    {
                        pos++;
                        break;
                    }

                    if (s[pos] == ',')
                    {
                        pos++;
                        continue;
                    }

                    if (count >= limits.MaxAddresses)
                    {
                        an |= MimeAnomaly.TooManyAddresses;
                        pos = s.Length;
                        break;
                    }

                    int end = FindElementEnd(s, pos);
                    members.Add(ParseElement(s.AsSpan(pos, end - pos), ref an));
                    count++;
                    pos = end == pos ? end + 1 : end;
                }

                items.Add(new MailboxGroup(name, members));
                continue;
            }

            int elementEnd = FindElementEnd(s, pos);
            items.Add(ParseElement(s.AsSpan(pos, elementEnd - pos), ref an));
            count++;
            pos = elementEnd == pos ? elementEnd + 1 : elementEnd;
        }

        return AddressList.Create(items.ToArray(), an);
    }

    /// <summary>If a group header (<c>phrase ':'</c>) starts at <paramref name="pos"/>, returns the colon position, else -1.</summary>
    private static int FindGroupColon(string s, int pos)
    {
        int i = pos;
        while (i < s.Length)
        {
            char c = s[i];
            switch (c)
            {
                case ':':
                    return i;
                case '"':
                    i = SkipQuoted(s, i);
                    break;
                case '(':
                    FieldScanner.SkipComment(s, ref i);
                    break;
                case '<' or '@' or ',' or ';':
                    return -1;
                default:
                    i++;
                    break;
            }
        }

        return -1;
    }

    private static int SkipQuoted(string s, int i)
    {
        i++;
        while (i < s.Length && s[i] != '"')
        {
            i += s[i] == '\\' ? 2 : 1;
        }

        return Math.Min(i + 1, s.Length);
    }

    /// <summary>End of the element starting at <paramref name="pos"/>: the next top-level comma or semicolon.</summary>
    private static int FindElementEnd(string s, int pos)
    {
        int i = pos;
        while (i < s.Length)
        {
            char c = s[i];
            switch (c)
            {
                case ',' or ';':
                    return i;
                case '"':
                    i = SkipQuoted(s, i);
                    break;
                case '(':
                    FieldScanner.SkipComment(s, ref i);
                    break;
                case '<':
                    {
                        i++;
                        while (i < s.Length && s[i] != '>')
                        {
                            i = s[i] == '"' ? SkipQuoted(s, i) : i + 1;
                        }

                        i = Math.Min(i + 1, s.Length);
                        break;
                    }

                default:
                    i++;
                    break;
            }
        }

        return s.Length;
    }

    private static Mailbox ParseElement(ReadOnlySpan<char> el, ref MimeAnomaly an)
    {
        // Split into: phrase words (atoms and quoted strings, in order), comments, angle-addr content.
        var phrase = new StringBuilder();
        string? lastComment = null;
        string? angle = null;
        int i = 0;
        bool sawAnglePhrase = false;
        while (i < el.Length)
        {
            char c = el[i];
            if (c is ' ' or '\t' or '\r' or '\n')
            {
                i++;
            }
            else if (c == '(')
            {
                int start = i;
                FieldScanner.SkipComment(el, ref i);
                int end = el[start..i].EndsWith(")") ? i - 1 : i;
                lastComment = Unescape(el[(start + 1)..Math.Max(start + 1, end)]);
            }
            else if (c == '<')
            {
                int start = ++i;
                while (i < el.Length && el[i] != '>')
                {
                    i = el[i] == '"' ? SkipQuoted(el, i) : i + 1;
                }

                if (angle is null)
                {
                    angle = el[start..Math.Min(i, el.Length)].ToString();
                    sawAnglePhrase = true;
                }
                else
                {
                    an |= MimeAnomaly.InvalidAddress; // a second angle-addr: only the first one is used
                }

                if (i >= el.Length)
                {
                    an |= MimeAnomaly.InvalidAddress; // missing '>'
                }

                i = Math.Min(i + 1, el.Length);
            }
            else if (c == '"')
            {
                int start = i;
                i = SkipQuoted(el, i);
                int end = i > start + 1 && el[i - 1] == '"' ? i - 1 : i;
                if (angle is null)
                {
                    if (phrase.Length > 0)
                    {
                        phrase.Append(' ');
                    }

                    phrase.Append(Unescape(el[(start + 1)..Math.Max(start + 1, end)]));
                }
                else
                {
                    an |= MimeAnomaly.InvalidAddress; // text after the angle-addr is ignored
                }
            }
            else
            {
                int start = i;
                while (i < el.Length && el[i] is not (' ' or '\t' or '\r' or '\n' or '"' or '(' or '<'))
                {
                    i++;
                }

                if (angle is null)
                {
                    if (phrase.Length > 0)
                    {
                        phrase.Append(' ');
                    }

                    phrase.Append(el[start..i]);
                }
                else
                {
                    an |= MimeAnomaly.InvalidAddress; // text after the angle-addr is ignored
                }
            }
        }

        if (sawAnglePhrase)
        {
            string name = phrase.Length > 0 ? DecodeName(phrase.ToString(), ref an) : (lastComment is null ? string.Empty : DecodeName(lastComment, ref an));
            return MakeMailbox(name, StripRoute(angle!), ref an);
        }

        // No angle-addr: the element is an addr-spec, possibly with comments and obsolete whitespace around dots and at-signs,
        // or "Display Name addr@host" without brackets.
        string dispFromComment = lastComment is null ? string.Empty : DecodeName(lastComment, ref an);
        var runs = SplitRuns(el);
        if (runs.Count == 0)
        {
            an |= MimeAnomaly.InvalidAddress;
            return new Mailbox(dispFromComment, string.Empty);
        }

        if (runs.Count == 1)
        {
            return MakeMailbox(dispFromComment, runs[0], ref an);
        }

        int atRun = -1;
        int atCount = 0;
        for (int r = 0; r < runs.Count; r++)
        {
            if (runs[r].Contains('@'))
            {
                atRun = r;
                atCount++;
            }
        }

        if (atCount == 1)
        {
            an |= MimeAnomaly.InvalidAddress; // recovered, but a display name without angle brackets is not valid syntax
            var name = new StringBuilder();
            for (int r = 0; r < runs.Count; r++)
            {
                if (r != atRun)
                {
                    if (name.Length > 0)
                    {
                        name.Append(' ');
                    }

                    name.Append(runs[r].Trim('"'));
                }
            }

            return MakeMailbox(DecodeName(name.ToString(), ref an), runs[atRun], ref an);
        }

        return MakeMailbox(dispFromComment, string.Concat(runs), ref an);
    }

    private static Mailbox MakeMailbox(string displayName, string addrSpecRaw, ref MimeAnomaly an)
    {
        string spec = StripCfwsKeepQuotes(addrSpecRaw);
        if (EmailAddress.TryParse(spec, allowUtf8: true, out var address))
        {
            return new Mailbox(displayName, address);
        }

        an |= MimeAnomaly.InvalidAddress;
        return new Mailbox(displayName, spec);
    }

    /// <summary>Splits into whitespace-separated runs outside quotes and comments; runs touching a dot or at-sign are merged (obs-addr-spec).</summary>
    private static List<string> SplitRuns(ReadOnlySpan<char> el)
    {
        var runs = new List<string>();
        var cur = new StringBuilder();
        int i = 0;
        while (i < el.Length)
        {
            char c = el[i];
            if (c is ' ' or '\t' or '\r' or '\n')
            {
                i++;
                EndRun(runs, cur);
            }
            else if (c == '(')
            {
                FieldScanner.SkipComment(el, ref i);
                EndRun(runs, cur);
            }
            else if (c == '"')
            {
                int start = i;
                i = SkipQuoted(el, i);
                cur.Append(el[start..i]);
            }
            else
            {
                cur.Append(c);
                i++;
            }
        }

        EndRun(runs, cur);
        for (int r = runs.Count - 1; r > 0; r--)
        {
            string prev = runs[r - 1];
            string next = runs[r];
            if (prev[^1] is '.' or '@' || next[0] is '.' or '@')
            {
                runs[r - 1] = prev + next;
                runs.RemoveAt(r);
            }
        }

        return runs;
    }

    private static void EndRun(List<string> runs, StringBuilder cur)
    {
        if (cur.Length > 0)
        {
            runs.Add(cur.ToString());
            cur.Clear();
        }
    }

    /// <summary>Removes an obsolete source route (<c>@a,@b:</c>) from the content of an angle-addr.</summary>
    private static string StripRoute(string angle)
    {
        int i = 0;
        while (i < angle.Length && angle[i] is ' ' or '\t')
        {
            i++;
        }

        if (i < angle.Length && angle[i] == '@')
        {
            int colon = angle.IndexOf(':', i);
            if (colon >= 0)
            {
                return angle[(colon + 1)..];
            }
        }

        return angle;
    }

    /// <summary>Removes comments and whitespace outside quoted strings.</summary>
    private static string StripCfwsKeepQuotes(ReadOnlySpan<char> s)
    {
        var sb = new StringBuilder(s.Length);
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            if (c is ' ' or '\t' or '\r' or '\n')
            {
                i++;
            }
            else if (c == '(')
            {
                FieldScanner.SkipComment(s, ref i);
            }
            else if (c == '"')
            {
                int start = i;
                i++;
                while (i < s.Length && s[i] != '"')
                {
                    i += s[i] == '\\' ? 2 : 1;
                }

                i = Math.Min(i + 1, s.Length);
                sb.Append(s[start..i]);
            }
            else
            {
                sb.Append(c);
                i++;
            }
        }

        return sb.ToString();
    }

    private static string CollectPhrase(ReadOnlySpan<char> s)
    {
        var sb = new StringBuilder();
        int i = 0;
        while (i < s.Length)
        {
            char c = s[i];
            if (c is ' ' or '\t' or '\r' or '\n')
            {
                i++;
            }
            else if (c == '(')
            {
                FieldScanner.SkipComment(s, ref i);
            }
            else if (c == '"')
            {
                int start = i;
                i = SkipQuoted(s, i);
                int end = i > start + 1 && s[i - 1] == '"' ? i - 1 : i;
                if (sb.Length > 0)
                {
                    sb.Append(' ');
                }

                sb.Append(Unescape(s[(start + 1)..Math.Max(start + 1, end)]));
            }
            else
            {
                int start = i;
                while (i < s.Length && s[i] is not (' ' or '\t' or '\r' or '\n' or '"' or '('))
                {
                    i++;
                }

                if (sb.Length > 0)
                {
                    sb.Append(' ');
                }

                sb.Append(s[start..i]);
            }
        }

        return sb.ToString();
    }

    private static int SkipQuoted(ReadOnlySpan<char> s, int i)
    {
        i++;
        while (i < s.Length && s[i] != '"')
        {
            i += s[i] == '\\' ? 2 : 1;
        }

        return Math.Min(i + 1, s.Length);
    }

    private static string Unescape(ReadOnlySpan<char> s)
    {
        if (!s.Contains('\\'))
        {
            return s.ToString();
        }

        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '\\' && i + 1 < s.Length)
            {
                i++;
            }

            sb.Append(s[i]);
        }

        return sb.ToString();
    }

    private static string DecodeName(string raw, ref MimeAnomaly an)
    {
        string decoded = raw.Contains("=?", StringComparison.Ordinal) ? Rfc2047.DecodeCore(raw, ref an) : raw;
        return decoded.Trim();
    }
}
