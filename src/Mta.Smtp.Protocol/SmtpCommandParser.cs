using System.Buffers.Text;
using System.Text;
using Mta.Core;

namespace Mta.Smtp.Protocol;

/// <summary>Options controlling command parsing.</summary>
public sealed class SmtpParseOptions
{
    /// <summary>Maximum command line length in octets including CRLF (RFC 5321 §4.5.3.1.4 says 512; extensions add to it).</summary>
    public int MaxLineLength { get; init; } = 2048;

    /// <summary>Whether SMTPUTF8 is advertised, which allows non-ASCII mailboxes.</summary>
    public bool AllowSmtpUtf8 { get; init; } = true;

    /// <summary>
    /// Optional memo of recently parsed mailboxes (one per session; it is not thread safe), so the sender of every message of a connection is not
    /// allocated again. Parsing gives the same result with or without it.
    /// </summary>
    public EmailAddressCache? AddressCache { get; init; }

    public static readonly SmtpParseOptions Default = new();
}

/// <summary>
/// Parses a command line (without the trailing CRLF). The caller has already rejected bare CR/LF; NUL and other
/// control characters are rejected here.
/// </summary>
public static class SmtpCommandParser
{
    public static SmtpParseError TryParse(ReadOnlySpan<byte> line, SmtpParseOptions options, out SmtpCommand command)
    {
        command = default;
        if (line.Length + 2 > options.MaxLineLength)
        {
            return SmtpParseError.LineTooLong;
        }

        foreach (byte b in line)
        {
            if (b == 0 || (b < 32 && b != '\t') || b == 127)
            {
                return SmtpParseError.InvalidCharacter;
            }
        }

        int sp = line.IndexOf((byte)' ');
        ReadOnlySpan<byte> verbSpan = sp < 0 ? line : line[..sp];
        ReadOnlySpan<byte> rest = sp < 0 ? default : TrimStart(line[(sp + 1)..]);
        SmtpVerb verb = ParseVerb(verbSpan);
        switch (verb)
        {
            case SmtpVerb.Helo:
            case SmtpVerb.Ehlo:
                {
                    if (rest.Length == 0) { return SmtpParseError.Syntax; }
                    string? domain = ParseDomain(TrimEnd(rest));
                    if (domain is null) { return SmtpParseError.Syntax; }
                    command = new SmtpCommand { Verb = verb, Argument = domain };
                    return SmtpParseError.None;
                }

            case SmtpVerb.Mail:
                return ParseMail(rest, options, out command);

            case SmtpVerb.Rcpt:
                return ParseRcpt(rest, options, out command);

            case SmtpVerb.Data:
            case SmtpVerb.Rset:
            case SmtpVerb.Quit:
            case SmtpVerb.StartTls:
                if (TrimEnd(rest).Length != 0) { return SmtpParseError.Syntax; }
                command = new SmtpCommand { Verb = verb };
                return SmtpParseError.None;

            case SmtpVerb.Noop:
            case SmtpVerb.Help:
            case SmtpVerb.Vrfy:
            case SmtpVerb.Expn:
                command = new SmtpCommand { Verb = verb, Argument = rest.Length == 0 ? null : Encoding.UTF8.GetString(TrimEnd(rest)) };
                return SmtpParseError.None;

            case SmtpVerb.Bdat:
                return ParseBdat(rest, out command);

            case SmtpVerb.Auth:
                return ParseAuth(rest, out command);

            default:
                return SmtpParseError.UnknownCommand;
        }
    }

    private static SmtpVerb ParseVerb(ReadOnlySpan<byte> v)
    {
        if (v.Length is < 4 or > 8) { return SmtpVerb.Unknown; }
        Span<byte> upper = stackalloc byte[8];
        for (int i = 0; i < v.Length; i++)
        {
            byte c = v[i];
            upper[i] = c is >= (byte)'a' and <= (byte)'z' ? (byte)(c - 32) : c;
        }

        ReadOnlySpan<byte> u = upper[..v.Length];
        if (u.SequenceEqual("HELO"u8)) { return SmtpVerb.Helo; }
        if (u.SequenceEqual("EHLO"u8)) { return SmtpVerb.Ehlo; }
        if (u.SequenceEqual("MAIL"u8)) { return SmtpVerb.Mail; }
        if (u.SequenceEqual("RCPT"u8)) { return SmtpVerb.Rcpt; }
        if (u.SequenceEqual("DATA"u8)) { return SmtpVerb.Data; }
        if (u.SequenceEqual("BDAT"u8)) { return SmtpVerb.Bdat; }
        if (u.SequenceEqual("RSET"u8)) { return SmtpVerb.Rset; }
        if (u.SequenceEqual("NOOP"u8)) { return SmtpVerb.Noop; }
        if (u.SequenceEqual("QUIT"u8)) { return SmtpVerb.Quit; }
        if (u.SequenceEqual("VRFY"u8)) { return SmtpVerb.Vrfy; }
        if (u.SequenceEqual("EXPN"u8)) { return SmtpVerb.Expn; }
        if (u.SequenceEqual("HELP"u8)) { return SmtpVerb.Help; }
        if (u.SequenceEqual("STARTTLS"u8)) { return SmtpVerb.StartTls; }
        if (u.SequenceEqual("AUTH"u8)) { return SmtpVerb.Auth; }
        return SmtpVerb.Unknown;
    }

    private static string? ParseDomain(ReadOnlySpan<byte> s)
    {
        if (s.Length == 0 || s.Length > 255) { return null; }
        foreach (byte b in s)
        {
            if (b == ' ') { return null; }
        }

        if (s[0] == '[')
        {
            if (s[^1] != ']') { return null; }
            return Encoding.ASCII.GetString(s);
        }

        // Be liberal about HELO names: real clients send underscores, bare IPs, single labels. Reject only
        // characters that could cause trouble downstream (headers, logs).
        foreach (byte b in s)
        {
            if (b > 0x7E || b < 0x21 || b is (byte)'<' or (byte)'>' or (byte)'"' or (byte)'\\' or (byte)'(' or (byte)')')
            {
                // Non-ASCII HELO names are tolerated when valid UTF-8 (SMTPUTF8 clients).
                if (b > 0x7F) { continue; }
                return null;
            }
        }

        return Encoding.UTF8.GetString(s);
    }

    private static SmtpParseError ParseMail(ReadOnlySpan<byte> rest, SmtpParseOptions options, out SmtpCommand command)
    {
        command = default;
        if (!StartsWithIgnoreCase(rest, "FROM:"u8)) { return SmtpParseError.Syntax; }
        rest = TrimStart(rest[5..]);
        var err = ParsePath(rest, options, allowNull: true, out var path, out var after);
        if (err != SmtpParseError.None) { return err; }

        long? size = null;
        var body = SmtpBodyType.SevenBit;
        bool utf8 = false;
        string? auth = null, envid = null;
        bool retHdrs = false;
        var seen = 0;

        while (true)
        {
            after = TrimStart(after);
            if (after.Length == 0) { break; }
            int end = after.IndexOf((byte)' ');
            var token = end < 0 ? after : after[..end];
            after = end < 0 ? default : after[(end + 1)..];
            int eq = token.IndexOf((byte)'=');
            var name = eq < 0 ? token : token[..eq];
            var value = eq < 0 ? default : token[(eq + 1)..];

            if (EqualsIgnoreCase(name, "SIZE"u8))
            {
                if (eq < 0 || (seen & 1) != 0) { return SmtpParseError.BadParameter; }
                seen |= 1;
                if (!Utf8Parser.TryParse(value, out long n, out int used) || used != value.Length || n < 0) { return SmtpParseError.BadParameter; }
                size = n;
            }
            else if (EqualsIgnoreCase(name, "BODY"u8))
            {
                if (eq < 0 || (seen & 2) != 0) { return SmtpParseError.BadParameter; }
                seen |= 2;
                if (EqualsIgnoreCase(value, "7BIT"u8)) { body = SmtpBodyType.SevenBit; }
                else if (EqualsIgnoreCase(value, "8BITMIME"u8)) { body = SmtpBodyType.EightBitMime; }
                else if (EqualsIgnoreCase(value, "BINARYMIME"u8)) { body = SmtpBodyType.BinaryMime; }
                else { return SmtpParseError.BadParameter; }
            }
            else if (EqualsIgnoreCase(name, "SMTPUTF8"u8))
            {
                if (eq >= 0 || (seen & 4) != 0 || !options.AllowSmtpUtf8) { return SmtpParseError.BadParameter; }
                seen |= 4;
                utf8 = true;
            }
            else if (EqualsIgnoreCase(name, "AUTH"u8))
            {
                if (eq < 0 || (seen & 8) != 0) { return SmtpParseError.BadParameter; }
                seen |= 8;
                auth = Encoding.ASCII.GetString(value);
            }
            else if (EqualsIgnoreCase(name, "ENVID"u8))
            {
                if (eq < 0 || (seen & 16) != 0 || value.Length > 100) { return SmtpParseError.BadParameter; }
                seen |= 16;
                envid = Encoding.ASCII.GetString(value);
            }
            else if (EqualsIgnoreCase(name, "RET"u8))
            {
                if (eq < 0 || (seen & 32) != 0) { return SmtpParseError.BadParameter; }
                seen |= 32;
                if (EqualsIgnoreCase(value, "HDRS"u8)) { retHdrs = true; }
                else if (!EqualsIgnoreCase(value, "FULL"u8)) { return SmtpParseError.BadParameter; }
            }
            else
            {
                return SmtpParseError.ParameterNotImplemented;
            }
        }

        if (!utf8 && path.IsInternational) { return SmtpParseError.BadParameter; }
        command = new SmtpCommand
        {
            Verb = SmtpVerb.Mail,
            Path = path,
            Mail = new MailParameters(size, body, utf8, auth, envid, retHdrs),
        };
        return SmtpParseError.None;
    }

    private static SmtpParseError ParseRcpt(ReadOnlySpan<byte> rest, SmtpParseOptions options, out SmtpCommand command)
    {
        command = default;
        if (!StartsWithIgnoreCase(rest, "TO:"u8)) { return SmtpParseError.Syntax; }
        rest = TrimStart(rest[3..]);
        var err = ParsePath(rest, options, allowNull: false, out var path, out var after);
        if (err != SmtpParseError.None) { return err; }

        string? notify = null, orcpt = null;
        while (true)
        {
            after = TrimStart(after);
            if (after.Length == 0) { break; }
            int end = after.IndexOf((byte)' ');
            var token = end < 0 ? after : after[..end];
            after = end < 0 ? default : after[(end + 1)..];
            int eq = token.IndexOf((byte)'=');
            if (eq < 0) { return SmtpParseError.BadParameter; }
            var name = token[..eq];
            var value = token[(eq + 1)..];
            if (EqualsIgnoreCase(name, "NOTIFY"u8)) { notify = Encoding.ASCII.GetString(value); }
            else if (EqualsIgnoreCase(name, "ORCPT"u8)) { orcpt = Encoding.UTF8.GetString(value); }
            else { return SmtpParseError.ParameterNotImplemented; }
        }

        command = new SmtpCommand { Verb = SmtpVerb.Rcpt, Path = path, Rcpt = new RcptParameters(notify, orcpt) };
        return SmtpParseError.None;
    }

    private static SmtpParseError ParseBdat(ReadOnlySpan<byte> rest, out SmtpCommand command)
    {
        command = default;
        rest = TrimEnd(rest);
        int sp = rest.IndexOf((byte)' ');
        var num = sp < 0 ? rest : rest[..sp];
        bool last = false;
        if (sp >= 0)
        {
            var tail = TrimStart(rest[(sp + 1)..]);
            if (!EqualsIgnoreCase(tail, "LAST"u8)) { return SmtpParseError.Syntax; }
            last = true;
        }

        if (num.Length == 0 || num.Length > 12 || !Utf8Parser.TryParse(num, out long size, out int used) || used != num.Length || size < 0)
        {
            return SmtpParseError.Syntax;
        }

        command = new SmtpCommand { Verb = SmtpVerb.Bdat, ChunkSize = size, LastChunk = last };
        return SmtpParseError.None;
    }

    private static SmtpParseError ParseAuth(ReadOnlySpan<byte> rest, out SmtpCommand command)
    {
        command = default;
        rest = TrimEnd(rest);
        if (rest.Length == 0) { return SmtpParseError.Syntax; }
        int sp = rest.IndexOf((byte)' ');
        var mech = sp < 0 ? rest : rest[..sp];
        string? initial = null;
        if (sp >= 0)
        {
            var ir = TrimStart(rest[(sp + 1)..]);
            if (ir.Length == 0 || ir.IndexOf((byte)' ') >= 0) { return SmtpParseError.Syntax; }
            initial = Encoding.ASCII.GetString(ir);
        }

        foreach (byte b in mech)
        {
            if (!(b is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9' or (byte)'-' or (byte)'_'))
            {
                return SmtpParseError.Syntax;
            }
        }

        command = new SmtpCommand { Verb = SmtpVerb.Auth, Argument = Encoding.ASCII.GetString(mech).ToUpperInvariant(), InitialResponse = initial };
        return SmtpParseError.None;
    }

    /// <summary>
    /// Parses <c>&lt;path&gt;</c> where path may include a source route (accepted and stripped, RFC 5321 Appendix C).
    /// Unbracketed paths are rejected (strict), except where clients are known to omit them nowhere in v1.
    /// </summary>
    private static SmtpParseError ParsePath(ReadOnlySpan<byte> s, SmtpParseOptions options, bool allowNull, out EmailAddress address, out ReadOnlySpan<byte> after)
    {
        address = default;
        after = default;
        if (s.Length < 2 || s[0] != '<') { return SmtpParseError.Syntax; }

        // Find the closing '>' outside a quoted local part.
        int close = -1;
        bool quoted = false;
        for (int i = 1; i < s.Length; i++)
        {
            byte c = s[i];
            if (quoted)
            {
                if (c == '\\') { i++; }
                else if (c == '"') { quoted = false; }
            }
            else if (c == '"') { quoted = true; }
            else if (c == '>') { close = i; break; }
        }

        if (close < 0) { return SmtpParseError.Syntax; }
        var inner = s[1..close];
        after = s[(close + 1)..];
        if (after.Length > 0 && after[0] != ' ') { return SmtpParseError.Syntax; }

        if (inner.Length == 0)
        {
            if (!allowNull) { return SmtpParseError.Syntax; }
            address = EmailAddress.Null;
            return SmtpParseError.None;
        }

        // Strip an obsolete source route "@a,@b:" prefix.
        if (inner[0] == '@')
        {
            int colon = inner.IndexOf((byte)':');
            if (colon < 0) { return SmtpParseError.Syntax; }
            inner = inner[(colon + 1)..];
        }

        // Decoded into stack memory: only the address parts that the result keeps are allocated.
        Span<char> chars = inner.Length <= 512 ? stackalloc char[inner.Length] : new char[inner.Length];
        int length = Encoding.UTF8.GetChars(inner, chars);
        if (!EmailAddress.TryParse(chars[..length], options.AllowSmtpUtf8, options.AddressCache, out address))
        {
            return SmtpParseError.Syntax;
        }

        return SmtpParseError.None;
    }

    private static ReadOnlySpan<byte> TrimStart(ReadOnlySpan<byte> s)
    {
        int i = 0;
        while (i < s.Length && (s[i] == ' ' || s[i] == '\t')) { i++; }
        return s[i..];
    }

    private static ReadOnlySpan<byte> TrimEnd(ReadOnlySpan<byte> s)
    {
        int n = s.Length;
        while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t')) { n--; }
        return s[..n];
    }

    private static bool StartsWithIgnoreCase(ReadOnlySpan<byte> s, ReadOnlySpan<byte> upperPrefix)
    {
        if (s.Length < upperPrefix.Length) { return false; }
        return EqualsIgnoreCase(s[..upperPrefix.Length], upperPrefix);
    }

    private static bool EqualsIgnoreCase(ReadOnlySpan<byte> s, ReadOnlySpan<byte> upper)
    {
        if (s.Length != upper.Length) { return false; }
        for (int i = 0; i < s.Length; i++)
        {
            byte c = s[i];
            if (c is >= (byte)'a' and <= (byte)'z') { c = (byte)(c - 32); }
            if (c != upper[i]) { return false; }
        }

        return true;
    }
}
