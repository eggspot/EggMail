using System.Buffers;
using System.Text;

namespace Mta.Smtp.Protocol;

/// <summary>The SMTP service extensions a server advertises (or that were parsed from an EHLO response).</summary>
public sealed class SmtpCapabilities
{
    public static readonly SmtpCapabilities None = new();

    public bool Pipelining { get; init; }
    public bool EightBitMime { get; init; }
    public bool BinaryMime { get; init; }
    public bool EnhancedStatusCodes { get; init; }
    public bool StartTls { get; init; }
    public bool SmtpUtf8 { get; init; }
    public bool Chunking { get; init; }
    public bool Dsn { get; init; }
    public bool RequireTls { get; init; }

    /// <summary>Maximum message size from <c>SIZE n</c>; 0 means "no limit declared", null means SIZE not offered.</summary>
    public long? Size { get; init; }

    /// <summary>AUTH mechanisms, upper-case.</summary>
    public IReadOnlyList<string> AuthMechanisms { get; init; } = [];

    /// <summary>Parses the extension lines of an EHLO reply (the first line is the greeting and must be skipped by the caller).</summary>
    public static SmtpCapabilities Parse(IEnumerable<string> extensionLines)
    {
        bool pipelining = false, eight = false, binary = false, enhanced = false, starttls = false, utf8 = false, chunking = false, dsn = false, requireTls = false;
        long? size = null;
        var auth = new List<string>();
        foreach (string line in extensionLines)
        {
            string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) { continue; }
            switch (parts[0].ToUpperInvariant())
            {
                case "PIPELINING": pipelining = true; break;
                case "8BITMIME": eight = true; break;
                case "BINARYMIME": binary = true; break;
                case "ENHANCEDSTATUSCODES": enhanced = true; break;
                case "STARTTLS": starttls = true; break;
                case "SMTPUTF8": utf8 = true; break;
                case "CHUNKING": chunking = true; break;
                case "DSN": dsn = true; break;
                case "REQUIRETLS": requireTls = true; break;
                case "SIZE":
                    size = parts.Length > 1 && long.TryParse(parts[1], out long n) && n >= 0 ? n : 0;
                    break;
                case "AUTH":
                case "AUTH=PLAIN":
                    for (int i = 1; i < parts.Length; i++) { auth.Add(parts[i].ToUpperInvariant()); }
                    break;
            }
        }

        return new SmtpCapabilities
        {
            Pipelining = pipelining, EightBitMime = eight, BinaryMime = binary, EnhancedStatusCodes = enhanced,
            StartTls = starttls, SmtpUtf8 = utf8, Chunking = chunking, Dsn = dsn, RequireTls = requireTls,
            Size = size, AuthMechanisms = auth,
        };
    }

    /// <summary>Builds the EHLO reply lines (greeting first).</summary>
    public IReadOnlyList<string> ToEhloLines(string greeting)
    {
        var lines = new List<string>(12) { greeting };
        if (Pipelining) { lines.Add("PIPELINING"); }
        if (Size is not null) { lines.Add(Size == 0 ? "SIZE" : $"SIZE {Size}"); }
        if (EightBitMime) { lines.Add("8BITMIME"); }
        if (BinaryMime) { lines.Add("BINARYMIME"); }
        if (SmtpUtf8) { lines.Add("SMTPUTF8"); }
        if (Chunking) { lines.Add("CHUNKING"); }
        if (EnhancedStatusCodes) { lines.Add("ENHANCEDSTATUSCODES"); }
        if (Dsn) { lines.Add("DSN"); }
        if (RequireTls) { lines.Add("REQUIRETLS"); }
        if (StartTls) { lines.Add("STARTTLS"); }
        if (AuthMechanisms.Count > 0) { lines.Add("AUTH " + string.Join(' ', AuthMechanisms)); }
        return lines;
    }
}
