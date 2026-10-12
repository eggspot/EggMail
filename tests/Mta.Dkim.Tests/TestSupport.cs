using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Mta.Core;
using Mta.Dns;
using Mta.Dkim.Internal;

namespace Mta.Dkim.Tests;

internal sealed class FixedClock : IClock
{
    private DateTimeOffset _now;

    public FixedClock(DateTimeOffset now) => _now = now;

    public DateTimeOffset UtcNow => _now;

    public long Timestamp => _now.Ticks;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>RSA keys are slow to generate; share them across tests.</summary>
internal static class TestKeys
{
    public static readonly RSA Rsa2048 = RSA.Create(2048);
    public static readonly RSA Rsa2048Other = RSA.Create(2048);
    public static readonly RSA Rsa1024 = RSA.Create(1024);
}

internal static class Msg
{
    public static readonly DateTimeOffset Now = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);

    public static byte[] Bytes(string s) => Encoding.Latin1.GetBytes(s);

    public static string Text(ReadOnlySpan<byte> b) => Encoding.Latin1.GetString(b);

    /// <summary>A typical outbound message.</summary>
    public static string Simple(string body = "Hello,\r\n\r\nThis is the body.\r\n") =>
        "Received: from client (client.example.org [192.0.2.7])\r\n\tby mx.example.com with ESMTP id abc123;\r\n\tMon, 12 Oct 2026 11:59:59 +0000\r\n"
        + "From: Alice <alice@example.com>\r\n"
        + "To: Bob <bob@example.net>\r\n"
        + "Subject: Test message\r\n"
        + "Date: Mon, 12 Oct 2026 12:00:00 +0000\r\n"
        + "Message-ID: <1234@example.com>\r\n"
        + "MIME-Version: 1.0\r\n"
        + "Content-Type: text/plain; charset=utf-8\r\n"
        + "\r\n"
        + body;

    public static string Prepend(string header, string message) => header + message;

    public static string InsertBeforeBlankLine(string message, string header)
    {
        int i = message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return message.Substring(0, i + 2) + header + message.Substring(i + 2);
    }

    public static string Sign(DkimSigner signer, string message) => signer.Sign(Bytes(message)) + message;

    public static DkimSigner Signer(RSA? key = null, string domain = "example.com", string selector = "sel",        DkimCanonicalization header = DkimCanonicalization.Relaxed, DkimCanonicalization body = DkimCanonicalization.Relaxed,
        bool oversign = true, IReadOnlyList<string>? headers = null, TimeSpan? lifetime = null, string? identity = null, IClock? clock = null)
    {
        return new DkimSigner(new DkimSignerOptions
        {
            Domain = domain,
            Selector = selector,
            HeaderCanonicalization = header,
            BodyCanonicalization = body,
            OversignHeaders = oversign,
            SignedHeaders = headers ?? DkimSignerOptions.DefaultSignedHeaders,
            SignatureLifetime = lifetime,
            Identity = identity,
            Clock = clock ?? new FixedClock(Now),
        }, key ?? TestKeys.Rsa2048);
    }

    public static StaticDnsResolver Dns(RSA key, string domain = "example.com", string selector = "sel", string? txt = null)
    {
        var dns = new StaticDnsResolver();
        dns.AddTxt($"{selector}._domainkey.{domain}", txt ?? DkimKeyTools.FormatDnsTxtValue(key));
        return dns;
    }

    public static DkimVerifier Verifier(IDnsResolver dns, IClock? clock = null, Action<DkimVerifierOptionsBuilder>? configure = null)
    {
        var b = new DkimVerifierOptionsBuilder { Clock = clock ?? new FixedClock(Now) };
        configure?.Invoke(b);
        return new DkimVerifier(dns, b.Build());
    }

    public static async Task<DkimVerificationResult> VerifyOne(DkimVerifier verifier, string message)
    {
        var results = await verifier.VerifyAsync(Bytes(message));
        return Assert.Single(results);
    }

    public static string ReplaceFirst(string text, string find, string replace)
    {
        int i = text.IndexOf(find, StringComparison.Ordinal);
        Assert.True(i >= 0, "pattern not found: " + find);
        return text.Substring(0, i) + replace + text.Substring(i + find.Length);
    }
}

/// <summary>Mutable builder because the options type is init-only.</summary>
internal sealed class DkimVerifierOptionsBuilder
{
    public IClock Clock { get; set; } = SystemClock.Instance;
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);
    public int MaxSignaturesVerified { get; set; } = 5;
    public int MaxHeaderCount { get; set; } = 1024;
    public int MaxSignatureHeaderLength { get; set; } = 16384;
    public int MinimumKeyBits { get; set; } = 1024;
    public int WeakKeyBelowBits { get; set; } = 2048;
    public int MaximumKeyBits { get; set; } = 4096;
    public bool RejectBodyLengthLimit { get; set; }

    public DkimVerifierOptions Build() => new()
    {
        Clock = Clock,
        ClockSkew = ClockSkew,
        MaxSignaturesVerified = MaxSignaturesVerified,
        MaxHeaderCount = MaxHeaderCount,
        MaxSignatureHeaderLength = MaxSignatureHeaderLength,
        MinimumKeyBits = MinimumKeyBits,
        WeakKeyBelowBits = WeakKeyBelowBits,
        MaximumKeyBits = MaximumKeyBits,
        RejectBodyLengthLimit = RejectBodyLengthLimit,
    };
}

/// <summary>A resolver wrapper that counts queries and can inject failures.</summary>
internal sealed class SpyResolver : IDnsResolver
{
    private readonly IDnsResolver _inner;
    private int _queries;

    public SpyResolver(IDnsResolver inner) => _inner = inner;

    public Func<string, Exception?>? Throw { get; set; }

    public int Queries => Volatile.Read(ref _queries);

    public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref _queries);
        var ex = Throw?.Invoke(name);
        if (ex is not null) { throw ex; }
        return _inner.QueryAsync(name, type, cancellationToken);
    }
}

/// <summary>
/// An independent, deliberately naive (string and regex based) implementation of RFC 6376 section 3.4 and of signature
/// creation, used as an oracle for the span based production code and to craft signatures with arbitrary tags (l=, x=, ...).
/// </summary>
internal static class Reference
{
    public static string RelaxedHeader(string field)
    {
        if (field.EndsWith("\r\n", StringComparison.Ordinal)) { field = field.Substring(0, field.Length - 2); }
        int colon = field.IndexOf(':');
        string name = field.Substring(0, colon).Trim(' ', '\t').ToLowerInvariant();
        string value = field.Substring(colon + 1);
        value = value.Replace("\r\n", string.Empty);
        value = Regex.Replace(value, "[ \t]+", " ").Trim(' ');
        return name + ":" + value + "\r\n";
    }

    public static string SimpleHeader(string field) => field.EndsWith("\r\n", StringComparison.Ordinal) ? field : field + "\r\n";

    public static string Body(string body, bool relaxed)
    {
        var lines = new List<string>(body.Split("\r\n"));
        if (lines.Count > 0 && lines[^1].Length == 0) { lines.RemoveAt(lines.Count - 1); }
        if (relaxed)
        {
            for (int i = 0; i < lines.Count; i++) { lines[i] = Regex.Replace(lines[i], "[ \t]+", " ").TrimEnd(' '); }
        }

        while (lines.Count > 0 && lines[^1].Length == 0) { lines.RemoveAt(lines.Count - 1); }
        if (lines.Count == 0) { return relaxed ? string.Empty : "\r\n"; }
        var sb = new StringBuilder();
        foreach (string l in lines) { sb.Append(l).Append("\r\n"); }
        return sb.ToString();
    }

    public static (List<string> Headers, string Body) Split(string message)
    {
        int i = message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        string head = i < 0 ? message : message.Substring(0, i + 2);
        string body = i < 0 ? string.Empty : message.Substring(i + 4);
        var headers = new List<string>();
        foreach (string line in head.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            if ((line[0] == ' ' || line[0] == '\t') && headers.Count > 0) { headers[^1] += "\r\n" + line; }
            else { headers.Add(line); }
        }

        return (headers, body);
    }

    /// <summary>
    /// Creates a complete DKIM-Signature header (without trailing CRLF) over <paramref name="message"/> with exactly the tags given in
    /// <paramref name="extraTags"/> appended before b=. The tag order is v, a, c, d, s, [extra], h, bh, b.
    /// </summary>
    public static string MakeSignature(string message, RSA key, string domain, string selector, string signedHeaders,
        bool headerRelaxed = true, bool bodyRelaxed = true, long? bodyLength = null, string extraTags = "", string algorithm = "rsa-sha256")
    {
        var (headers, body) = Split(message);
        string canonBody = Body(body, bodyRelaxed);
        if (bodyLength is long l) { canonBody = canonBody.Substring(0, (int)Math.Min(l, canonBody.Length)); }
        string bh = Convert.ToBase64String(SHA256.HashData(Encoding.Latin1.GetBytes(canonBody)));

        var names = signedHeaders.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var used = new HashSet<int>();
        var data = new StringBuilder();
        foreach (string name in names)
        {
            for (int i = headers.Count - 1; i >= 0; i--)
            {
                if (used.Contains(i)) { continue; }
                string hn = headers[i].Substring(0, headers[i].IndexOf(':')).Trim(' ', '\t');
                if (!string.Equals(hn, name, StringComparison.OrdinalIgnoreCase)) { continue; }
                used.Add(i);
                data.Append(headerRelaxed ? RelaxedHeader(headers[i]) : SimpleHeader(headers[i]));
                break;
            }
        }

        string c = (headerRelaxed ? "relaxed" : "simple") + "/" + (bodyRelaxed ? "relaxed" : "simple");
        string lTag = bodyLength is long len ? $"l={len}; " : string.Empty;
        string template = $"DKIM-Signature: v=1; a={algorithm}; c={c}; d={domain}; s={selector}; {extraTags}{lTag}h={signedHeaders}; bh={bh}; b=";
        string canonSig = headerRelaxed ? RelaxedHeader(template).TrimEnd('\r', '\n') : template;
        data.Append(canonSig);
        byte[] sig = key.SignData(Encoding.Latin1.GetBytes(data.ToString()), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return template + Convert.ToBase64String(sig);
    }
}

internal static class Canon
{
    public static string Header(string field, bool relaxed, bool appendCrlf = true)
    {
        var w = new ArrayBufferWriter<byte>();
        Span<byte> scratch = stackalloc byte[16];
        var sink = new HashSink(w, scratch);
        Canonicalizer.WriteHeader(Msg.Bytes(field), relaxed, appendCrlf, ref sink);
        sink.Flush();
        return Msg.Text(w.WrittenSpan);
    }

    public static string Body(string body, bool relaxed)
    {
        var w = new ArrayBufferWriter<byte>();
        Span<byte> scratch = stackalloc byte[16];
        var sink = new HashSink(w, scratch);
        Canonicalizer.WriteBody(Msg.Bytes(body), relaxed, ref sink);
        sink.Flush();
        return Msg.Text(w.WrittenSpan);
    }
}
