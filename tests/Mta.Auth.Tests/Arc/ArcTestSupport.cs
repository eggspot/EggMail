using System.Security.Cryptography;
using System.Text;
using Mta.Auth.Arc;
using Mta.Core;
using Mta.Dkim;
using Mta.Dns;

namespace Mta.Auth.Tests.Arc;

internal sealed class FixedTestClock : IClock
{
    public FixedTestClock(DateTimeOffset now) => UtcNow = now;

    public DateTimeOffset UtcNow { get; }

    public long Timestamp => UtcNow.Ticks;
}

/// <summary>RSA keys are slow to generate; share them across tests, one per sealing domain.</summary>
internal static class ArcKeys
{
    private static readonly Dictionary<string, RSA> Keys = new(StringComparer.OrdinalIgnoreCase);

    public const string Selector = "arc1";

    public static RSA For(string domain)
    {
        lock (Keys)
        {
            if (!Keys.TryGetValue(domain, out var key))
            {
                key = RSA.Create(2048);
                _ = key.ExportSubjectPublicKeyInfo(); // force lazy generation while holding the lock
                Keys[domain] = key;
            }

            return key;
        }
    }

    /// <summary>A key that is never published in DNS.</summary>
    public static readonly RSA Stranger = RSA.Create(2048);

    public static RSA Small1024 { get; } = RSA.Create(1024);
}

internal static class ArcMsg
{
    public static readonly DateTimeOffset Now = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);

    public static readonly string[] Hops = ["a.example", "b.example", "c.example", "d.example", "e.example", "f.example"];

    public static byte[] Bytes(string s) => Encoding.Latin1.GetBytes(s);

    public static string Text(ReadOnlySpan<byte> b) => Encoding.Latin1.GetString(b);

    public static string Original(string body = "Hello,\r\n\r\nThis is the body.\r\n") =>
        "Received: from client (client.example.org [192.0.2.7])\r\n\tby mx.origin.example with ESMTP id abc123;\r\n\tMon, 12 Oct 2026 11:59:59 +0000\r\n"
        + "From: Alice <alice@origin.example>\r\n"
        + "To: Bob <bob@dest.example>\r\n"
        + "Subject: Test message\r\n"
        + "Date: Mon, 12 Oct 2026 12:00:00 +0000\r\n"
        + "Message-ID: <1234@origin.example>\r\n"
        + "MIME-Version: 1.0\r\n"
        + "Content-Type: text/plain; charset=utf-8\r\n"
        + "\r\n"
        + body;

    public static ArcSealer Sealer(string domain, bool oversign = false, IReadOnlyList<string>? headers = null, DateTimeOffset? now = null) =>
        new(new ArcSealerOptions
        {
            Domain = domain,
            Selector = ArcKeys.Selector,
            OversignHeaders = oversign,
            SignedHeaders = headers ?? ArcSealerOptions.DefaultSignedHeaders,
            Clock = new FixedTestClock(now ?? Now),
        }, ArcKeys.For(domain));

    /// <summary>A resolver that publishes the ARC key of each given domain.</summary>
    public static StaticDnsResolver Dns(params string[] domains)
    {
        var dns = new StaticDnsResolver();
        foreach (string d in domains) { dns.AddTxt(ArcKeys.Selector + "._domainkey." + d, DkimKeyTools.FormatDnsTxtValue(ArcKeys.For(d))); }
        return dns;
    }

    public static StaticDnsResolver DnsForAllHops() => Dns(Hops);

    public static ArcValidator Validator(IDnsResolver dns, ArcValidatorOptions? options = null) => new(dns, options);

    /// <summary>The Authentication-Results a hop would record.</summary>
    public static string ResultsFor(string hop, ArcChainResult incoming) =>
        "mx." + hop + "; spf=pass smtp.mailfrom=alice@origin.example; dkim=pass header.d=origin.example; " + ArcAuthenticationResults.Format(incoming);

    /// <summary>One forwarding hop: validate, seal, prepend. Optionally modifies the message before sealing (as a mailing list would).</summary>
    public static async Task<string> HopAsync(string message, string hop, StaticDnsResolver dns, Func<string, string>? modify = null, bool oversign = false)
    {
        var incoming = await Validator(dns).ValidateAsync(Bytes(message));
        string current = modify is null ? message : modify(message);
        using var sealer = Sealer(hop, oversign);
        var result = sealer.Seal(Bytes(current), ResultsFor(hop, incoming), incoming);
        Assert.True(result.IsSealed, result.NotSealedReason);
        return result.Headers + current;
    }

    public static async Task<string> ChainAsync(int hops, string? original = null, StaticDnsResolver? dns = null)
    {
        dns ??= DnsForAllHops();
        string message = original ?? Original();
        for (int i = 0; i < hops; i++) { message = await HopAsync(message, Hops[i], dns); }
        return message;
    }

    public static async Task<ArcChainResult> ValidateAsync(string message, StaticDnsResolver? dns = null, ArcValidatorOptions? options = null) =>
        await Validator(dns ?? DnsForAllHops(), options).ValidateAsync(Bytes(message));

    public static string ReplaceFirst(string text, string find, string replace)
    {
        int i = text.IndexOf(find, StringComparison.Ordinal);
        Assert.True(i >= 0, "'" + find + "' not found");
        return text.Substring(0, i) + replace + text.Substring(i + find.Length);
    }

    /// <summary>Splits a message into (header field lines, body); fields keep their continuation lines and CRLF.</summary>
    public static (List<string> Fields, string Body) Split(string message)
    {
        int blank = message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        string head = blank < 0 ? message : message.Substring(0, blank + 2);
        string body = blank < 0 ? string.Empty : message.Substring(blank + 2);
        var fields = new List<string>();
        foreach (string line in head.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            if ((line[0] == ' ' || line[0] == '\t') && fields.Count > 0) { fields[^1] += line + "\r\n"; }
            else { fields.Add(line + "\r\n"); }
        }

        return (fields, body);
    }

    public static string Join(List<string> fields, string body) => string.Concat(fields) + body;

    public static bool IsArc(string field) =>
        field.StartsWith("ARC-Seal:", StringComparison.OrdinalIgnoreCase)
        || field.StartsWith("ARC-Message-Signature:", StringComparison.OrdinalIgnoreCase)
        || field.StartsWith("ARC-Authentication-Results:", StringComparison.OrdinalIgnoreCase);

    public static int InstanceOf(string field)
    {
        int i = field.IndexOf("i=", StringComparison.Ordinal);
        int end = i + 2;
        while (char.IsAsciiDigit(field[end])) { end++; }
        return int.Parse(field.AsSpan(i + 2, end - i - 2));
    }
}
