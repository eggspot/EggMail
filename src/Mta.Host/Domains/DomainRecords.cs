using Mta.Dkim;

namespace Mta.Host.Domains;

/// <summary>Why a DNS record is on the domain's setup list (the API <c>purpose</c> field).</summary>
public enum DomainRecordPurpose
{
    Dkim,
    ReturnPath,
    Spf,
    Dmarc,
}

/// <summary>Result of looking one expected record up in DNS (the API <c>status</c> field).</summary>
public enum DomainRecordStatus
{
    /// <summary>Not looked up yet.</summary>
    Pending,
    Ok,
    Missing,

    /// <summary>A record exists at the name but does not carry the expected value.</summary>
    Invalid,
}

/// <summary>A DNS record the operator's customer has to publish. <see cref="Required"/> records decide verification; the others are advice only.</summary>
public sealed record ExpectedDomainRecord(string Type, string Host, string Value, int Ttl, DomainRecordPurpose Purpose, bool Required);

/// <summary>An expected record together with what DNS actually returned.</summary>
public sealed record DomainRecordCheck(ExpectedDomainRecord Expected, DomainRecordStatus Status, string? Found);

/// <summary>A DKIM key the domain must publish: its selector and the public key as base64 SubjectPublicKeyInfo.</summary>
public sealed record DomainDkimKey(string Selector, string PublicKeyBase64);

/// <summary>Options shared by the planner and the checker.</summary>
public sealed class DomainRecordOptions
{
    /// <summary>The operator's bounce domain; the per-domain return-path host is a CNAME to it. When null, no return-path record is required and bounces use the shared bounce domain.</summary>
    public string? BounceDomain { get; init; }

    /// <summary>Label prepended to the customer's domain for the return-path CNAME (<c>bounce.example.com</c>).</summary>
    public string ReturnPathLabel { get; init; } = "bounce";

    /// <summary>Suggested SPF value. Flat and soft-fail by default; the operator can add an <c>include:</c> for outbound IPs.</summary>
    public string? SpfInclude { get; init; }

    /// <summary>TTL suggested for every record.</summary>
    public int Ttl { get; init; } = 3600;
}

/// <summary>Builds the list of DNS records a domain has to publish (design §8). Pure function; no DNS access.</summary>
public static class DomainRecordPlanner
{
    public static string ReturnPathHost(string domain, DomainRecordOptions options) =>
        options.ReturnPathLabel + "." + Normalize(domain);

    public static IReadOnlyList<ExpectedDomainRecord> Plan(string domain, IEnumerable<DomainDkimKey> dkimKeys, DomainRecordOptions options)
    {
        ArgumentNullException.ThrowIfNull(dkimKeys);
        ArgumentNullException.ThrowIfNull(options);
        string name = Normalize(domain);
        var records = new List<ExpectedDomainRecord>();
        foreach (var key in dkimKeys)
        {
            records.Add(new ExpectedDomainRecord("TXT", DkimKeyTools.GetDnsName(name, key.Selector), DkimKeyTools.FormatDnsTxtValue(key.PublicKeyBase64), options.Ttl, DomainRecordPurpose.Dkim, true));
        }

        if (!string.IsNullOrWhiteSpace(options.BounceDomain))
        {
            records.Add(new ExpectedDomainRecord("CNAME", ReturnPathHost(name, options), Normalize(options.BounceDomain), options.Ttl, DomainRecordPurpose.ReturnPath, true));
        }

        string spf = string.IsNullOrWhiteSpace(options.SpfInclude) ? "v=spf1 ~all" : $"v=spf1 include:{Normalize(options.SpfInclude)} ~all";
        records.Add(new ExpectedDomainRecord("TXT", name, spf, options.Ttl, DomainRecordPurpose.Spf, false));
        records.Add(new ExpectedDomainRecord("TXT", "_dmarc." + name, $"v=DMARC1; p=none; rua=mailto:dmarc@{name}", options.Ttl, DomainRecordPurpose.Dmarc, false));
        return records;
    }

    internal static string Normalize(string name) => name.Trim().TrimEnd('.').ToLowerInvariant();
}
