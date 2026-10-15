using System.Net;
using System.Security.Cryptography;
using System.Text;
using Mta.Dkim;
using Mta.Dns;

namespace Mta.Host.Domains;

/// <summary>Why a DNS record is on the domain's setup list (the API <c>purpose</c> field).</summary>
public enum DomainRecordPurpose
{
    Dkim,
    ReturnPath,
    Spf,
    Dmarc,

    /// <summary>MX of the operator's bounce domain, pointing at this server: the receiving side of the return-path CNAME (bounces reach the bounce listener on port 25).</summary>
    BounceMx,

    /// <summary><c>_smtp._tls</c> TXT: where receivers send TLS-RPT reports (RFC 8460).</summary>
    TlsRpt,

    /// <summary><c>_mta-sts</c> TXT: announces the MTA-STS policy (RFC 8461) that EggMail serves itself.</summary>
    MtaSts,

    /// <summary>Name <c>mta-sts.&lt;domain&gt;</c>: must lead to this server, which serves the policy file over HTTPS.</summary>
    MtaStsHost,

    /// <summary>Reverse DNS of the sending IP: advice only, it is set at whoever owns the IP address, not in the domain's zone.</summary>
    Ptr,
}

/// <summary>Result of looking one expected record up in DNS (the API <c>status</c> field).</summary>
public enum DomainRecordStatus
{
    /// <summary>Not looked up yet.</summary>
    Pending,
    Ok,

    /// <summary>Nothing is published at the name (or no record of the expected kind).</summary>
    Missing,

    /// <summary>A record of the expected kind exists but is unusable: malformed, or several where only one may exist (a second SPF record breaks SPF).</summary>
    Invalid,

    /// <summary>A well-formed record exists but does not carry the expected value (another DKIM key, another CNAME target, an SPF record without our mechanism).</summary>
    Mismatch,
}

/// <summary>A DNS record the operator's customer has to publish. <see cref="Required"/> records decide verification; the others are advice only.</summary>
/// <param name="Note">One sentence saying what the record is for, shown next to it.</param>
public sealed record ExpectedDomainRecord(string Type, string Host, string Value, int Ttl, DomainRecordPurpose Purpose, bool Required, string? Note = null);

/// <summary>An expected record together with what DNS actually returned.</summary>
public sealed record DomainRecordCheck(ExpectedDomainRecord Expected, DomainRecordStatus Status, string? Found);

/// <summary>A DKIM key the domain must publish: its selector and the public key as base64 SubjectPublicKeyInfo.</summary>
public sealed record DomainDkimKey(string Selector, string PublicKeyBase64);

/// <summary>Whether and how EggMail serves the MTA-STS policy file of the sending domains (<c>Domains:MtaStsMode</c>).</summary>
public enum MtaStsServingMode
{
    /// <summary>No policy is served and no MTA-STS record is suggested.</summary>
    Off = 0,

    /// <summary>Senders report TLS problems but still deliver (the safe way to start).</summary>
    Testing,

    /// <summary>Senders must deliver over verified TLS to the listed hosts or not at all.</summary>
    Enforce,
}

/// <summary>Options shared by the planner, the checker and the MTA-STS policy server.</summary>
public sealed class DomainRecordOptions
{
    /// <summary>The operator's bounce domain; the per-domain return-path host is a CNAME to it. When null, no return-path record is required and bounces use the shared bounce domain.</summary>
    public string? BounceDomain { get; init; }

    /// <summary>Label prepended to the customer's domain for the return-path CNAME (<c>bounce.example.com</c>).</summary>
    public string ReturnPathLabel { get; init; } = "bounce";

    /// <summary>Suggested SPF <c>include:</c> host. With none, the SPF value authorizes <see cref="PublicSendingIp"/> or, failing that, the <see cref="ServerHostname"/>.</summary>
    public string? SpfInclude { get; init; }

    /// <summary>TTL suggested for every record.</summary>
    public int Ttl { get; init; } = 3600;

    /// <summary>
    /// This server's public host name (<c>Hostname</c>, the <c>EGGMAIL_HOSTNAME</c> alias): the target of the bounce MX, the MTA-STS <c>mx:</c> line, the
    /// name <c>mta-sts.&lt;domain&gt;</c> must point at, and the name whose reverse DNS is checked. Null when it is not a fully qualified name (the
    /// machine name default), in which case none of those records is suggested.
    /// </summary>
    public string? ServerHostname { get; init; }

    /// <summary>The address receivers see our connections come from (<c>Delivery:PublicSendingIp</c>): authorized in SPF and used for the reverse-DNS advice.</summary>
    public string? PublicSendingIp { get; init; }

    /// <summary>DMARC policy of the suggested record: <c>none</c> (monitor only, the default), <c>quarantine</c> or <c>reject</c>.</summary>
    public string DmarcPolicy { get; init; } = "none";

    /// <summary>Where DMARC aggregate reports go: an e-mail address, <c>{domain}</c> stands for the customer's domain. Null: <c>dmarc@{domain}</c>.</summary>
    public string? DmarcReportAddress { get; init; }

    /// <summary>Where TLS-RPT reports go: an e-mail address or an <c>https://</c> URL, <c>{domain}</c> stands for the customer's domain. Null: <c>tls-rpt@{domain}</c>.</summary>
    public string? TlsReportAddress { get; init; }

    /// <summary>Serve the MTA-STS policy file of every registered domain and suggest its records. Only right when this server receives mail for the domain (see docs/operations.md).</summary>
    public MtaStsServingMode MtaStsMode { get; init; }

    /// <summary>The <c>max_age</c> of the served policy.</summary>
    public TimeSpan MtaStsMaxAge { get; init; } = TimeSpan.FromDays(7);

    /// <summary>The <c>mx:</c> lines of the served policy. Empty: the <see cref="ServerHostname"/>.</summary>
    public IReadOnlyList<string> MtaStsMx { get; init; } = [];

    /// <summary>True when the MTA-STS policy is served and has at least one <c>mx:</c> line.</summary>
    public bool MtaStsEnabled => MtaStsMode != MtaStsServingMode.Off && EffectiveMtaStsMx.Count > 0;

    /// <summary>The <c>mx:</c> patterns of the policy.</summary>
    public IReadOnlyList<string> EffectiveMtaStsMx => MtaStsMx.Count > 0 ? MtaStsMx : ServerHostname is { } host ? [host] : [];

    /// <summary>A host name usable in DNS records: fully qualified (has a dot), not an IP address; lower-case without a trailing dot. Null otherwise.</summary>
    public static string? UsableHostname(string? hostname)
    {
        if (string.IsNullOrWhiteSpace(hostname))
        {
            return null;
        }

        string name = hostname.Trim().TrimEnd('.').ToLowerInvariant();
        return name.Contains('.') && !IPAddress.TryParse(name, out _) && !name.Any(char.IsWhiteSpace) ? name : null;
    }
}

/// <summary>The MTA-STS policy file (RFC 8461 section 3.2) EggMail serves for a sending domain, and the id that goes with it into the <c>_mta-sts</c> TXT record.</summary>
public static class MtaStsPolicyDocument
{
    public const string WellKnownPath = "/.well-known/mta-sts.txt";

    /// <summary>The policy file; lines end in CRLF.</summary>
    public static string Render(DomainRecordOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var text = new StringBuilder();
        text.Append("version: STSv1\r\n");
        text.Append("mode: ").Append(options.MtaStsMode == MtaStsServingMode.Enforce ? "enforce" : "testing").Append("\r\n");
        foreach (string mx in options.EffectiveMtaStsMx)
        {
            text.Append("mx: ").Append(mx).Append("\r\n");
        }

        text.Append("max_age: ").Append(Math.Max(1, (long)options.MtaStsMaxAge.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture)).Append("\r\n");
        return text.ToString();
    }

    /// <summary>The policy id of the TXT record: a hash of the policy text, so it changes exactly when the policy does (as RFC 8461 requires) and needs no stored counter.</summary>
    public static string PolicyId(DomainRecordOptions options) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Render(options))), 0, 8).ToLowerInvariant();

    /// <summary>The name that serves the policy: <c>mta-sts.&lt;domain&gt;</c>.</summary>
    public static string HostFor(string domain) => "mta-sts." + DomainRecordPlanner.Normalize(domain);

    public static string UrlFor(string domain) => "https://" + HostFor(domain) + WellKnownPath;
}

/// <summary>The words the API and the dashboard use for a record purpose.</summary>
public static class DomainRecordPurposes
{
    public static string ApiWord(DomainRecordPurpose purpose) => purpose switch
    {
        DomainRecordPurpose.Dkim => "dkim",
        DomainRecordPurpose.ReturnPath => "return_path",
        DomainRecordPurpose.Spf => "spf",
        DomainRecordPurpose.Dmarc => "dmarc",
        DomainRecordPurpose.BounceMx => "bounce_mx",
        DomainRecordPurpose.TlsRpt => "tls_rpt",
        DomainRecordPurpose.MtaSts => "mta_sts",
        DomainRecordPurpose.MtaStsHost => "mta_sts_host",
        _ => "ptr",
    };

    /// <summary>A short human label (zone file comments, the CLI).</summary>
    public static string Label(DomainRecordPurpose purpose) => purpose switch
    {
        DomainRecordPurpose.Dkim => "DKIM",
        DomainRecordPurpose.ReturnPath => "Return-path",
        DomainRecordPurpose.Spf => "SPF",
        DomainRecordPurpose.Dmarc => "DMARC",
        DomainRecordPurpose.BounceMx => "Bounce MX",
        DomainRecordPurpose.TlsRpt => "TLS-RPT",
        DomainRecordPurpose.MtaSts => "MTA-STS",
        DomainRecordPurpose.MtaStsHost => "MTA-STS host",
        _ => "Reverse DNS",
    };
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
            records.Add(new ExpectedDomainRecord("TXT", DkimKeyTools.GetDnsName(name, key.Selector), DkimKeyTools.FormatDnsTxtValue(key.PublicKeyBase64), options.Ttl, DomainRecordPurpose.Dkim, true,
                "Lets receivers verify that mail from this domain is signed by EggMail."));
        }

        string? bounceDomain = string.IsNullOrWhiteSpace(options.BounceDomain) ? null : Normalize(options.BounceDomain);
        if (bounceDomain is not null)
        {
            records.Add(new ExpectedDomainRecord("CNAME", ReturnPathHost(name, options), bounceDomain, options.Ttl, DomainRecordPurpose.ReturnPath, true,
                "Makes bounce messages for this domain reach EggMail."));
        }

        records.Add(new ExpectedDomainRecord("TXT", name, SpfValue(options), options.Ttl, DomainRecordPurpose.Spf, false,
            "Authorizes this server to send for the domain. Keep a single SPF record per domain: merge this into an existing one."));
        records.Add(new ExpectedDomainRecord("TXT", "_dmarc." + name, DmarcValue(name, options), options.Ttl, DomainRecordPurpose.Dmarc, false,
            "Tells receivers what to do with mail that fails authentication and where to send reports. The default only monitors (p=none)."));
        records.Add(new ExpectedDomainRecord("TXT", "_smtp._tls." + name, TlsRptValue(name, options), options.Ttl, DomainRecordPurpose.TlsRpt, false,
            "Asks receivers to send daily TLS reports (RFC 8460) to the address in rua."));

        if (options.MtaStsEnabled && options.ServerHostname is { } server)
        {
            records.Add(new ExpectedDomainRecord("TXT", "_mta-sts." + name, $"v=STSv1; id={MtaStsPolicyDocument.PolicyId(options)}", options.Ttl, DomainRecordPurpose.MtaSts, false,
                $"Announces the MTA-STS policy that EggMail serves at {MtaStsPolicyDocument.UrlFor(name)}. The id changes when the policy changes."));
            records.Add(new ExpectedDomainRecord("CNAME", MtaStsPolicyDocument.HostFor(name), server, options.Ttl, DomainRecordPurpose.MtaStsHost, false,
                $"Must lead to this server ({server}) so it can serve the policy over HTTPS; its certificate has to cover mta-sts.{name}."));
        }

        if (bounceDomain is not null && options.ServerHostname is { } mailHost)
        {
            records.Add(new ExpectedDomainRecord("MX", bounceDomain, "10 " + mailHost, options.Ttl, DomainRecordPurpose.BounceMx, false,
                "Published once by the operator for all domains: delivers bounces for the bounce domain to this server (port 25 reaches the bounce listener)."));
        }

        if (options.ServerHostname is { } ptrHost)
        {
            string? arpa = IPAddress.TryParse(options.PublicSendingIp, out IPAddress? ip) ? DnsName.ReverseArpaName(ip) : null;
            records.Add(new ExpectedDomainRecord("PTR", arpa ?? ptrHost, ptrHost, options.Ttl, DomainRecordPurpose.Ptr, false,
                "Advice: the reverse DNS of the sending IP should be this server's host name. It is set at whoever owns the IP address (your hosting provider), not in your zone."));
        }

        return records;
    }

    /// <summary>
    /// The suggested SPF record. It authorizes what the operator configured: an <c>include:</c> host, the sending IP, and otherwise the server's own host
    /// name (<c>a:</c>); with none of them the record is only <c>v=spf1 ~all</c>. (SPF is evaluated for the return-path domain, which is the operator's bounce
    /// domain, so DMARC passes through DKIM; this record still matters for the HELO name and for receivers that check the From domain.)
    /// </summary>
    public static string SpfValue(DomainRecordOptions options)
    {
        var mechanisms = new List<string> { "v=spf1" };
        if (!string.IsNullOrWhiteSpace(options.SpfInclude))
        {
            mechanisms.Add("include:" + Normalize(options.SpfInclude));
        }

        if (IPAddress.TryParse(options.PublicSendingIp, out IPAddress? ip))
        {
            mechanisms.Add((ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !ip.IsIPv4MappedToIPv6 ? "ip6:" : "ip4:") + (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip));
        }
        else if (string.IsNullOrWhiteSpace(options.SpfInclude) && options.ServerHostname is { } host)
        {
            mechanisms.Add("a:" + host);
        }

        mechanisms.Add("~all");
        return string.Join(' ', mechanisms);
    }

    public static string DmarcValue(string domain, DomainRecordOptions options)
    {
        string policy = options.DmarcPolicy.Trim().ToLowerInvariant();
        return $"v=DMARC1; p={policy}; rua=mailto:{ReportAddress(options.DmarcReportAddress, "dmarc@{domain}", domain)}";
    }

    public static string TlsRptValue(string domain, DomainRecordOptions options)
    {
        string address = ReportAddress(options.TlsReportAddress, "tls-rpt@{domain}", domain);
        return "v=TLSRPTv1; rua=" + (address.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || address.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) ? address : "mailto:" + address);
    }

    private static string ReportAddress(string? configured, string fallback, string domain) =>
        (string.IsNullOrWhiteSpace(configured) ? fallback : configured.Trim()).Replace("{domain}", domain, StringComparison.OrdinalIgnoreCase);

    internal static string Normalize(string name) => name.Trim().TrimEnd('.').ToLowerInvariant();
}

/// <summary>Renders planned records as zone-file text (RFC 1035 master file syntax) that can be pasted into a DNS provider's import or edited by hand.</summary>
public static class ZoneFile
{
    private const int MaxCharacterString = 255;

    /// <summary>
    /// The zone-file text for <paramref name="domain"/>: one comment line and one record per entry. A record that does not belong in the domain's zone is
    /// written as a comment: the reverse DNS (set where the IP address is managed) and the bounce MX when the bounce domain is not inside the domain
    /// (the operator publishes it once for all domains).
    /// </summary>
    public static string Render(string domain, IReadOnlyList<ExpectedDomainRecord> records)
    {
        ArgumentNullException.ThrowIfNull(records);
        var text = new StringBuilder();
        text.Append("; DNS records for ").Append(DomainRecordPlanner.Normalize(domain)).Append('\n');
        text.Append("; Required records decide whether the domain can send; recommended ones improve delivery and give you reports.\n");
        foreach (ExpectedDomainRecord record in records)
        {
            text.Append('\n');
            text.Append("; ").Append(DomainRecordPurposes.Label(record.Purpose)).Append(record.Required ? " (required)" : " (recommended)");
            if (record.Note is not null)
            {
                text.Append(": ").Append(record.Note);
            }

            text.Append('\n');
            text.Append(Line(record, domain)).Append('\n');
        }

        return text.ToString();
    }

    /// <summary>One record as a zone-file line, or a comment line for a record that cannot be created in the zone of <paramref name="zoneDomain"/>.</summary>
    public static string Line(ExpectedDomainRecord record, string zoneDomain)
    {
        ArgumentNullException.ThrowIfNull(record);
        string zone = DomainRecordPlanner.Normalize(zoneDomain);
        bool inZone = record.Host == zone || record.Host.EndsWith("." + zone, StringComparison.Ordinal);
        switch (record.Type)
        {
            case "TXT":
                return $"{Fqdn(record.Host)} {record.Ttl} IN TXT {QuotedStrings(record.Value)}";
            case "CNAME":
                return $"{Fqdn(record.Host)} {record.Ttl} IN CNAME {Fqdn(record.Value)}";
            case "MX" when !inZone:
                return $"; MX {record.Host} -> {record.Value} (published once by whoever runs EggMail, not in this zone)";
            case "MX":
            {
                int space = record.Value.IndexOf(' ', StringComparison.Ordinal);
                return $"{Fqdn(record.Host)} {record.Ttl} IN MX {record.Value[..space]} {Fqdn(record.Value[(space + 1)..])}";
            }

            default:
                return $"; {record.Type} {record.Host} -> {record.Value}";
        }
    }

    private static string Fqdn(string name) => name.EndsWith('.') ? name : name + ".";

    /// <summary>The value as quoted character-strings of at most 255 bytes each (a 2048-bit DKIM key does not fit in one).</summary>
    public static string QuotedStrings(string value)
    {
        var pieces = new List<string>();
        for (int i = 0; i < Math.Max(value.Length, 1); i += MaxCharacterString)
        {
            string piece = value.Substring(i, Math.Min(MaxCharacterString, value.Length - i));
            pieces.Add('"' + piece.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + '"');
        }

        return string.Join(' ', pieces);
    }
}
