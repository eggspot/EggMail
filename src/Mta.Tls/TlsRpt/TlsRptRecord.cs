using Mta.Dns;

namespace Mta.Tls.TlsRpt;

/// <summary>The scheme of a TLS-RPT reporting endpoint.</summary>
public enum TlsRptEndpointKind
{
    /// <summary>Reports are sent by e-mail (<c>mailto:</c>). Sending is the delivery layer's job.</summary>
    Mailto,

    /// <summary>Reports are POSTed over HTTPS.</summary>
    Https,
}

/// <summary>One <c>rua</c> destination of a TLS-RPT record.</summary>
/// <param name="Kind">The endpoint kind.</param>
/// <param name="Uri">The URI as published (for <c>mailto:</c> without any query part).</param>
/// <param name="MailtoAddress">For <see cref="TlsRptEndpointKind.Mailto"/>, the recipient address; otherwise <see langword="null"/>.</param>
public sealed record TlsRptEndpoint(TlsRptEndpointKind Kind, string Uri, string? MailtoAddress);

/// <summary>A parsed <c>_smtp._tls.&lt;domain&gt;</c> TXT record (RFC 8460 section 3).</summary>
/// <param name="Endpoints">The valid reporting destinations in published order (at least one).</param>
public sealed record TlsRptRecord(IReadOnlyList<TlsRptEndpoint> Endpoints);

/// <summary>Parser for TLS-RPT TXT records. Never throws on malformed input.</summary>
public static class TlsRptRecordParser
{
    /// <summary>The maximum number of endpoints kept from one record.</summary>
    public const int MaxEndpoints = 8;

    private const int MaxRecordLength = 4096;
    private const int MaxUriLength = 2048;

    /// <summary>
    /// Parses a record such as <c>v=TLSRPTv1; rua=mailto:a@example.com,https://reports.example.com/tlsrpt</c>.
    /// Unknown tags and endpoints with other schemes are ignored; the record is invalid without any valid endpoint.
    /// </summary>
    public static bool TryParse(string? text, out TlsRptRecord? record)
    {
        record = null;
        if (text is null || text.Length > MaxRecordLength)
        {
            return false;
        }

        bool first = true;
        List<TlsRptEndpoint>? endpoints = null;
        foreach (string rawField in text.Split(';'))
        {
            string field = rawField.Trim(' ', '\t');
            if (field.Length == 0)
            {
                continue;
            }

            int eq = field.IndexOf('=');
            if (eq <= 0)
            {
                return false;
            }

            string key = field[..eq].Trim(' ', '\t');
            string value = field[(eq + 1)..].Trim(' ', '\t');
            if (first)
            {
                if (!string.Equals(key, "v", StringComparison.OrdinalIgnoreCase) || value != "TLSRPTv1")
                {
                    return false;
                }

                first = false;
            }
            else if (string.Equals(key, "rua", StringComparison.OrdinalIgnoreCase))
            {
                if (endpoints is not null)
                {
                    return false; // duplicate rua
                }

                endpoints = [];
                foreach (string rawUri in value.Split(','))
                {
                    if (endpoints.Count < MaxEndpoints && TryParseEndpoint(rawUri.Trim(' ', '\t'), out var endpoint))
                    {
                        endpoints.Add(endpoint!);
                    }
                }
            }
        }

        if (first || endpoints is null || endpoints.Count == 0)
        {
            return false;
        }

        record = new TlsRptRecord(endpoints);
        return true;
    }

    /// <summary>
    /// Selects the TLS-RPT record from a TXT RRset: records not starting with <c>v=TLSRPTv1</c> are ignored; if there is
    /// not exactly one candidate (RFC 8460 section 3) there is no usable record.
    /// </summary>
    public static TlsRptRecord? Select(IEnumerable<TxtRecord> records)
    {
        TlsRptRecord? found = null;
        int candidates = 0;
        foreach (var r in records)
        {
            if (!r.Text.TrimStart(' ', '\t').StartsWith("v=TLSRPTv1", StringComparison.Ordinal))
            {
                continue;
            }

            if (++candidates > 1)
            {
                return null;
            }

            TryParse(r.Text, out found);
        }

        return candidates == 1 ? found : null;
    }

    /// <summary>Parses one reporting URI (<c>mailto:</c> or <c>https:</c>).</summary>
    public static bool TryParseEndpoint(string? uri, out TlsRptEndpoint? endpoint)
    {
        endpoint = null;
        if (string.IsNullOrEmpty(uri) || uri.Length > MaxUriLength)
        {
            return false;
        }

        if (uri.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
        {
            string address = uri[7..];
            int query = address.IndexOf('?');
            if (query >= 0)
            {
                address = address[..query];
            }

            if (!IsValidMailbox(address))
            {
                return false;
            }

            endpoint = new TlsRptEndpoint(TlsRptEndpointKind.Mailto, "mailto:" + address, address);
            return true;
        }

        if (uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            && Uri.TryCreate(uri, UriKind.Absolute, out Uri? parsed)
            && parsed.Scheme == Uri.UriSchemeHttps
            && string.IsNullOrEmpty(parsed.UserInfo)
            && string.IsNullOrEmpty(parsed.Fragment)
            && DnsNames.TryNormalizeHost(parsed.IdnHost, out string host)
            && host.Contains('.'))
        {
            endpoint = new TlsRptEndpoint(TlsRptEndpointKind.Https, parsed.AbsoluteUri, null);
            return true;
        }

        return false;
    }

    private static bool IsValidMailbox(string address)
    {
        if (address.Length is 0 or > 254)
        {
            return false;
        }

        int at = address.LastIndexOf('@');
        if (at <= 0 || at != address.IndexOf('@') || at > 64)
        {
            return false;
        }

        foreach (char c in address)
        {
            if (c <= ' ' || c == 0x7F || c is '<' or '>' or ',' or ';' or '"' or '\\')
            {
                return false;
            }
        }

        return DnsNames.TryNormalizeHost(address[(at + 1)..], out _);
    }
}

/// <summary>Looks up the TLS-RPT record of a recipient domain.</summary>
public sealed class TlsRptRecordLookup
{
    private readonly IDnsResolver _resolver;

    /// <summary>Creates a lookup over <paramref name="resolver"/>.</summary>
    public TlsRptRecordLookup(IDnsResolver resolver) => _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));

    /// <summary>Returns the domain's TLS-RPT record, or <see langword="null"/> if there is none (or DNS failed). Does not throw on DNS failures.</summary>
    public async ValueTask<TlsRptRecord?> LookupAsync(string domain, CancellationToken cancellationToken = default)
    {
        if (!DnsNames.TryNormalizeHost(domain, out string name))
        {
            return null;
        }

        try
        {
            DnsResponse response = await _resolver.QueryAsync("_smtp._tls." + name, DnsRecordType.TXT, cancellationToken).ConfigureAwait(false);
            return response.IsSuccess ? TlsRptRecordParser.Select(response.Get<TxtRecord>()) : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }
}
