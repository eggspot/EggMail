using Mta.Auth.Domains;
using Mta.Dns;

namespace Mta.Auth.Dmarc;

/// <summary>The outcome of the external destination check for a report address (RFC 7489 section 7.1).</summary>
public enum DmarcReportAuthorization
{
    /// <summary>Reports may be sent to the address.</summary>
    Authorized = 0,

    /// <summary>The destination domain did not publish the authorization record; do not send.</summary>
    NotAuthorized,

    /// <summary>A DNS error prevented the check; retry later or skip this address.</summary>
    TempError,

    /// <summary>The URI is not a deliverable <c>mailto:</c> address.</summary>
    NotApplicable,
}

/// <summary>
/// Verifies that a third party agrees to receive reports for a domain: for a <c>rua</c>/<c>ruf</c> address whose domain
/// differs from the policy domain's organizational domain, the destination must publish a TXT record
/// <c>v=DMARC1</c> at <c>&lt;policy-domain&gt;._report._dmarc.&lt;destination-domain&gt;</c>.
/// </summary>
public sealed class DmarcReportAuthorizer
{
    private readonly IDnsResolver _resolver;
    private readonly PublicSuffixList _publicSuffixList;

    /// <summary>Creates an authorizer.</summary>
    /// <param name="resolver">The DNS resolver.</param>
    /// <param name="publicSuffixList">The suffix list; null uses the embedded list.</param>
    public DmarcReportAuthorizer(IDnsResolver resolver, PublicSuffixList? publicSuffixList = null)
    {
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _publicSuffixList = publicSuffixList ?? PublicSuffixList.Default;
    }

    /// <summary>The name of the authorization record for a destination (<c>example.com._report._dmarc.thirdparty.net</c>).</summary>
    /// <param name="policyDomain">The domain whose policy requested the report.</param>
    /// <param name="destinationDomain">The domain of the report address.</param>
    public static string AuthorizationRecordName(string policyDomain, string destinationDomain) =>
        policyDomain.Trim().TrimEnd('.').ToLowerInvariant() + "._report._dmarc." + destinationDomain.Trim().TrimEnd('.').ToLowerInvariant();

    /// <summary>Checks one report address.</summary>
    /// <param name="policyDomain">The domain the DMARC record was published for.</param>
    /// <param name="uri">The report address.</param>
    /// <param name="cancellationToken">Cancels the DNS lookup.</param>
    public async ValueTask<DmarcReportAuthorization> CheckAsync(string policyDomain, DmarcReportUri uri, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(policyDomain);
        ArgumentNullException.ThrowIfNull(uri);
        string? destination = uri.MailDomain;
        if (destination is null)
        {
            return DmarcReportAuthorization.NotApplicable;
        }

        if (_publicSuffixList.HaveSameOrganizationalDomain(policyDomain, destination))
        {
            return DmarcReportAuthorization.Authorized;
        }

        DnsResponse response;
        try
        {
            response = await _resolver.QueryAsync(AuthorizationRecordName(policyDomain, destination), DnsRecordType.TXT, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
#pragma warning disable CA1031 // Any resolver failure is a transient error.
        catch (Exception)
#pragma warning restore CA1031
        {
            return DmarcReportAuthorization.TempError;
        }

        if (response.Rcode == DnsRcode.NameError)
        {
            return DmarcReportAuthorization.NotAuthorized;
        }

        if (response.Rcode != DnsRcode.NoError)
        {
            return DmarcReportAuthorization.TempError;
        }

        foreach (TxtRecord txt in response.Get<TxtRecord>())
        {
            if (!DmarcRecord.HasVersionTag(txt.Text))
            {
                continue;
            }

            // The verification record may carry its own rua= that restricts the permitted addresses.
            string? overrideList = ReadTag(txt.Text, "rua");
            if (overrideList is null)
            {
                return DmarcReportAuthorization.Authorized;
            }

            foreach (string item in overrideList.Split(','))
            {
                if (DmarcReportUri.TryParse(item, out DmarcReportUri? allowed)
                    && string.Equals(allowed.MailAddress, uri.MailAddress, StringComparison.OrdinalIgnoreCase))
                {
                    return DmarcReportAuthorization.Authorized;
                }
            }
        }

        return DmarcReportAuthorization.NotAuthorized;
    }

    /// <summary>Returns the addresses of <paramref name="uris"/> that are authorized to receive reports for <paramref name="policyDomain"/>.</summary>
    /// <param name="policyDomain">The domain the DMARC record was published for.</param>
    /// <param name="uris">The candidate report addresses (<c>rua</c> or <c>ruf</c>).</param>
    /// <param name="cancellationToken">Cancels the DNS lookups.</param>
    public async ValueTask<IReadOnlyList<DmarcReportUri>> FilterAuthorizedAsync(string policyDomain, IEnumerable<DmarcReportUri> uris, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uris);
        var allowed = new List<DmarcReportUri>();
        foreach (DmarcReportUri uri in uris)
        {
            if (await CheckAsync(policyDomain, uri, cancellationToken).ConfigureAwait(false) == DmarcReportAuthorization.Authorized)
            {
                allowed.Add(uri);
            }
        }

        return allowed;
    }

    private static string? ReadTag(string record, string tag)
    {
        foreach (string part in record.Split(';'))
        {
            int eq = part.IndexOf('=');
            if (eq > 0 && part[..eq].Trim().Equals(tag, StringComparison.OrdinalIgnoreCase))
            {
                return part[(eq + 1)..].Trim();
            }
        }

        return null;
    }
}
