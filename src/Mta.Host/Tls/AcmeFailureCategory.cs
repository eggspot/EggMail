using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Tls;

/// <summary>
/// What may be said about a failed order to anybody who can read the unauthenticated capabilities and <c>/readyz</c> warnings: a category, never the
/// error text (which can carry what the CA, the network or the file system said). The full text stays in the renewal state, the server log and the
/// admin view (<c>GET /api/v1/admin/certificates/acme</c>, the dashboard's ACME renewals).
/// </summary>
public static class AcmeFailureCategory
{
    /// <summary>The category of a recorded error as a phrase for the warning. The messages are the ones this code base records; anything else is "the order failed".</summary>
    public static string Describe(string? lastError)
    {
        string text = lastError ?? "";
        bool Has(string part) => text.Contains(part, StringComparison.OrdinalIgnoreCase);

        if (Has("ACME HTTP-01:") && (Has("already in use") || Has("not allowed to listen") || Has("cannot listen")))
        {
            return "the port for the HTTP-01 challenge could not be bound";
        }

        if (Has("wildcard"))
        {
            return "a wildcard name needs DNS-01";
        }

        if (Has("external account"))
        {
            return "the CA needs or refused external account binding";
        }

        if (Has("Cloudflare: "))
        {
            return "the DNS provider (Cloudflare) could not publish or remove the challenge record";
        }

        if (Has("Authorization for") && (Has("ended as") || Has("is still")))
        {
            return "the CA could not validate the challenge";
        }

        if (Has("The CA issued a certificate") || Has("The CA sent no certificate") || Has("certificate chain") || Has("no certificate for the key"))
        {
            return "the CA sent a certificate that does not match the order";
        }

        if (Has("could not be reached") || Has("did not answer in time"))
        {
            return "the CA could not be reached";
        }

        if (Has("answer this client cannot read") || Has("does not offer an endpoint"))
        {
            return "the CA's answer could not be understood";
        }

        if (Has("The order is still") || Has("The CA marked the order invalid"))
        {
            return "the CA did not finish the order";
        }

        if (Has("ACME server error") || Has("ACME error"))
        {
            return "the CA refused the request";
        }

        return "the order failed";
    }

    /// <summary>
    /// The certificates the renewal service will try again by itself: the configured one (while <c>Acme:Domains</c> is not empty) and every active ACME
    /// certificate. A failed row of any other name (a dashboard request for names that were never issued) is only a record: nobody retries it.
    /// </summary>
    public static HashSet<string> RetriedNames(AcmeSection acme, IEnumerable<CertificateRecord> certificates)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var certificate in certificates)
        {
            if (certificate.Active && certificate.Source == "acme")
            {
                names.Add(certificate.Name);
            }
        }

        if (acme.Domains.Count > 0)
        {
            names.Add(acme.CertificateName);
        }

        return names;
    }
}
