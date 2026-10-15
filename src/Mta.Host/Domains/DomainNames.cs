using System.Net;
using Mta.Core;

namespace Mta.Host.Domains;

/// <summary>Validation of the domain names a tenant registers (the API and <c>Domains:Bootstrap</c> use the same rule).</summary>
public static class DomainNames
{
    /// <summary>
    /// Lower-cases and validates a domain name and returns its A-label form: a host name with at least two labels, no address literal, no IP address, no
    /// underscore, at most 253 characters. A trailing dot is dropped.
    /// </summary>
    public static bool TryNormalize(string? input, out string name)
    {
        name = "";
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        string trimmed = input.Trim().TrimEnd('.');
        if (trimmed.Length > 253 || !EmailAddress.TryParse("postmaster@" + trimmed, allowUtf8: true, out EmailAddress parsed)
            || parsed.IsAddressLiteral || !parsed.Domain.Contains('.') || parsed.Domain.Contains('_') || IPAddress.TryParse(parsed.Domain, out _))
        {
            return false;
        }

        name = parsed.Domain;
        return true;
    }
}
