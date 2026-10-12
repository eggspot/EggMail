namespace Mta.Auth.AuthenticationResults;

/// <summary>
/// Trust rules for Authentication-Results headers that arrive on a message (RFC 8601 section 5): the header is
/// only as trustworthy as the system that added it, so an MTA removes headers claiming its own identity (they were
/// forged or are left over from another hop) and downstream consumers only believe configured authserv-ids.
/// </summary>
public static class AuthenticationResultsPolicy
{
    /// <summary>
    /// Decides whether an incoming Authentication-Results header must be removed before this MTA adds its own.
    /// A header is removed when its authserv-id equals one of <paramref name="ownAuthservIds"/> (case-insensitive),
    /// or when it cannot be parsed (its origin cannot be established, so it cannot be trusted).
    /// </summary>
    /// <param name="fieldBody">The text after <c>Authentication-Results:</c>.</param>
    /// <param name="ownAuthservIds">The identifiers this system uses.</param>
    public static bool ShouldRemoveOnIngress(string? fieldBody, IReadOnlyCollection<string> ownAuthservIds)
    {
        ArgumentNullException.ThrowIfNull(ownAuthservIds);
        if (!AuthenticationResultsParser.TryReadAuthservId(fieldBody, out string? id))
        {
            return true;
        }

        return Contains(ownAuthservIds, id);
    }

    /// <summary>
    /// Keeps only the headers that parse and whose authserv-id is in <paramref name="trustedAuthservIds"/>;
    /// everything else is ignored.
    /// </summary>
    /// <param name="fieldBodies">The field bodies of all Authentication-Results headers on the message.</param>
    /// <param name="trustedAuthservIds">The identifiers whose results may be believed.</param>
    public static IReadOnlyList<AuthenticationResultsHeader> SelectTrusted(IEnumerable<string?> fieldBodies, IReadOnlyCollection<string> trustedAuthservIds)
    {
        ArgumentNullException.ThrowIfNull(fieldBodies);
        ArgumentNullException.ThrowIfNull(trustedAuthservIds);
        var trusted = new List<AuthenticationResultsHeader>();
        foreach (string? body in fieldBodies)
        {
            if (AuthenticationResultsParser.TryParse(body, out AuthenticationResultsHeader? header) && Contains(trustedAuthservIds, header.AuthservId))
            {
                trusted.Add(header);
            }
        }

        return trusted;
    }

    private static bool Contains(IReadOnlyCollection<string> ids, string id)
    {
        string normalized = id.Trim().TrimEnd('.');
        foreach (string candidate in ids)
        {
            if (string.Equals(candidate.Trim().TrimEnd('.'), normalized, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
