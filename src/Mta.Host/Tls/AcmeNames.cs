using System.Globalization;
using System.Net;

namespace Mta.Host.Tls;

/// <summary>The names of an ACME certificate: how they are written for the CA, and which of them only DNS-01 can prove.</summary>
public static class AcmeNames
{
    private static readonly IdnMapping Idn = new() { AllowUnassigned = false, UseStd3AsciiRules = true };

    public static bool IsWildcard(string name) => name.StartsWith("*.", StringComparison.Ordinal);

    /// <summary>
    /// The name as the CA wants it: trimmed, lower case, without a trailing dot, internationalized labels in their ASCII form (<c>bücher.example</c> is
    /// <c>xn--bcher-kva.example</c>; the certificate carries that form, as the CA orders it). Null with <paramref name="error"/> when it is not a usable
    /// public host name: an IP address, a single label, or characters no DNS name has. A wildcard (<c>*.example.com</c>) keeps its <c>*.</c>.
    /// </summary>
    public static string? TryNormalize(string name, out string? error)
    {
        error = null;
        string text = name.Trim().TrimEnd('.').ToLowerInvariant();
        bool wildcard = IsWildcard(text);
        string host = wildcard ? text[2..] : text;
        if (host.Length == 0 || host.Contains('*', StringComparison.Ordinal))
        {
            error = $"'{name}' is not a host name (a wildcard is only allowed as the first label: *.example.com).";
            return null;
        }

        if (IPAddress.TryParse(host, out _))
        {
            error = $"'{name}' is an IP address; ACME certificates here are issued for host names.";
            return null;
        }

        string ascii;
        try
        {
            ascii = Idn.GetAscii(host);
        }
        catch (ArgumentException ex)
        {
            error = $"'{name}' is not a valid host name ({ex.Message}).";
            return null;
        }

        if (!ascii.Contains('.', StringComparison.Ordinal))
        {
            error = $"'{name}' has a single label; a certificate from a public CA needs a fully qualified host name such as mail.example.com.";
            return null;
        }

        return wildcard ? "*." + ascii : ascii;
    }

    /// <summary>Every name normalized (see <see cref="TryNormalize"/>), duplicates removed, order kept; throws <see cref="AcmeException"/> for the first unusable name.</summary>
    public static List<string> NormalizeAll(IEnumerable<string> names)
    {
        var result = new List<string>();
        foreach (string name in names)
        {
            string normalized = TryNormalize(name, out string? error) ?? throw new AcmeException(error!);
            if (!result.Contains(normalized))
            {
                result.Add(normalized);
            }
        }

        return result;
    }
}
