using System.Globalization;
using System.Net;

namespace Mta.Tls;

/// <summary>Strict host-name normalisation for names that come from hostile sources (DNS, policy files, URIs).</summary>
internal static class DnsNames
{
    private static readonly IdnMapping Idn = new() { AllowUnassigned = false, UseStd3AsciiRules = true };

    /// <summary>
    /// Normalises a host name: trims, removes one trailing dot, converts to A-labels, lower-cases and validates
    /// letters-digits-hyphen labels. Rejects IP literals and purely numeric last labels.
    /// </summary>
    public static bool TryNormalizeHost(string? input, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        string s = input.Trim();
        if (s.EndsWith('.'))
        {
            s = s[..^1];
        }

        if (s.Length == 0 || s.Length > 1024)
        {
            return false;
        }

        foreach (char c in s)
        {
            if (c > 0x7F)
            {
                try
                {
                    s = Idn.GetAscii(s);
                }
                catch (ArgumentException)
                {
                    return false;
                }

                break;
            }
        }

        s = s.ToLowerInvariant();
        if (s.Length > 253 || !IsValidAsciiHost(s))
        {
            return false;
        }

        if (IPAddress.TryParse(s, out _))
        {
            return false;
        }

        int lastDot = s.LastIndexOf('.');
        bool allDigits = true;
        foreach (char c in s.AsSpan(lastDot + 1))
        {
            if (c is < '0' or > '9')
            {
                allDigits = false;
                break;
            }
        }

        if (allDigits)
        {
            return false;
        }

        normalized = s;
        return true;
    }

    private static bool IsValidAsciiHost(string s)
    {
        int labelLength = 0;
        char previous = '.';
        foreach (char c in s)
        {
            if (c == '.')
            {
                if (labelLength == 0 || previous == '-')
                {
                    return false;
                }

                labelLength = 0;
            }
            else if (c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9'))
            {
                if (++labelLength > 63)
                {
                    return false;
                }
            }
            else if (c == '-')
            {
                if (labelLength == 0 || ++labelLength > 63)
                {
                    return false;
                }
            }
            else
            {
                return false;
            }

            previous = c;
        }

        return labelLength > 0 && previous != '-';
    }
}
