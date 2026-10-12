namespace Mta.Policy;

/// <summary>
/// Extracts a "try again in N seconds/minutes/hours" style hint from reply text. Allocation-free.
/// Recognized phrases include "Retry-After: 120", "retry after 5 minutes", "try again in 60 seconds", "try again after 10 min",
/// "come back in 2 hours" and "please wait 30 seconds". The result is the raw hint; callers bound it (see <see cref="RetryScheduleOptions"/>).
/// </summary>
public static class RetryAfterHint
{
    private static readonly (string Phrase, bool UnitOptional)[] Phrases =
    [
        ("retry-after", true),
        ("retry after", false),
        ("retry in", false),
        ("try again in", false),
        ("try again after", false),
        ("try again within", false),
        ("again in", false),
        ("come back in", false),
        ("come back after", false),
        ("please wait", false),
        ("wait for", false),
        ("wait", false),
    ];

    /// <summary>Tries to find a retry hint in <paramref name="text"/>.</summary>
    public static bool TryParse(ReadOnlySpan<char> text, out TimeSpan hint)
    {
        hint = default;
        if (text.IsEmpty)
        {
            return false;
        }

        foreach ((string phrase, bool unitOptional) in Phrases)
        {
            int searchFrom = 0;
            while (searchFrom < text.Length)
            {
                int idx = text[searchFrom..].IndexOf(phrase, StringComparison.OrdinalIgnoreCase);
                if (idx < 0)
                {
                    break;
                }

                int pos = searchFrom + idx + phrase.Length;
                if (TryReadAmount(text, pos, unitOptional, out hint))
                {
                    return true;
                }

                searchFrom = pos;
            }
        }

        return false;
    }

    private static bool TryReadAmount(ReadOnlySpan<char> text, int pos, bool unitOptional, out TimeSpan hint)
    {
        hint = default;

        // Skip a short filler such as ": ", " about ", " approximately ".
        int limit = Math.Min(text.Length, pos + 16);
        while (pos < limit && !char.IsAsciiDigit(text[pos]))
        {
            if (text[pos] is '.' or '\n' or '\r' or ',' or ';')
            {
                return false; // different sentence or clause: not a hint for this phrase
            }

            pos++;
        }

        if (pos >= limit || !char.IsAsciiDigit(text[pos]))
        {
            return false;
        }

        long value = 0;
        int digits = 0;
        while (pos < text.Length && char.IsAsciiDigit(text[pos]) && digits < 9)
        {
            value = (value * 10) + (text[pos] - '0');
            pos++;
            digits++;
        }

        while (pos < text.Length && text[pos] == ' ')
        {
            pos++;
        }

        int unitStart = pos;
        while (pos < text.Length && char.IsAsciiLetter(text[pos]) && pos - unitStart < 12)
        {
            pos++;
        }

        ReadOnlySpan<char> unit = text[unitStart..pos];
        double seconds;
        if (unit.IsEmpty)
        {
            if (!unitOptional)
            {
                return false;
            }

            seconds = value; // "Retry-After: 120" means seconds
        }
        else if (unit.Equals("s", StringComparison.OrdinalIgnoreCase) || unit.StartsWith("sec", StringComparison.OrdinalIgnoreCase))
        {
            seconds = value;
        }
        else if (unit.Equals("m", StringComparison.OrdinalIgnoreCase) || unit.StartsWith("min", StringComparison.OrdinalIgnoreCase))
        {
            seconds = value * 60d;
        }
        else if (unit.Equals("h", StringComparison.OrdinalIgnoreCase) || unit.StartsWith("hour", StringComparison.OrdinalIgnoreCase)
                 || unit.Equals("hr", StringComparison.OrdinalIgnoreCase) || unit.Equals("hrs", StringComparison.OrdinalIgnoreCase))
        {
            seconds = value * 3600d;
        }
        else if (unit.Equals("d", StringComparison.OrdinalIgnoreCase) || unit.StartsWith("day", StringComparison.OrdinalIgnoreCase))
        {
            seconds = value * 86400d;
        }
        else
        {
            return false;
        }

        hint = TimeSpan.FromSeconds(Math.Min(seconds, TimeSpan.FromDays(30).TotalSeconds));
        return true;
    }
}
