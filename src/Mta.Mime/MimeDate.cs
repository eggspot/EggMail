using System.Globalization;

namespace Mta.Mime;

/// <summary>RFC 5322 date-time formatting and tolerant parsing (including obsolete syntax and zone names).</summary>
public static class MimeDate
{
    private static readonly string[] Months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    private static readonly string[] Days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

    /// <summary>Maximum characters <see cref="TryFormat"/> writes.</summary>
    public const int MaxFormattedLength = 31;

    /// <summary>Formats as <c>Mon, 05 Oct 2026 14:03:09 +0200</c> (always English names, numeric zone).</summary>
    public static string Format(DateTimeOffset value)
    {
        Span<char> buffer = stackalloc char[MaxFormattedLength];
        TryFormat(value, buffer, out int written);
        return new string(buffer[..written]);
    }

    /// <summary>Formats into <paramref name="destination"/> without allocating.</summary>
    public static bool TryFormat(DateTimeOffset value, Span<char> destination, out int charsWritten)
    {
        charsWritten = 0;
        if (destination.Length < MaxFormattedLength)
        {
            return false;
        }

        var local = value.DateTime;
        int pos = 0;
        Days[(int)local.DayOfWeek].CopyTo(destination[pos..]);
        pos += 3;
        destination[pos++] = ',';
        destination[pos++] = ' ';
        Write2(destination, ref pos, local.Day);
        destination[pos++] = ' ';
        Months[local.Month - 1].CopyTo(destination[pos..]);
        pos += 3;
        destination[pos++] = ' ';
        local.Year.TryFormat(destination[pos..], out int w, "D4", CultureInfo.InvariantCulture);
        pos += w;
        destination[pos++] = ' ';
        Write2(destination, ref pos, local.Hour);
        destination[pos++] = ':';
        Write2(destination, ref pos, local.Minute);
        destination[pos++] = ':';
        Write2(destination, ref pos, local.Second);
        destination[pos++] = ' ';
        var offset = value.Offset;
        destination[pos++] = offset < TimeSpan.Zero ? '-' : '+';
        int total = (int)Math.Abs(offset.TotalMinutes);
        Write2(destination, ref pos, total / 60);
        Write2(destination, ref pos, total % 60);
        charsWritten = pos;
        return true;
    }

    private static void Write2(Span<char> destination, ref int pos, int value)
    {
        destination[pos++] = (char)('0' + (value / 10 % 10));
        destination[pos++] = (char)('0' + (value % 10));
    }

    /// <summary>
    /// Parses a Date header value. Accepts an optional day name, one or two digit days, month names, two- and three-digit
    /// years (RFC 5322 section 4.3), optional seconds, numeric zones, obsolete zone names (UT, GMT, EST ... PDT) and
    /// military zones (treated as UTC), and comments. A missing zone is read as UTC. Returns false for anything else.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<char> text, out DateTimeOffset value)
    {
        value = default;
        int pos = 0;
        FieldScanner.SkipCfws(text, ref pos);

        // Optional "Day," prefix.
        int save = pos;
        string word = ReadAlpha(text, ref pos);
        if (word.Length >= 3 && IndexOfDay(word) >= 0)
        {
            FieldScanner.SkipCfws(text, ref pos);
            if (pos < text.Length && text[pos] == ',')
            {
                pos++;
            }
        }
        else
        {
            pos = save;
        }

        FieldScanner.SkipCfws(text, ref pos);
        if (!ReadInt(text, ref pos, 1, 2, out int day))
        {
            return false;
        }

        FieldScanner.SkipCfws(text, ref pos);
        string monthText = ReadAlpha(text, ref pos);
        int month = IndexOfMonth(monthText);
        if (month < 0)
        {
            return false;
        }

        FieldScanner.SkipCfws(text, ref pos);
        int yearStart = pos;
        if (!ReadInt(text, ref pos, 2, 4, out int year))
        {
            return false;
        }

        int yearDigits = pos - yearStart;
        if (yearDigits == 2)
        {
            year += year < 50 ? 2000 : 1900;
        }
        else if (yearDigits == 3)
        {
            year += 1900;
        }

        FieldScanner.SkipCfws(text, ref pos);
        if (!ReadInt(text, ref pos, 1, 2, out int hour))
        {
            return false;
        }

        FieldScanner.SkipCfws(text, ref pos);
        if (pos >= text.Length || text[pos] != ':')
        {
            return false;
        }

        pos++;
        FieldScanner.SkipCfws(text, ref pos);
        if (!ReadInt(text, ref pos, 1, 2, out int minute))
        {
            return false;
        }

        int second = 0;
        FieldScanner.SkipCfws(text, ref pos);
        if (pos < text.Length && text[pos] == ':')
        {
            pos++;
            FieldScanner.SkipCfws(text, ref pos);
            if (!ReadInt(text, ref pos, 1, 2, out second))
            {
                return false;
            }
        }

        FieldScanner.SkipCfws(text, ref pos);
        TimeSpan offset = TimeSpan.Zero;
        if (pos < text.Length)
        {
            if (text[pos] is '+' or '-')
            {
                bool negative = text[pos] == '-';
                pos++;
                int zoneStart = pos;
                if (!ReadInt(text, ref pos, 2, 4, out int zone))
                {
                    return false;
                }

                int digits = pos - zoneStart;
                int zh = digits == 2 ? zone : zone / 100;
                int zm = digits == 2 ? 0 : zone % 100;

                if (zh > 99 || zm > 59)
                {
                    return false;
                }

                int totalMinutes = (zh * 60) + zm;
                if (totalMinutes > 14 * 60)
                {
                    return false;
                }

                offset = TimeSpan.FromMinutes(negative ? -totalMinutes : totalMinutes);
            }
            else if (!TryReadZoneName(text, ref pos, out offset))
            {
                return false;
            }
        }

        if (month < 1 || day < 1 || year < 1 || year > 9999 || hour > 23 || minute > 59 || second > 60)
        {
            return false;
        }

        if (day > DateTime.DaysInMonth(year, month))
        {
            return false;
        }

        if (second == 60)
        {
            second = 59; // leap second
        }

        try
        {
            value = new DateTimeOffset(year, month, day, hour, minute, second, offset);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }

    /// <summary>Parses a Date header value (string overload).</summary>
    public static bool TryParse(string? text, out DateTimeOffset value)
    {
        if (text is null)
        {
            value = default;
            return false;
        }

        return TryParse(text.AsSpan(), out value);
    }

    private static bool TryReadZoneName(ReadOnlySpan<char> text, ref int pos, out TimeSpan offset)
    {
        string name = ReadAlpha(text, ref pos);
        offset = TimeSpan.Zero;
        if (name.Length == 0)
        {
            return false;
        }

        int hours;
        switch (name.ToUpperInvariant())
        {
            case "UT" or "UTC" or "GMT" or "Z":
                hours = 0;
                break;
            case "EST":
                hours = -5;
                break;
            case "EDT":
                hours = -4;
                break;
            case "CST":
                hours = -6;
                break;
            case "CDT":
                hours = -5;
                break;
            case "MST":
                hours = -7;
                break;
            case "MDT":
                hours = -6;
                break;
            case "PST":
                hours = -8;
                break;
            case "PDT":
                hours = -7;
                break;
            default:
                // Military single letters and unknown names are "-0000" (RFC 5322 section 4.3): UTC with unknown local time.
                hours = 0;
                break;
        }

        offset = TimeSpan.FromHours(hours);
        return true;
    }

    private static string ReadAlpha(ReadOnlySpan<char> text, ref int pos)
    {
        int start = pos;
        while (pos < text.Length && char.IsAsciiLetter(text[pos]))
        {
            pos++;
        }

        return text[start..pos].ToString();
    }

    private static bool ReadInt(ReadOnlySpan<char> text, ref int pos, int minDigits, int maxDigits, out int value)
    {
        int start = pos;
        value = 0;
        while (pos < text.Length && pos - start < maxDigits && char.IsAsciiDigit(text[pos]))
        {
            value = (value * 10) + (text[pos] - '0');
            pos++;
        }

        return pos - start >= minDigits;
    }

    private static int IndexOfDay(string word)
    {
        for (int i = 0; i < Days.Length; i++)
        {
            if (word.StartsWith(Days[i], StringComparison.OrdinalIgnoreCase))
            {
                return i;
            }
        }

        return -1;
    }

    private static int IndexOfMonth(string word)
    {
        if (word.Length < 3)
        {
            return -1;
        }

        for (int i = 0; i < Months.Length; i++)
        {
            if (word.StartsWith(Months[i], StringComparison.OrdinalIgnoreCase))
            {
                return i + 1;
            }
        }

        return -1;
    }
}
