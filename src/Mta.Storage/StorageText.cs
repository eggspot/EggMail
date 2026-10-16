namespace Mta.Storage;

/// <summary>
/// Text that cannot be stored. PostgreSQL text columns refuse the NUL character (and UTF-8 cannot encode an unpaired surrogate), SQLite stores both:
/// without a rule, the same input would be a harmless miss on one backend and an exception on the other. The rule, for both: such text never matches a
/// stored value, and when it must be written (text a remote server controls, such as a reply or a certificate name) it is written with U+FFFD in place
/// of the characters that cannot be stored.
/// </summary>
public static class StorageText
{
    /// <summary>True when <paramref name="text"/> can be stored as it is: no NUL and no unpaired surrogate. Null is storable.</summary>
    public static bool IsStorable(string? text)
    {
        if (text is null)
        {
            return true;
        }

        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '\0')
            {
                return false;
            }

            if (char.IsHighSurrogate(c))
            {
                if (i + 1 >= text.Length || !char.IsLowSurrogate(text[i + 1])) { return false; }
                i++;
            }
            else if (char.IsLowSurrogate(c))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary><paramref name="text"/> with every NUL and unpaired surrogate replaced by U+FFFD (the same instance when there is nothing to replace).</summary>
    public static string? Clean(string? text)
    {
        if (IsStorable(text))
        {
            return text;
        }

        var chars = text!.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (c == '\0')
            {
                chars[i] = '�';
            }
            else if (char.IsHighSurrogate(c) && i + 1 < chars.Length && char.IsLowSurrogate(chars[i + 1]))
            {
                i++;
            }
            else if (char.IsSurrogate(c))
            {
                chars[i] = '�';
            }
        }

        return new string(chars);
    }
}
