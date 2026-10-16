namespace Mta.Storage;

/// <summary>
/// Text that cannot be stored as it is. PostgreSQL text columns refuse the NUL character and UTF-8 cannot encode an unpaired surrogate; SQLite stores NUL, and
/// turns an unpaired surrogate into U+FFFD when it binds the text. Without a rule, the same input would be a harmless miss on one backend and an exception on
/// another. The rules, the same for every backend:
/// <list type="bullet">
/// <item>In a <b>lookup or filter</b> such text matches nothing (<see cref="IsStorable"/>, then no row): it is never cleaned first, because a search for
/// <c>a&lt;NUL&gt;b</c> must not find the stored text <c>a&#xFFFD;b</c>.</item>
/// <item>A <b>write</b> of such text must not fail. What is stored differs: PostgreSQL stores <see cref="Clean"/> (U+FFFD in place of the characters it cannot
/// hold); SQLite and the in-memory store keep NUL as it is. Readers therefore compare <c>Clean(value)</c>. In practice only text a remote server controls can reach
/// a write (a reply, a host name, a certificate name); everything a client sends is refused earlier.</item>
/// </list>
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

    /// <summary>True when every text filter of the query can be stored (a query with one that cannot matches nothing).</summary>
    public static bool IsStorable(MessageQuery query) =>
        IsStorable(query.Recipient) && IsStorable(query.Sender) && IsStorable(query.SubjectContains) && IsStorable(query.Status) && IsStorable(query.Tag);

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
