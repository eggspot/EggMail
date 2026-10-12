using System.Buffers.Text;
using System.Text;

namespace Mta.Smtp.Protocol;

/// <summary>SASL helpers for AUTH PLAIN and AUTH LOGIN (RFC 4616 and the de-facto LOGIN mechanism) and xtext (RFC 3461).</summary>
public static class Sasl
{
    public const int MaxCredentialBytes = 1024;

    /// <summary>Strict base64 decode (no whitespace, proper padding). Returns false on any irregularity.</summary>
    public static bool TryDecodeBase64(string text, out byte[] data)
    {
        data = [];
        if (text.Length == 0)
        {
            return true;
        }

        if (text.Length > MaxCredentialBytes * 2 || text.Length % 4 != 0)
        {
            return false;
        }

        byte[] buf = new byte[Base64.GetMaxDecodedFromUtf8Length(text.Length)];
        if (!Convert.TryFromBase64String(text, buf, out int written))
        {
            return false;
        }

        data = buf.AsSpan(0, written).ToArray();
        return true;
    }

    /// <summary>Decodes a PLAIN response <c>[authzid] NUL authcid NUL passwd</c> (UTF-8).</summary>
    public static bool TryParsePlain(ReadOnlySpan<byte> response, out string authzid, out string authcid, out string password)
    {
        authzid = authcid = password = "";
        if (response.Length == 0 || response.Length > MaxCredentialBytes)
        {
            return false;
        }

        int first = response.IndexOf((byte)0);
        if (first < 0) { return false; }
        int second = response[(first + 1)..].IndexOf((byte)0);
        if (second < 0) { return false; }
        second += first + 1;
        var id = response[..first];
        var user = response[(first + 1)..second];
        var pass = response[(second + 1)..];
        if (user.Length == 0 || pass.Length == 0 || pass.IndexOf((byte)0) >= 0) { return false; }
        try
        {
            var strict = new UTF8Encoding(false, throwOnInvalidBytes: true);
            authzid = strict.GetString(id);
            authcid = strict.GetString(user);
            password = strict.GetString(pass);
        }
        catch (ArgumentException)
        {
            return false;
        }

        return true;
    }

    public static string EncodeBase64(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    /// <summary>xtext encoding (RFC 3461 §4): printable ASCII except '+' and '=', others as +HH.</summary>
    public static string EncodeXtext(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (byte b in Encoding.UTF8.GetBytes(value))
        {
            if (b is >= 33 and <= 126 && b != '+' && b != '=')
            {
                sb.Append((char)b);
            }
            else
            {
                sb.Append('+').Append(b.ToString("X2"));
            }
        }

        return sb.ToString();
    }

    public static bool TryDecodeXtext(string text, out string value)
    {
        value = "";
        var bytes = new List<byte>(text.Length);
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '+')
            {
                if (i + 2 >= text.Length) { return false; }
                if (!byte.TryParse(text.AsSpan(i + 1, 2), System.Globalization.NumberStyles.AllowHexSpecifier, null, out byte b)) { return false; }
                bytes.Add(b);
                i += 2;
            }
            else if (c is >= (char)33 and <= (char)126 && c != '=')
            {
                bytes.Add((byte)c);
            }
            else
            {
                return false;
            }
        }

        try
        {
            value = new UTF8Encoding(false, true).GetString(bytes.ToArray());
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
