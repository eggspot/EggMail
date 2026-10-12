using System.Text;

namespace Mta.Mime.Tests;

/// <summary>Helpers shared by the tests.</summary>
internal static class T
{
    /// <summary>UTF-8 bytes of <paramref name="text"/> with every LF turned into CRLF (text must not contain CR).</summary>
    public static byte[] Crlf(string text) => Encoding.UTF8.GetBytes(text.Replace("\n", "\r\n", StringComparison.Ordinal));

    /// <summary>Latin-1 bytes (each char one byte) with LF turned into CRLF; for building 8-bit messages.</summary>
    public static byte[] Latin1Crlf(string text) => Encoding.Latin1.GetBytes(text.Replace("\n", "\r\n", StringComparison.Ordinal));

    public static byte[] Raw(string text) => Encoding.Latin1.GetBytes(text);

    public static string Str(ReadOnlyMemory<byte> bytes) => Encoding.Latin1.GetString(bytes.Span);

    public static string Utf8(ReadOnlyMemory<byte> bytes) => Encoding.UTF8.GetString(bytes.Span);

    public const string SimpleMessage =
        "From: Alice <alice@example.com>\n" +
        "To: bob@example.net\n" +
        "Subject: Hello\n" +
        "Date: Mon, 05 Oct 2026 14:03:09 +0200\n" +
        "Message-ID: <abc@example.com>\n" +
        "MIME-Version: 1.0\n" +
        "Content-Type: text/plain; charset=utf-8\n" +
        "\n" +
        "Hello world\n";

    public static string Multipart(string boundary, params string[] parts)
    {
        var sb = new StringBuilder();
        sb.Append("From: a@example.com\nTo: b@example.net\nSubject: multipart\nMIME-Version: 1.0\n");
        sb.Append("Content-Type: multipart/mixed; boundary=\"").Append(boundary).Append("\"\n\npreamble\n");
        foreach (string p in parts)
        {
            sb.Append("--").Append(boundary).Append('\n').Append(p).Append('\n');
        }

        sb.Append("--").Append(boundary).Append("--\nepilogue\n");
        return sb.ToString();
    }
}
