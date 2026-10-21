using System.Text;
using Mta.Host.Inbound;

namespace Mta.Host.Tests;

/// <summary>Characters that change how text is displayed without being visible never reach the page or a webhook receiver in a header value or an attachment name.</summary>
public class InboundContentSanitizeTests
{
    // Built from code points on purpose: a source file with the characters themselves in it would be unreadable (and a bidi character in source is an attack of its own).
    private static string Chars(params int[] codePoints) => string.Concat(codePoints.Select(c => char.ConvertFromUtf32(c)));

    public static TheoryData<int[], string> Invisible => new()
    {
        { [0x202E], "ab" },
        { [0x202A, 0x202B, 0x202C, 0x202D], "ab" },
        { [0x2066, 0x2067, 0x2068, 0x2069], "ab" },
        { [0x200B, 0x2060, 0xFEFF], "ab" },
        { [0xE0001, 0xE0068, 0xE0069, 0xE007F], "ab" },   // invisible tag characters (surrogate pairs) spelling hidden text
        { [0x200E, 0x200F, 0x061C], "ab" },
        { [0x2028, 0x2029], "ab" },
    };

    private static InboundMessageContent Read(string headersAndBody) => InboundContentReader.Read(Encoding.UTF8.GetBytes(headersAndBody), 1024);

    [Fact]
    public void A_right_to_left_override_in_an_attachment_name_is_removed_so_the_extension_is_not_disguised()
    {
        // filename*=UTF-8''invoice%E2%80%AEgpj.exe is "invoice" + U+202E + "gpj.exe": displayed as "invoiceexe.jpg".
        InboundMessageContent content = Read(
            "From: a@sender.test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b\r\n"
            + "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*=UTF-8''invoice%E2%80%AEgpj.exe\r\n\r\nx\r\n--b--\r\n");

        InboundAttachment attachment = Assert.Single(content.Attachments);
        Assert.Equal("invoicegpj.exe", attachment.FileName);
    }

    [Theory]
    [MemberData(nameof(Invisible))]
    public void Invisible_formatting_characters_are_removed_from_header_values(int[] invisible, string expected)
    {
        // Between "a" and "b", sent as UTF-8; the reader decodes the value for display.
        InboundMessageContent content = Read("From: a@sender.test\r\nX-Test: a" + Chars(invisible) + "b\r\nSubject: s\r\n\r\nbody\r\n");

        Assert.Equal(expected, content.Headers.Single(h => h.Name == "X-Test").Value);
    }

    [Fact]
    public void Ordinary_text_in_any_script_is_kept()
    {
        string value = "plain " + Chars(0x00FC, 0x4E2D, 0x05D0, 0x0627);   // u with diaeresis, a Han character, Hebrew alef, Arabic alef: letters, not formatting
        InboundMessageContent content = Read("From: a@sender.test\r\nX-Test: " + value + "\r\n\r\nbody\r\n");

        Assert.Equal(value, content.Headers.Single(h => h.Name == "X-Test").Value);
    }

    [Fact]
    public void Joiners_and_the_soft_hyphen_are_kept_because_scripts_and_emoji_need_them()
    {
        string value = Chars(0x0645, 0x06CC, 0x200C, 0x0634, 0x0648, 0x062F)   // Persian "mishavad" needs the ZWNJ
            + " " + Chars(0x0915, 0x094D, 0x200D, 0x0937)                        // Devanagari conjunct with ZWJ
            + " " + Chars(0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467)             // family emoji: ZWJ sequence
            + " hy" + Chars(0x00AD) + "phen";
        InboundMessageContent content = Read("From: a@sender.test\r\nX-Test: " + value + "\r\n\r\nbody\r\n");

        Assert.Equal(value, content.Headers.Single(h => h.Name == "X-Test").Value);
    }
}
