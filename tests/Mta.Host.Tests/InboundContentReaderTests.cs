using System.Text;
using Mta.Host.Inbound;
using Mta.Mime;

namespace Mta.Host.Tests;

/// <summary>The inbound message reader: it must number attachments exactly as the history extractor does (the webhook payload and the download endpoint agree on the index), and survive hostile input.</summary>
public class InboundContentReaderTests
{
    private static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace("\n", "\r\n", StringComparison.Ordinal));

    public static TheoryData<string> Messages =>
    [
        // text and html in alternative, two attachments
        "From: a@x.test\nSubject: One\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=m\n\n--m\nContent-Type: multipart/alternative; boundary=a\n\n--a\nContent-Type: text/plain\n\nplain\n--a\nContent-Type: text/html\n\n<b>html</b>\n--a--\n--m\nContent-Type: application/pdf; name=\"a.pdf\"\nContent-Disposition: attachment; filename=\"a.pdf\"\nContent-Transfer-Encoding: base64\n\nUERG\n--m\nContent-Type: image/png\nContent-ID: <logo@x>\nContent-Transfer-Encoding: base64\n\niVBO\n--m--\n",
        // a second text part is an attachment, not a body
        "From: a@x.test\nSubject: Two\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=m\n\n--m\nContent-Type: text/plain\n\nfirst\n--m\nContent-Type: text/plain; name=note.txt\nContent-Disposition: attachment; filename=note.txt\n\nsecond\n--m\nContent-Type: text/plain\n\nthird\n--m--\n",
        // a text part marked as attachment never becomes the body
        "From: a@x.test\nSubject: Three\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=m\n\n--m\nContent-Type: text/plain\nContent-Disposition: attachment; filename=log.txt\n\nlogs\n--m\nContent-Type: text/html\n\n<p>hi</p>\n--m--\n",
        // a plain message with no MIME headers
        "From: a@x.test\nSubject: Plain\n\njust text\n",
        // an embedded message and a part without a type
        "From: a@x.test\nSubject: Four\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=m\n\n--m\nContent-Type: message/rfc822\n\nFrom: b@y.test\nSubject: inner\n\ninner body\n--m\n\nno headers at all\n--m--\n",
        // html only
        "From: a@x.test\nSubject: Five\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n<p>only html</p>\n",
        // deep nesting and an unterminated multipart
        "From: a@x.test\nSubject: Six\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=m\n\n--m\nContent-Type: multipart/mixed; boundary=n\n\n--n\nContent-Type: application/zip; name=z.zip\nContent-Disposition: attachment\n\nPK\n--n--\n--m\nContent-Type: text/plain\n\nbody\n",
    ];

    [Theory]
    [MemberData(nameof(Messages))]
    public void Attachments_are_numbered_and_described_like_the_history_extractor_does(string message)
    {
        byte[] raw = Bytes(message);
        ExtractedContent expected = MessageContentExtractor.Extract(raw, 1 << 20);
        InboundMessageContent actual = InboundContentReader.Read(raw, 1 << 20);

        Assert.Equal(expected.Attachments.Count, actual.Attachments.Count);
        for (int i = 0; i < actual.Attachments.Count; i++)
        {
            Assert.Equal(i, actual.Attachments[i].Index);
            Assert.Equal(expected.Attachments[i].FileName, actual.Attachments[i].FileName);
            Assert.Equal(expected.Attachments[i].ContentType, actual.Attachments[i].ContentType);
            Assert.Equal(expected.Attachments[i].Size, actual.Attachments[i].Size);
            Assert.Equal(expected.Attachments[i].ContentId, actual.Attachments[i].ContentId);
            Assert.Equal(expected.Attachments[i].IsInline ? "inline" : "attachment", actual.Attachments[i].Disposition);
        }

        Assert.Equal(expected.TextBody, actual.Text);
        Assert.Equal(expected.HtmlBody, actual.Html);
    }

    [Fact]
    public void An_attachment_part_gives_its_decoded_bytes()
    {
        byte[] raw = Bytes("From: a@x.test\nSubject: x\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=m\n\n--m\nContent-Type: text/plain\n\nbody\n--m\nContent-Type: application/octet-stream; name=d.bin\nContent-Disposition: attachment; filename=d.bin\nContent-Transfer-Encoding: base64\n\nSGVsbG8gd29ybGQ=\n--m--\n");

        InboundAttachment attachment = Assert.Single(InboundContentReader.Read(raw, 1000).Attachments);

        Assert.Equal("Hello world", Encoding.ASCII.GetString(attachment.Part.GetDecodedBytes()));
        Assert.Equal(11, attachment.Size);
    }

    [Fact]
    public void Headers_are_decoded_unfolded_and_cleaned_and_their_number_is_bounded()
    {
        var sb = new StringBuilder("Subject: =?UTF-8?B?w6RwZmVs?=\r\nX-Folded: one\r\n two\r\n\tthree\r\nFrom: a@x.test\r\n");
        for (int i = 0; i < InboundContentReader.MaxHeaders + 50; i++)
        {
            sb.Append("X-Extra-").Append(i).Append(": v\r\n");
        }

        sb.Append("\r\nbody\r\n");
        InboundMessageContent content = InboundContentReader.Read(Encoding.UTF8.GetBytes(sb.ToString()), 1000);

        Assert.Equal(InboundContentReader.MaxHeaders, content.Headers.Count);
        Assert.Equal(("Subject", "äpfel"), (content.Headers[0].Name, content.Headers[0].Value));
        Assert.Equal("one two three", content.Headers[1].Value);
    }

    [Fact]
    public void A_body_over_the_limit_is_cut_and_flagged()
    {
        byte[] raw = Bytes("From: a@x.test\nSubject: big\nContent-Type: text/plain; charset=utf-8\n\n" + new string('é', 5000) + "\n");

        InboundMessageContent content = InboundContentReader.Read(raw, 1000);

        Assert.True(content.Truncated);
        Assert.True(Encoding.UTF8.GetByteCount(content.Text!) <= 1000);
        Assert.StartsWith("éé", content.Text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("\r\n\r\n")]
    [InlineData("not a message at all")]
    [InlineData("Content-Type: multipart/mixed; boundary=\"\r\n\r\n--\r\n")]
    [InlineData("Content-Type: multipart/mixed; boundary=a\r\n\r\n--a\r\nContent-Type: multipart/mixed; boundary=a\r\n\r\n--a\r\n--a--\r\n")]
    public void Hostile_input_gives_fewer_fields_never_an_exception(string raw)
    {
        InboundMessageContent content = InboundContentReader.Read(Encoding.UTF8.GetBytes(raw), 1000);

        Assert.NotNull(content.Headers);
        Assert.NotNull(content.Attachments);
    }

    [Fact]
    public void A_nul_in_a_body_is_removed()
    {
        InboundMessageContent content = InboundContentReader.Read(Encoding.UTF8.GetBytes("Subject: x\r\nContent-Type: text/plain\r\n\r\nab\0cd\r\n"), 1000);

        Assert.DoesNotContain('\0', content.Text!);
    }

    [Theory]
    [InlineData("report.pdf", "report.pdf")]
    [InlineData("../../etc/passwd", "passwd")]
    [InlineData("C:\\Users\\bob\\evil.exe", "evil.exe")]
    [InlineData("a\"b;c\r\nSet-Cookie: x=1.html", "a_b_c__Set-Cookie_ x_1.html")]
    [InlineData("tab\tand\u0000nul.txt", "tab_and_nul.txt")]
    [InlineData(".hidden", "hidden")]
    [InlineData("dä\u00fcmlaut.txt", "d__mlaut.txt")]
    [InlineData("", "fallback")]
    [InlineData(null, "fallback")]
    [InlineData("   ", "fallback")]
    [InlineData("///", "fallback")]
    public void A_download_name_is_a_single_safe_ascii_token(string? name, string expected)
    {
        Assert.Equal(expected, InboundContentReader.SafeDownloadName(name, "fallback"));
    }

    [Fact]
    public void A_very_long_name_is_shortened()
    {
        Assert.Equal(100, InboundContentReader.SafeDownloadName(new string('a', 5000) + ".txt", "x").Length);
    }
}
