using System.Text;

namespace Mta.Mime.Tests;

public class ContentExtractorTests
{
    private static ExtractedContent Extract(string text, int max = MessageContentExtractor.DefaultMaxStoredBodyBytes) =>
        MessageContentExtractor.Extract(T.Crlf(text), max);

    [Fact]
    public void Simple_text_message()
    {
        var c = Extract(T.SimpleMessage);
        Assert.Equal("Hello", c.Subject);
        Assert.Equal("Hello world\r\n", c.TextBody);
        Assert.Null(c.HtmlBody);
        Assert.Empty(c.Attachments);
        Assert.False(c.IsTruncated);
    }

    [Fact]
    public void Subject_is_decoded_and_sanitized()
    {
        Assert.Equal("Café世界", Extract("Subject: =?utf-8?Q?Caf=C3=A9?= =?utf-8?B?5LiW55WM?=\n\nx").Subject);
        Assert.Equal("a b", Extract("Subject: =?utf-8?Q?a=0D=0Ab?=\n\nx").Subject); // CR/LF from encoded words become spaces
        Assert.Equal("a b", Extract("Subject: =?utf-8?Q?a=00b?=\n\nx").Subject); // NUL too
        Assert.Null(Extract("From: a@b.example\n\nx").Subject);
        Assert.Equal(string.Empty, Extract("Subject:\n\nx").Subject);
    }

    [Fact]
    public void Subject_is_capped()
    {
        var c = Extract("Subject: " + new string('a', 5000) + "\n\nx");
        Assert.Equal(MessageContentExtractor.MaxSubjectChars, c.Subject!.Length);
        Assert.True(c.SubjectTruncated);
        Assert.True(c.IsTruncated);
    }

    [Fact]
    public void First_subject_wins_when_duplicated() =>
        Assert.Equal("one", Extract("Subject: one\nSubject: two\n\nx").Subject);

    [Fact]
    public void Alternative_with_text_and_html()
    {
        var c = Extract("Subject: s\nContent-Type: multipart/alternative; boundary=B\n\n--B\nContent-Type: text/plain; charset=utf-8\n\nplain é\n--B\nContent-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\n<p>html =C3=A9</p>\n--B--\n");
        Assert.Equal("plain é", c.TextBody);
        Assert.Equal("<p>html é</p>", c.HtmlBody);
        Assert.Empty(c.Attachments);
    }

    [Fact]
    public void Mixed_with_attachments_and_inline_images()
    {
        string pdf = Convert.ToBase64String(new byte[3000], Base64FormattingOptions.InsertLineBreaks);
        var c = Extract(
            "Content-Type: multipart/mixed; boundary=M\n\n--M\nContent-Type: multipart/related; boundary=R\n\n--R\nContent-Type: text/html\n\n<img src=\"cid:logo\">\n--R\nContent-Type: image/png\nContent-ID: <logo>\nContent-Disposition: inline; filename=logo.png\nContent-Transfer-Encoding: base64\n\nAAAA\n--R--\n--M\nContent-Type: application/pdf; name=\"report.pdf\"\nContent-Disposition: attachment; filename=\"report.pdf\"\nContent-Transfer-Encoding: base64\n\n" + pdf + "\n--M--\n");

        Assert.Equal("<img src=\"cid:logo\">", c.HtmlBody);
        Assert.Null(c.TextBody);
        Assert.Equal(2, c.Attachments.Count);
        Assert.Equal(new AttachmentInfo("logo.png", "image/png", 3, "logo", true), c.Attachments[0]);
        Assert.Equal(new AttachmentInfo("report.pdf", "application/pdf", 3000, null, false), c.Attachments[1]);
    }

    [Fact]
    public void Only_the_first_text_and_html_parts_are_the_bodies()
    {
        var c = Extract("Content-Type: multipart/mixed; boundary=M\n\n--M\nContent-Type: text/plain\n\nfirst\n--M\nContent-Type: text/plain\n\nsecond\n--M\nContent-Type: text/html\n\n<i>h1</i>\n--M\nContent-Type: text/html\n\n<i>h2</i>\n--M--\n");
        Assert.Equal("first", c.TextBody);
        Assert.Equal("<i>h1</i>", c.HtmlBody);
        Assert.Equal(2, c.Attachments.Count);
        Assert.All(c.Attachments, a => Assert.StartsWith("text/", a.ContentType));
    }

    [Fact]
    public void Text_part_marked_as_attachment_is_an_attachment()
    {
        var c = Extract("Content-Type: multipart/mixed; boundary=M\n\n--M\nContent-Type: text/plain\nContent-Disposition: attachment; filename=n.txt\n\nattached\n--M\nContent-Type: text/plain\n\nbody\n--M--\n");
        Assert.Equal("body", c.TextBody);
        var a = Assert.Single(c.Attachments);
        Assert.Equal("n.txt", a.FileName);
        Assert.Equal(8, a.Size);
    }

    [Fact]
    public void Embedded_message_is_an_attachment_not_descended()
    {
        var c = Extract("Content-Type: multipart/mixed; boundary=M\n\n--M\nContent-Type: text/plain\n\nbody\n--M\nContent-Type: message/rfc822\n\nSubject: inner\nContent-Type: text/plain\n\ninner text\n--M--\n");
        Assert.Equal("body", c.TextBody);
        var a = Assert.Single(c.Attachments);
        Assert.Equal("message/rfc822", a.ContentType);
    }

    [Fact]
    public void Single_non_text_message_is_one_attachment()
    {
        var c = Extract("Content-Type: application/pdf\nContent-Transfer-Encoding: base64\n\nAAAA\n");
        Assert.Null(c.TextBody);
        Assert.Equal(3, Assert.Single(c.Attachments).Size);
    }

    [Fact]
    public void Truncation_flag_and_utf8_byte_limit()
    {
        string body = string.Concat(Enumerable.Repeat("é世", 10_000));
        var c = Extract("Content-Type: text/plain; charset=utf-8\n\n" + body, max: 1000);

        Assert.True(c.TextTruncated);
        Assert.True(c.IsTruncated);
        Assert.True(Encoding.UTF8.GetByteCount(c.TextBody!) <= 1000);
        Assert.True(Encoding.UTF8.GetByteCount(c.TextBody!) > 990);
        Assert.DoesNotContain('�', c.TextBody!);
        Assert.StartsWith("é世", c.TextBody!, StringComparison.Ordinal);
    }

    [Fact]
    public void Latin1_body_that_grows_in_utf8_is_clamped()
    {
        var raw = Encoding.ASCII.GetBytes("Content-Type: text/plain; charset=iso-8859-1\r\n\r\n")
            .Concat(Enumerable.Repeat((byte)0xE9, 1000)).ToArray();
        var c = MessageContentExtractor.Extract(raw, 1000);
        Assert.True(Encoding.UTF8.GetByteCount(c.TextBody!) <= 1000);
        Assert.True(c.TextTruncated);
    }

    [Fact]
    public void Body_at_exactly_the_limit_is_not_truncated()
    {
        var c = Extract("Content-Type: text/plain\n\n" + new string('a', 100), max: 100);
        Assert.False(c.IsTruncated);
        Assert.Equal(100, c.TextBody!.Length);
    }

    [Fact]
    public void Zero_limit_stores_nothing()
    {
        var c = Extract("Content-Type: text/plain\n\nabc", max: 0);
        Assert.Equal(string.Empty, c.TextBody);
        Assert.True(c.TextTruncated);
        Assert.Throws<ArgumentOutOfRangeException>(() => MessageContentExtractor.Extract(T.Crlf("x"), -1));
    }

    [Fact]
    public void Nul_bytes_are_removed_from_stored_text()
    {
        var c = MessageContentExtractor.Extract(Encoding.ASCII.GetBytes("Content-Type: text/plain\r\n\r\na\0b"));
        Assert.Equal("ab", c.TextBody);
    }

    [Fact]
    public void File_names_have_control_characters_replaced()
    {
        var c = Extract("Content-Type: application/zip\nContent-Disposition: attachment; filename*=utf-8''evil%0D%0Aname%00.zip\n\nx");
        Assert.Equal("evil name .zip", Assert.Single(c.Attachments).FileName);
    }

    [Fact]
    public void Hostile_messages_never_throw()
    {
        foreach (var raw in new[]
        {
            Array.Empty<byte>(),
            new byte[] { 0 },
            Encoding.ASCII.GetBytes("Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n"),
            Encoding.ASCII.GetBytes("\r\n\r\n\r\n"),
            Encoding.ASCII.GetBytes("Content-Type: text/plain; charset=utf-7\r\nContent-Transfer-Encoding: base64\r\n\r\n+++===\r\n"),
        })
        {
            var c = MessageContentExtractor.Extract(raw);
            Assert.NotNull(c.Attachments);
        }
    }
}
