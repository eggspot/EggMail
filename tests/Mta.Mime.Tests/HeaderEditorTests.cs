using System.Buffers;
using System.Text;

namespace Mta.Mime.Tests;

public class HeaderEditorTests
{
    private static readonly byte[] Original = T.Crlf("From: a@example.com\nSubject: one\n  folded\nX-Dup: 1\nx-dup: 2\nTo: b@example.net\n\nbody line 1\nbody line 2\n");

    private static string Edit(Action<MessageHeaderEditor> edit, byte[]? message = null)
    {
        var editor = new MessageHeaderEditor(message ?? Original);
        edit(editor);
        return Encoding.UTF8.GetString(editor.ToArray());
    }

    [Fact]
    public void No_edits_returns_identical_bytes() => Assert.Equal(Original, new MessageHeaderEditor(Original).ToArray());

    [Fact]
    public void Prepend_puts_each_new_header_on_top()
    {
        string result = Edit(e => e.Prepend("Received", "from x by y").Prepend("Return-Path", "<a@example.com>"));
        Assert.StartsWith("Return-Path: <a@example.com>\r\nReceived: from x by y\r\nFrom: a@example.com\r\n", result);
        Assert.EndsWith("\r\n\r\nbody line 1\r\nbody line 2\r\n", result);
    }

    [Fact]
    public void Body_bytes_are_copied_verbatim_even_when_not_text()
    {
        var body = new byte[] { 0, 1, 2, 0xFF, (byte)'\r', (byte)'\n', (byte)'\n', 0x80, (byte)'\r' };
        var message = Encoding.ASCII.GetBytes("From: a@b.example\r\n\r\n").Concat(body).ToArray();
        byte[] edited = new MessageHeaderEditor(message).PrependReceived("x").ToArray();
        Assert.True(edited.AsSpan(edited.Length - body.Length).SequenceEqual(body));
    }

    [Fact]
    public void Folds_long_prepended_values()
    {
        string result = Edit(e => e.Prepend("Received", "from mail.example.com (mail.example.com [192.0.2.1]) by mx.example.net with ESMTPS id abcdef123456 for <user@example.net>; Mon, 05 Oct 2026 14:03:09 +0000"));
        string[] lines = result.Split("\r\n");
        Assert.All(lines.Take(4), l => Assert.True(l.Length <= 78, l));
        Assert.StartsWith(" ", lines[1]);
    }

    [Fact]
    public void Remove_deletes_all_matches_case_insensitively_and_keeps_others_byte_exact()
    {
        string result = Edit(e => e.Remove("X-DUP"));
        Assert.DoesNotContain("X-Dup", result, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Subject: one\r\n  folded\r\nTo: b@example.net\r\n\r\n", result);
    }

    [Fact]
    public void Remove_of_missing_header_changes_nothing() => Assert.Equal(Original, new MessageHeaderEditor(Original).Remove("Nope").ToArray());

    [Fact]
    public void Replace_keeps_position_and_drops_later_duplicates()
    {
        string result = Edit(e => e.Replace("x-dup", "only"));
        Assert.Contains("Subject: one\r\n  folded\r\nx-dup: only\r\nTo: b@example.net\r\n", result);
        Assert.Equal(1, Regex(result, "(?i)x-dup:"));
    }

    [Fact]
    public void Replace_of_missing_header_appends_it()
    {
        string result = Edit(e => e.Replace("X-New", "v"));
        Assert.Contains("To: b@example.net\r\nX-New: v\r\n\r\nbody", result);
    }

    [Fact]
    public void Append_goes_before_the_blank_line()
    {
        string result = Edit(e => e.Append("X-Last", "1"));
        Assert.Contains("To: b@example.net\r\nX-Last: 1\r\n\r\nbody line 1", result);
    }

    [Fact]
    public void Remove_then_replace_and_replace_then_remove_follow_the_last_call()
    {
        Assert.DoesNotContain("X-Dup", Edit(e => e.Replace("X-Dup", "v").Remove("X-Dup")), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("X-Dup: v", Edit(e => e.Remove("X-Dup").Replace("X-Dup", "v")));
    }

    [Fact]
    public void Edits_headers_without_a_body_separator()
    {
        var message = Encoding.ASCII.GetBytes("From: a@b.example\r\nSubject: s");
        string result = Encoding.ASCII.GetString(new MessageHeaderEditor(message).Prepend("X", "1").ToArray());
        Assert.Equal("X: 1\r\nFrom: a@b.example\r\nSubject: s\r\n\r\n", result);
    }

    [Fact]
    public void Edits_bare_lf_messages_without_normalizing_the_originals()
    {
        var message = Encoding.ASCII.GetBytes("From: a@b.example\nSubject: s\n\nbody\n");
        string result = Encoding.ASCII.GetString(new MessageHeaderEditor(message).Prepend("X", "1").ToArray());
        Assert.Equal("X: 1\r\nFrom: a@b.example\nSubject: s\n\nbody\n", result);
    }

    [Fact]
    public void Edits_empty_message()
    {
        string result = Encoding.ASCII.GetString(new MessageHeaderEditor(ReadOnlyMemory<byte>.Empty).Prepend("X", "1").ToArray());
        Assert.Equal("X: 1\r\n\r\n", result);
    }

    [Fact]
    public void Works_on_messages_with_more_headers_than_the_parse_limit()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 5000; i++)
        {
            sb.Append("X-Bcc: secret").Append(i).Append("\r\n");
        }

        sb.Append("Bcc: late@example.com\r\n\r\nbody");
        string result = Encoding.ASCII.GetString(new MessageHeaderEditor(Encoding.ASCII.GetBytes(sb.ToString())).Remove("Bcc").Remove("X-Bcc").ToArray());
        Assert.Equal("\r\nbody", result);
    }

    [Fact]
    public void Malformed_lines_are_preserved()
    {
        var message = Encoding.ASCII.GetBytes("junk\r\nFrom: a@b.example\r\n\r\nx");
        string result = Encoding.ASCII.GetString(new MessageHeaderEditor(message).Remove("From").ToArray());
        Assert.Equal("junk\r\n\r\nx", result);
    }

    [Fact]
    public void Writes_to_buffer_writer_and_reports_length()
    {
        var writer = new ArrayBufferWriter<byte>();
        long n = new MessageHeaderEditor(Original).Prepend("X", "1").WriteTo(writer);
        Assert.Equal(writer.WrittenCount, n);
        Assert.Equal(Original.Length + 6, n);
    }

    [Fact]
    public void Can_be_written_more_than_once()
    {
        var editor = new MessageHeaderEditor(Original).Replace("X-Dup", "v").Prepend("A", "1");
        Assert.Equal(editor.ToArray(), editor.ToArray());
    }

    [Fact]
    public void Prepend_raw_accepts_a_prefolded_dkim_signature()
    {
        var sig = Encoding.ASCII.GetBytes("DKIM-Signature: v=1; a=rsa-sha256; d=example.com;\r\n\ts=sel; h=from:to;\r\n\tb=AAAA\r\n");
        string result = Encoding.ASCII.GetString(new MessageHeaderEditor(Original).PrependRaw(sig).ToArray());
        Assert.StartsWith("DKIM-Signature: v=1;", result);
        Assert.Contains("\r\n\tb=AAAA\r\nFrom: a@example.com", result);
        Assert.Equal(MimeAnomaly.None, HeaderList.Parse(Encoding.ASCII.GetBytes(result)).Anomalies);
    }

    [Theory]
    [InlineData("X: a\r\nBcc: e@example.com\r\n")]
    [InlineData("X: a\n")]
    [InlineData("X: a")]
    [InlineData("X: a\r\n\r\n")]
    [InlineData("X: a\r\n\r\nbody\r\n")]
    [InlineData("X: a\rb\r\n")]
    [InlineData("X: a\0b\r\n")]
    [InlineData("no colon\r\n")]
    [InlineData(": empty name\r\n")]
    [InlineData("Bad Name: v\r\n")]
    [InlineData("")]
    public void Prepend_raw_rejects_anything_but_exactly_one_field(string raw)
    {
        var editor = new MessageHeaderEditor(Original);
        Assert.Throws<HeaderInjectionException>(() => editor.PrependRaw(Encoding.Latin1.GetBytes(raw)));
        Assert.Throws<HeaderInjectionException>(() => editor.AppendRaw(Encoding.Latin1.GetBytes(raw)));
    }

    [Theory]
    [InlineData("X-A", "v\r\nBcc: e@example.com")]
    [InlineData("X-A", "v\nBcc: e")]
    [InlineData("X-A", "v\rBcc: e")]
    [InlineData("X-A", "v\0")]
    [InlineData("X-A\r\nBcc", "v")]
    [InlineData("X A", "v")]
    [InlineData("X-A", "café")]
    public void Injection_is_rejected_by_every_method(string name, string value)
    {
        var editor = new MessageHeaderEditor(Original);
        Assert.Throws<HeaderInjectionException>(() => editor.Prepend(name, value));
        Assert.Throws<HeaderInjectionException>(() => editor.Append(name, value));
        Assert.Throws<HeaderInjectionException>(() => editor.Replace(name, value));
        if (name.Length > 0 && !name.Contains('\0'))
        {
            Assert.Equal(Original, editor.ToArray()); // nothing was recorded by the failed calls
        }
    }

    [Fact]
    public void Remove_rejects_invalid_names() => Assert.Throws<HeaderInjectionException>(() => new MessageHeaderEditor(Original).Remove("a\r\nb"));

    [Fact]
    public void Utf8_values_need_opt_in()
    {
        var editor = new MessageHeaderEditor(Original);
        Assert.Throws<HeaderInjectionException>(() => editor.Prepend("X-A", "café"));
        string result = Encoding.UTF8.GetString(editor.Prepend("X-A", "café", allowUtf8: true).ToArray());
        Assert.StartsWith("X-A: café\r\n", result);
        Assert.True(MessageInspector.HasUtf8Headers(Encoding.UTF8.GetBytes(result)));
    }

    [Fact]
    public void Trace_helpers()
    {
        string result = Edit(e => e.PrependAuthenticationResults("mx.example.net; dkim=pass").PrependReceived("from a by b").PrependReturnPath("a@example.com"));
        Assert.StartsWith("Return-Path: <a@example.com>\r\nReceived: from a by b\r\nAuthentication-Results: mx.example.net; dkim=pass\r\nFrom:", result);
    }

    private static int Regex(string text, string pattern) => System.Text.RegularExpressions.Regex.Matches(text, pattern).Count;
}
