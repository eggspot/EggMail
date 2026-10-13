using System.Text;

namespace Mta.Mime.Tests;

/// <summary>Runs every public parser over one input and checks the invariants that must hold for any input.</summary>
internal static class Pipeline
{
    public static readonly string[] AddressHeaders = ["From", "To", "Cc", "Bcc", "Reply-To", "Sender"];

    public static void RunEverything(byte[] data, MimeLimits? limits = null)
    {
        limits ??= MimeLimits.Default;
        var memory = new ReadOnlyMemory<byte>(data);

        // ---- header list
        var headers = HeaderList.Parse(memory, limits);
        Assert.True(headers.Count <= limits.MaxHeaderCount);
        Assert.InRange(headers.BodyOffset, 0, data.Length);
        int previousEnd = 0;
        foreach (var h in headers)
        {
            Assert.True(h.Offset >= previousEnd);
            previousEnd = h.Offset + h.LengthWithLineEnding;
            Assert.True(previousEnd <= data.Length);
            _ = h.Name;
            _ = h.GetValue(4096);
            _ = h.GetDecodedValue(4096);
            _ = h.GetUnfoldedValueLength();
            _ = h.NameEquals("from");
        }

        foreach (string name in AddressHeaders)
        {
            if (headers.TryGetFirst(name, out var h))
            {
                var list = AddressList.Parse(h, limits);
                Assert.True(list.MailboxCount <= limits.MaxAddresses + limits.MaxAddresses); // groups may add members
                foreach (var m in list.Mailboxes)
                {
                    if (m.IsValid)
                    {
                        _ = m.Domain;
                        _ = m.ToString();
                    }
                }
            }
        }

        if (headers.TryGetFirst(HeaderId.Date, out var date))
        {
            MimeDate.TryParse(date.GetValue(256), out _);
        }

        // ---- MIME tree
        var message = MimeMessage.Parse(memory, limits);
        Assert.True(message.PartCount <= limits.MaxParts);
        int parts = 0;
        foreach (var part in message.EnumerateParts())
        {
            parts++;
            Assert.True(part.Depth <= limits.MaxDepth + 1);
            Assert.True(part.Raw.Length <= data.Length);
            _ = part.ContentType.ToHeaderValue();
            _ = part.Disposition;
            _ = part.FileName;
            _ = part.ContentId;
            _ = part.IsAttachment;
            string text = part.GetText(2000, out _);
            Assert.True(text.Length <= 2000 + 2);
            Assert.True(part.GetDecodedBytes(5000).Length <= 5000);
            Assert.True(part.GetDecodedLength() <= limits.MaxDecodedBytes);
        }

        Assert.Equal(message.PartCount, parts);

        // ---- extraction
        var content = MessageContentExtractor.Extract(memory, 256 * 1024, limits);
        Assert.True(content.Attachments.Count <= limits.MaxParts);
        Assert.True(content.Subject is null || content.Subject.Length <= MessageContentExtractor.MaxSubjectChars);
        foreach (string? s in new[] { content.Subject, content.TextBody, content.HtmlBody })
        {
            if (s is not null)
            {
                Assert.DoesNotContain('\0', s);
                Assert.True(Encoding.UTF8.GetByteCount(s) <= 256 * 1024);
            }
        }

        if (content.Subject is not null)
        {
            Assert.DoesNotContain(content.Subject, char.IsControl);
        }

        foreach (var a in content.Attachments)
        {
            if (a.FileName is not null)
            {
                Assert.DoesNotContain(a.FileName, char.IsControl);
            }

            Assert.True(a.Size >= 0);
        }

        // ---- validator
        var validation = MessageValidator.Validate(memory, limits);
        Assert.NotNull(validation.Issues);

        // ---- editor: the body is never touched
        var edited = new MessageHeaderEditor(memory)
            .Remove("Bcc")
            .Remove("Return-Path")
            .PrependReceived("from fuzz by test")
            .PrependReturnPath("a@example.com")
            .Append("X-Trace", "1")
            .ToArray();
        var editedHeaders = HeaderList.Parse(edited, limits);
        Assert.Equal(headers.HasSeparator ? headers.Body.Length : 0, editedHeaders.Body.Length);
        if (headers.HasSeparator)
        {
            Assert.True(editedHeaders.Body.Span.SequenceEqual(headers.Body.Span));
        }

        // ---- 8BITMIME downgrade: either refused with a reason, untouched, or a 7-bit body of bounded size
        var downgraded = new System.Buffers.ArrayBufferWriter<byte>();
        var downgrade = EightBitDowngrader.Downgrade(memory, downgraded, limits);
        switch (downgrade.Status)
        {
            case EightBitDowngradeStatus.NotNeeded:
                Assert.Equal(0, downgraded.WrittenCount);
                Assert.False(MessageInspector.HasEightBitBody(data));
                break;
            case EightBitDowngradeStatus.Impossible:
                Assert.False(string.IsNullOrEmpty(downgrade.Reason));
                break;
            default:
                Assert.False(MessageInspector.HasEightBitBody(downgraded.WrittenSpan));
                Assert.True(downgraded.WrittenCount <= (4L * data.Length) + 4096);
                break;
        }

        // ---- line endings
        var normalized = LineEndings.ToCrlf(data);
        Assert.False(MessageInspector.ContainsBareLf(normalized));
        Assert.False(MessageInspector.ContainsBareCr(normalized));
        Assert.True(normalized.Length <= data.Length * 2);
        _ = MessageInspector.Inspect(data);
    }
}
