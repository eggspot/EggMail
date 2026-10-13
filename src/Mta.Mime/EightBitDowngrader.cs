using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Unicode;

namespace Mta.Mime;

/// <summary>What <see cref="EightBitDowngrader.Downgrade"/> did.</summary>
public enum EightBitDowngradeStatus
{
    /// <summary>The body is already 7-bit; nothing was written and the original bytes can be sent as they are.</summary>
    NotNeeded = 0,

    /// <summary>The body was re-encoded to 7-bit and written to the output.</summary>
    Downgraded,

    /// <summary>A faithful 7-bit form does not exist (see <see cref="EightBitDowngradeResult.Reason"/>); the output is undefined and must be discarded.</summary>
    Impossible,
}

/// <param name="Status">The outcome.</param>
/// <param name="Reason">For <see cref="EightBitDowngradeStatus.Impossible"/>: a short, human readable explanation suitable for a bounce message.</param>
public readonly record struct EightBitDowngradeResult(EightBitDowngradeStatus Status, string? Reason = null);

/// <summary>
/// Converts a message with an 8-bit body to a 7-bit one for a receiving server that does not offer 8BITMIME (RFC 6152 section 2 and
/// RFC 2045 section 6.4): 8-bit leaf entities are re-encoded (quoted-printable for mostly ASCII text, base64 otherwise) and their
/// <c>Content-Transfer-Encoding</c> field is replaced; multipart and embedded <c>message/rfc822</c> entities keep their structure and
/// are processed recursively, because RFC 2045 forbids encoding a composite entity as a whole. Every byte that is not part of a
/// re-encoded leaf (headers, delimiters, 7-bit parts) is copied unchanged, so the result is byte-exact where it can be.
/// <para>
/// Not everything can be downgraded, and the method then reports <see cref="EightBitDowngradeStatus.Impossible"/> instead of guessing:
/// 8-bit bytes in the header fields of a nested part or of an embedded message (they would need header downgrading, RFC 6857, which
/// is experimental), in a preamble, epilogue or delimiter line, a part that declares quoted-printable or base64 yet contains 8-bit
/// bytes, an unknown transfer encoding, <c>message/*</c> types other than <c>rfc822</c> and <c>global*</c>, and structure the parser
/// kept opaque (boundary problems, nesting beyond <see cref="MimeLimits.MaxDepth"/>). <c>message/global</c> (RFC 6532 section 3.7)
/// is encoded as a whole, as the RFC permits. The headers of the message itself may contain 8-bit bytes (SMTPUTF8); they are never changed
/// except for the transfer-encoding fields.
/// </para>
/// </summary>
public static class EightBitDowngrader
{
    /// <summary>
    /// Writes the 7-bit form of <paramref name="message"/> to <paramref name="output"/>. When the status is
    /// <see cref="EightBitDowngradeStatus.NotNeeded"/> nothing is written. When it is <see cref="EightBitDowngradeStatus.Impossible"/>
    /// the content of <paramref name="output"/> is undefined and the caller must discard it. Never throws for content problems.
    /// </summary>
    public static EightBitDowngradeResult Downgrade(ReadOnlyMemory<byte> message, IBufferWriter<byte> output, MimeLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(output);
        var span = message.Span;
        int bodyOffset = HeaderList.FindBodyOffset(span);
        if (Ascii.IsValid(span[bodyOffset..]))
        {
            return new EightBitDowngradeResult(EightBitDowngradeStatus.NotNeeded);
        }

        var parsed = MimeMessage.Parse(message, limits);
        var run = new Run(message, output);
        if (!run.EmitPart(parsed.Root, isRoot: true))
        {
            return new EightBitDowngradeResult(EightBitDowngradeStatus.Impossible, run.Failure);
        }

        return new EightBitDowngradeResult(EightBitDowngradeStatus.Downgraded);
    }

    private sealed class Run(ReadOnlyMemory<byte> root, IBufferWriter<byte> output)
    {
        public string? Failure { get; private set; }

        private bool Fail(string reason)
        {
            Failure ??= reason;
            return false;
        }

        private int OffsetOf(ReadOnlyMemory<byte> slice) =>
            (int)Unsafe.ByteOffset(ref MemoryMarshal.GetReference(root.Span), ref MemoryMarshal.GetReference(slice.Span));

        private static string Describe(MimePart part) => part.Depth == 0 ? "the message" : "a nested " + part.ContentType.MimeType + " part";

        public bool EmitPart(MimePart part, bool isRoot)
        {
            var raw = part.Raw.Span;
            if (!isRoot && Ascii.IsValid(raw))
            {
                Write(raw);
                return true;
            }

            var headers = part.Headers;
            if ((headers.Anomalies & (MimeAnomaly.TooManyHeaders | MimeAnomaly.HeaderBlockTooLarge)) != 0)
            {
                return Fail("the header block of " + Describe(part) + " is too large to be rewritten");
            }

            if (!isRoot && !Ascii.IsValid(raw[..headers.BodyOffset]))
            {
                return Fail("the header fields of " + Describe(part) + " contain 8-bit characters and cannot be converted to 7-bit");
            }

            var type = part.ContentType;
            bool composite = (type.IsMultipart && part.Children.Count > 0) || (part.IsEmbeddedMessage && type.MediaSubtype == "rfc822");
            if (composite)
            {
                return EmitComposite(part, isRoot);
            }

            return EmitLeaf(part, isRoot);
        }

        private bool EmitComposite(MimePart part, bool isRoot)
        {
            var raw = part.Raw.Span;
            var headers = part.Headers;
            if (part.IsEmbeddedMessage && !Ascii.IsValid(part.Children[0].Raw.Span[..part.Children[0].Headers.BodyOffset]))
            {
                return Fail("the embedded message in " + Describe(part) + " has 8-bit characters in its header fields and cannot be converted to 7-bit");
            }

            // A composite entity must be 7bit/8bit/binary only; what it contains is now 7-bit, so say so.
            string? cte = part.TransferEncoding is ContentTransferEncoding.EightBit or ContentTransferEncoding.Binary ? "7bit" : null;
            WriteHeaders(part, cte, isRoot, addContentType: false);

            int partStart = OffsetOf(part.Raw);
            int cursor = headers.BodyOffset;
            foreach (var child in part.Children)
            {
                int childStart = OffsetOf(child.Raw) - partStart;
                int childEnd = childStart + child.Raw.Length;
                if (childStart < cursor || childEnd > raw.Length)
                {
                    return Fail("the structure of " + Describe(part) + " could not be followed");
                }

                if (!CopyAscii(raw[cursor..childStart], part))
                {
                    return false;
                }

                if (!EmitPart(child, isRoot: false))
                {
                    return false;
                }

                cursor = childEnd;
            }

            return CopyAscii(raw[cursor..], part);
        }

        private bool CopyAscii(ReadOnlySpan<byte> gap, MimePart owner)
        {
            if (!Ascii.IsValid(gap))
            {
                return Fail("8-bit characters outside the body parts of " + Describe(owner) + " (preamble, epilogue or delimiter lines) cannot be converted to 7-bit");
            }

            Write(gap);
            return true;
        }

        private bool EmitLeaf(MimePart part, bool isRoot)
        {
            var type = part.ContentType;
            var body = part.Body.Span;
            string what = Describe(part);
            if (type.IsMultipart)
            {
                return Fail("the multipart structure of " + what + " could not be parsed, so its 8-bit content cannot be converted to 7-bit");
            }

            bool textual = type.IsText;
            if (type.MediaType == "message")
            {
                if (type.MediaSubtype != "global" && !type.MediaSubtype.StartsWith("global-", StringComparison.Ordinal))
                {
                    return Fail(what + " is 8-bit and a message/" + type.MediaSubtype + " entity cannot be re-encoded");
                }

                textual = true;
            }

            ContentTransferEncoding target;
            switch (part.TransferEncoding)
            {
                case ContentTransferEncoding.SevenBit:
                case ContentTransferEncoding.EightBit:
                    target = textual ? TransferEncoder.ChooseForText(body, allow8Bit: false) : ContentTransferEncoding.Base64;
                    break;
                case ContentTransferEncoding.Binary:
                    target = ContentTransferEncoding.Base64;
                    break;
                default:
                    return Fail(what + " declares a transfer encoding of its own but contains 8-bit bytes");
            }

            if (target == ContentTransferEncoding.SevenBit)
            {
                target = ContentTransferEncoding.QuotedPrintable;   // non-ASCII data never yields 7bit; defensive
            }

            bool addContentType = isRoot && !part.Headers.TryGetFirst(HeaderId.ContentType, out _) && Utf8.IsValid(body);
            WriteHeaders(part, target.ToToken(), isRoot, addContentType);
            if (target == ContentTransferEncoding.QuotedPrintable)
            {
                TransferEncoder.WriteQuotedPrintable(body, output);
            }
            else
            {
                TransferEncoder.WriteBase64(body, output);
                if (isRoot)
                {
                    Write("\r\n"u8);
                }
            }

            return true;
        }

        /// <summary>
        /// Copies the header block of <paramref name="part"/> with its Content-Transfer-Encoding replaced (added when missing, further
        /// duplicates dropped). At the message root MIME-Version is added when missing, since a transfer encoding means nothing without it.
        /// </summary>
        private void WriteHeaders(MimePart part, string? newCte, bool isRoot, bool addContentType)
        {
            var data = part.Raw.Span;
            var headers = part.Headers;
            int cursor = 0;
            bool cteWritten = false;
            bool hasMimeVersion = false;
            for (int i = 0; i < headers.Count; i++)
            {
                var h = headers[i];
                if (h.Id == HeaderId.MimeVersion)
                {
                    hasMimeVersion = true;
                }

                if (newCte is null || h.Id != HeaderId.ContentTransferEncoding)
                {
                    continue;
                }

                Write(data[cursor..h.Offset]);
                if (!cteWritten)
                {
                    WriteField("Content-Transfer-Encoding", newCte);
                    cteWritten = true;
                }

                cursor = h.Offset + h.LengthWithLineEnding;
            }

            int fieldsEnd = headers.Count == 0 ? 0 : headers[headers.Count - 1].Offset + headers[headers.Count - 1].LengthWithLineEnding;
            if (cursor < fieldsEnd)
            {
                Write(data[cursor..fieldsEnd]);
                cursor = fieldsEnd;
            }

            if (isRoot && !hasMimeVersion)
            {
                WriteField("MIME-Version", "1.0");
            }

            if (addContentType)
            {
                WriteField("Content-Type", "text/plain; charset=utf-8");
            }

            if (newCte is not null && !cteWritten)
            {
                WriteField("Content-Transfer-Encoding", newCte);
            }

            Write(data[cursor..headers.BodyOffset]);
        }

        private void WriteField(string name, string value)
        {
            int length = name.Length + 2 + value.Length + 2;
            var span = output.GetSpan(length);
            int n = Encoding.ASCII.GetBytes(name, span);
            span[n++] = (byte)':';
            span[n++] = (byte)' ';
            n += Encoding.ASCII.GetBytes(value, span[n..]);
            span[n++] = (byte)'\r';
            span[n++] = (byte)'\n';
            output.Advance(n);
        }

        private void Write(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty)
            {
                return;
            }

            var span = output.GetSpan(data.Length);
            data.CopyTo(span);
            output.Advance(data.Length);
        }
    }
}
