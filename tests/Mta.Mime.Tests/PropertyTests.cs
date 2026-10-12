using System.Buffers;
using System.Text;
using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;

namespace Mta.Mime.Tests;

/// <summary>FsCheck properties (fixed replay seed, so runs are deterministic).</summary>
public class PropertyTests
{
    private const string Seed = "20261012,1";

    private static string RemoveLoneSurrogates(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var rune in s.EnumerateRunes())
        {
            sb.Append(rune.ToString());
        }

        return sb.ToString();
    }

    [Property(MaxTest = 300, Replay = Seed)]
    public bool Base64_decoder_inverts_the_encoder_for_any_chunking(byte[] data, PositiveInt chunk)
    {
        var writer = new ArrayBufferWriter<byte>();
        TransferEncoder.WriteBase64(data, writer);
        byte[] encoded = writer.WrittenSpan.ToArray();

        var decoder = new Base64Decoder();
        var output = new List<byte>();
        int step = (chunk.Get % 97) + 1;
        var buffer = new byte[Base64Decoder.GetMaxDecodedLength(step)];
        for (int i = 0; i < encoded.Length; i += step)
        {
            int n = decoder.Decode(encoded.AsSpan(i, Math.Min(step, encoded.Length - i)), buffer);
            output.AddRange(buffer.AsSpan(0, n).ToArray());
        }

        var tail = new byte[4];
        output.AddRange(tail.AsSpan(0, decoder.Finish(tail)).ToArray());
        return output.SequenceEqual(data) && decoder.Anomalies == MimeAnomaly.None;
    }

    [Property(MaxTest = 300, Replay = Seed)]
    public bool Base64_encoder_output_is_valid_for_the_bcl(byte[] data)
    {
        var writer = new ArrayBufferWriter<byte>();
        TransferEncoder.WriteBase64(data, writer);
        string text = Encoding.ASCII.GetString(writer.WrittenSpan);
        return text.Split("\r\n").All(l => l.Length <= 76) && Convert.FromBase64String(text.Replace("\r\n", string.Empty)).SequenceEqual(data);
    }

    [Property(MaxTest = 300, Replay = Seed)]
    public bool Quoted_printable_round_trips_modulo_line_ending_normalization(byte[] data)
    {
        var writer = new ArrayBufferWriter<byte>();
        TransferEncoder.WriteQuotedPrintable(data, writer);
        byte[] encoded = writer.WrittenSpan.ToArray();
        if (encoded.Any(b => b >= 0x80 || (b < 32 && b != (byte)'\r' && b != (byte)'\n' && b != (byte)'\t')))
        {
            return false;
        }

        foreach (string line in Encoding.ASCII.GetString(encoded).Split("\r\n"))
        {
            if (line.Length > 76 || line.EndsWith(' ') || line.EndsWith('\t'))
            {
                return false;
            }
        }

        var back = new ArrayBufferWriter<byte>();
        BodyDecoder.Decode(encoded, ContentTransferEncoding.QuotedPrintable, back, long.MaxValue);
        // encoder turns every LF into CRLF (a CR before it is kept as part of that pair)
        var expected = new List<byte>();
        for (int i = 0; i < data.Length; i++)
        {
            if (data[i] == (byte)'\n' && (i == 0 || data[i - 1] != (byte)'\r'))
            {
                expected.Add((byte)'\r');
            }

            expected.Add(data[i]);
        }

        return back.WrittenSpan.SequenceEqual(expected.ToArray());
    }

    [Property(MaxTest = 500, Replay = Seed)]
    public bool Rfc2047_encode_then_decode_is_identity(string raw)
    {
        string text = RemoveLoneSurrogates(raw ?? string.Empty);
        string encoded = Rfc2047.Encode(text);
        bool asciiOnly = System.Text.Ascii.IsValid(encoded);
        bool wordsShort = encoded.Split(' ').Where(w => w.StartsWith("=?utf-8?", StringComparison.Ordinal)).All(w => w.Length <= 75);
        return asciiOnly && wordsShort && Rfc2047.Decode(encoded) == text;
    }

    [Property(MaxTest = 500, Replay = Seed)]
    public bool Rfc2047_decode_never_throws_and_never_grows_unboundedly(string raw)
    {
        string input = raw ?? string.Empty;
        string decoded = Rfc2047.Decode(input);
        return decoded.Length <= (input.Length * 3) + 8;
    }

    [Property(MaxTest = 500, Replay = Seed)]
    public bool Display_names_round_trip_through_format_and_parse(string raw, bool utf8)
    {
        string name = RemoveLoneSurrogates(raw ?? string.Empty);
        if (name.Any(char.IsControl) || name.Trim() != name || name.Length == 0)
        {
            return true; // not representable as a display name: rejected or trimmed by design
        }

        var mailbox = Mailbox.Create(name, "user@example.com");
        string formatted = mailbox.ToHeaderValue(utf8);
        var parsed = AddressList.Parse(formatted).Mailboxes.ToList();
        return parsed.Count == 1 && parsed[0].IsValid && parsed[0].DisplayName == name && parsed[0].Address.ToString() == "user@example.com";
    }

    [Property(MaxTest = 500, Replay = Seed)]
    public bool Address_parser_never_throws_and_respects_the_limit(string raw)
    {
        var list = AddressList.Parse(raw, new MimeLimits { MaxAddresses = 20 });
        return list.Count <= 40 && list.Mailboxes.Count() <= 40;
    }

    [Property(MaxTest = 500, Replay = Seed)]
    public bool Content_type_parser_never_throws(string raw)
    {
        var ct = ContentType.Parse(raw);
        return ct.MediaType.Length > 0 && ct.MediaSubtype.Length > 0 && ct.Parameters.Count <= MimeLimits.Default.MaxParameters;
    }

    [Property(MaxTest = 500, Replay = Seed)]
    public bool Date_parser_never_throws(string raw)
    {
        MimeDate.TryParse(raw, out _);
        return true;
    }

    [Property(MaxTest = 300, Replay = Seed)]
    public bool Date_format_parse_round_trips(DateTime time, sbyte offsetQuarterHours)
    {
        var offset = TimeSpan.FromMinutes(Math.Clamp(offsetQuarterHours, (sbyte)-56, (sbyte)56) * 15);
        var local = new DateTime(time.Year, time.Month, time.Day, time.Hour, time.Minute, time.Second, DateTimeKind.Unspecified);
        if (local.Year < 1900 || local.Year > 9000)
        {
            return true;
        }

        var value = new DateTimeOffset(local, offset);
        return MimeDate.TryParse(MimeDate.Format(value), out var back) && back == value && back.Offset == value.Offset;
    }

    [Property(MaxTest = 300, Replay = Seed)]
    public bool Folding_preserves_content_and_respects_the_line_limit(NonEmptyArray<NonEmptyString> words)
    {
        var cleaned = words.Get
            .Select(w => new string(w.Get.Where(c => c is > ' ' and < (char)127 && c != ':').ToArray()))
            .Where(w => w.Length > 0 && w.Length < 120)
            .Take(60)
            .ToList();
        if (cleaned.Count == 0)
        {
            return true;
        }

        string value = string.Join(' ', cleaned);
        string folded = HeaderFolder.Fold("X-Test", value);
        string[] lines = folded.Split("\r\n", StringSplitOptions.None);
        // the last element is empty (the text ends with CRLF); a line may exceed 78 columns only when it holds a single unbreakable token
        bool lengthsOk = lines.Take(lines.Length - 1).Select((l, i) => (l, i)).All(t => t.l.Length <= 78 || t.l.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length <= (t.i == 0 ? 2 : 1));
        bool continuation = lines.Skip(1).Take(Math.Max(0, lines.Length - 2)).All(l => l.StartsWith(' '));
        string unfolded = folded[..^2].Replace("\r\n", string.Empty, StringComparison.Ordinal);
        return lengthsOk && continuation && unfolded == "X-Test: " + value;
    }

    [Property(MaxTest = 200, Replay = Seed)]
    public bool Builder_output_parses_back_to_the_model(string subjectRaw, string textRaw, byte[] attachment)
    {
        string subject = new string(RemoveLoneSurrogates(subjectRaw ?? string.Empty).Where(c => !char.IsControl(c) && c is not ('\u2028' or '\u2029')).ToArray()).Trim();
        string text = RemoveLoneSurrogates(textRaw ?? string.Empty).Replace("\0", string.Empty, StringComparison.Ordinal);
        var b = new MessageBuilder(new MessageBuilderOptions { MessageIdDomain = "example.com" })
        {
            From = Mailbox.Create("Alice", "alice@example.com"),
            Subject = subject,
            TextBody = text,
        };
        b.To.Add(Mailbox.Create(null, "bob@example.net"));
        b.Attachments.Add(new BuilderAttachment("file.bin", "application/octet-stream", attachment));
        byte[] bytes = b.Build().Content;

        if (MessageInspector.ContainsBareLf(bytes) || MessageInspector.ContainsBareCr(bytes) || MessageInspector.Inspect(bytes).LongestBodyLine > 998 || !System.Text.Ascii.IsValid(bytes))
        {
            return false;
        }

        var content = MessageContentExtractor.Extract(bytes, int.MaxValue / 2);
        string expectedText = text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Replace("\n", "\r\n", StringComparison.Ordinal);
        string actualText = content.TextBody ?? string.Empty;
        bool textOk = actualText.TrimEnd('\r', '\n') == expectedText.TrimEnd('\r', '\n');
        var parsedAttachment = MimeMessage.Parse(bytes).EnumerateParts().First(p => p.FileName == "file.bin").GetDecodedBytes();
        return content.Subject == subject && textOk && parsedAttachment.SequenceEqual(attachment)
            && content.Attachments.Count == 1 && content.Attachments[0].Size == attachment.Length;
    }
}
