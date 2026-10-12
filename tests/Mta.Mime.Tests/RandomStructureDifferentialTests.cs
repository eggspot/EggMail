using System.Buffers;
using System.Text;
using Mk = MimeKit;

namespace Mta.Mime.Tests;

/// <summary>
/// Generates random but valid MIME trees (multipart nesting, random transfer encodings, random payloads), parses them
/// with MimeKit and Mta.Mime, and requires identical structure, parameters and decoded content.
/// </summary>
public class RandomStructureDifferentialTests
{
    private sealed class Node
    {
        public string Type = "text/plain";
        public string? Boundary;
        public List<Node> Children = [];
        public byte[] Payload = [];
        public ContentTransferEncoding Cte;
        public string? FileName;
        public string? ContentId;
        public string? Charset;
    }

    private static Node Generate(Random rng, int depth, ref int boundaryCounter)
    {
        if (depth < 3 && rng.Next(3) == 0)
        {
            var node = new Node
            {
                Type = "multipart/" + new[] { "mixed", "alternative", "related", "parallel" }[rng.Next(4)],
                Boundary = $"=_b{boundaryCounter++}_{rng.Next(1000)}",
            };
            int count = rng.Next(1, 5);
            for (int i = 0; i < count; i++)
            {
                node.Children.Add(Generate(rng, depth + 1, ref boundaryCounter));
            }

            return node;
        }

        var leaf = new Node
        {
            Type = new[] { "text/plain", "text/html", "application/octet-stream", "image/png", "application/pdf" }[rng.Next(5)],
        };
        bool text = leaf.Type.StartsWith("text/", StringComparison.Ordinal);
        if (text)
        {
            leaf.Charset = new[] { "utf-8", "iso-8859-1", "us-ascii" }[rng.Next(3)];
            leaf.Cte = new[] { ContentTransferEncoding.SevenBit, ContentTransferEncoding.QuotedPrintable, ContentTransferEncoding.Base64 }[rng.Next(3)];
            var sb = new StringBuilder();
            int lines = rng.Next(0, 8);
            for (int i = 0; i < lines; i++)
            {
                int len = rng.Next(0, 90);
                for (int j = 0; j < len; j++)
                {
                    sb.Append("abcdefghij klmnop,.;:!?()<>@#"[rng.Next(29)]);
                }

                sb.Append("\r\n");
            }

            // keep payload free of delimiter lookalikes (lines starting with "--" cannot occur: alphabet has no '-')
            leaf.Payload = Encoding.ASCII.GetBytes(sb.ToString());
            if (leaf.Charset != "us-ascii" && rng.Next(2) == 0)
            {
                // add non-ASCII text in the declared charset (always via a non-7bit encoding)
                string extra = "café crème";
                leaf.Payload = leaf.Payload.Concat(Encoding.GetEncoding(leaf.Charset).GetBytes(extra)).ToArray();
                if (leaf.Cte == ContentTransferEncoding.SevenBit)
                {
                    leaf.Cte = ContentTransferEncoding.QuotedPrintable;
                }
            }
        }
        else
        {
            leaf.Cte = ContentTransferEncoding.Base64;
            leaf.Payload = new byte[rng.Next(0, 400)];
            rng.NextBytes(leaf.Payload);
            if (rng.Next(2) == 0)
            {
                leaf.FileName = $"file{rng.Next(100)}.bin";
            }

            if (rng.Next(3) == 0)
            {
                leaf.ContentId = $"cid{rng.Next(1000)}@example.com";
            }
        }

        return leaf;
    }

    private static void Render(Node node, StringBuilder sb)
    {
        if (node.Boundary is not null)
        {
            sb.Append("Content-Type: ").Append(node.Type).Append("; boundary=\"").Append(node.Boundary).Append("\"\r\n\r\n");
            if (node.Children.Count > 0)
            {
                sb.Append("preamble\r\n");
            }

            foreach (var child in node.Children)
            {
                sb.Append("--").Append(node.Boundary).Append("\r\n");
                Render(child, sb);
                sb.Append("\r\n");
            }

            sb.Append("--").Append(node.Boundary).Append("--\r\n");
            return;
        }

        sb.Append("Content-Type: ").Append(node.Type);
        if (node.Charset is not null)
        {
            sb.Append("; charset=").Append(node.Charset);
        }

        if (node.FileName is not null)
        {
            sb.Append("; name=\"").Append(node.FileName).Append('"');
        }

        sb.Append("\r\n");
        if (node.Cte != ContentTransferEncoding.SevenBit)
        {
            sb.Append("Content-Transfer-Encoding: ").Append(node.Cte.ToToken()).Append("\r\n");
        }

        if (node.FileName is not null)
        {
            sb.Append("Content-Disposition: attachment; filename=\"").Append(node.FileName).Append("\"\r\n");
        }

        if (node.ContentId is not null)
        {
            sb.Append("Content-ID: <").Append(node.ContentId).Append(">\r\n");
        }

        sb.Append("\r\n");
        var writer = new ArrayBufferWriter<byte>();
        switch (node.Cte)
        {
            case ContentTransferEncoding.Base64:
                sb.Append(Convert.ToBase64String(node.Payload, Base64FormattingOptions.InsertLineBreaks));
                break;
            case ContentTransferEncoding.QuotedPrintable:
                TransferEncoder.WriteQuotedPrintable(node.Payload, writer);
                sb.Append(Encoding.ASCII.GetString(writer.WrittenSpan));
                break;
            default:
                sb.Append(Encoding.ASCII.GetString(node.Payload));
                break;
        }
    }

    private static byte[] ExpectedPayload(Node node)
    {
        // The decoded content of a text part is its payload, except that QP normalizes bare LF (none here) and drops trailing blanks.
        return node.Payload;
    }

    private static void Compare(Node node, MimePart ours, Mk.MimeEntity theirs, string path)
    {
        Assert.Equal(node.Type, ours.ContentType.MimeType);
        Assert.Equal(node.Type, theirs.ContentType.MimeType);
        Assert.Equal(node.Children.Count, ours.Children.Count);
        if (node.Boundary is not null)
        {
            var mp = Assert.IsAssignableFrom<Mk.Multipart>(theirs);
            Assert.Equal(node.Children.Count, mp.Count);
            Assert.Equal(node.Boundary, ours.ContentType.Boundary);
            for (int i = 0; i < node.Children.Count; i++)
            {
                Compare(node.Children[i], ours.Children[i], mp[i], path + "/" + i);
            }

            return;
        }

        var leaf = Assert.IsAssignableFrom<Mk.MimePart>(theirs);
        using var ms = new MemoryStream();
        leaf.Content?.DecodeTo(ms);
        byte[] expected = ExpectedPayload(node);
        byte[] fromOurs = ours.GetDecodedBytes();
        Assert.True(fromOurs.AsSpan().SequenceEqual(ms.ToArray()), $"{path}: decoded bytes differ between Mta.Mime and MimeKit");
        // QP drops trailing blanks per RFC 2045; the generated payload has none at line ends.
        Assert.True(fromOurs.AsSpan().SequenceEqual(expected), $"{path}: decoded bytes differ from the generated payload");
        Assert.Equal(node.FileName, ours.FileName);
        Assert.Equal(leaf.FileName, ours.FileName);
        Assert.Equal(node.ContentId, ours.ContentId);
        Assert.Equal(leaf.ContentId, ours.ContentId);
        if (node.Charset is not null)
        {
            Assert.Equal(node.Charset, ours.ContentType.Charset);
            string text = ours.GetText(1 << 20, out _);
            Assert.Equal(Encoding.GetEncoding(node.Charset).GetString(expected), text);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void Random_valid_trees_parse_identically(int seed)
    {
        Mta.Mime.MimeCharsets.RegisterCodePages();
        var rng = new Random(seed);
        for (int iteration = 0; iteration < 120; iteration++)
        {
            int counter = 0;
            var root = Generate(rng, 0, ref counter);
            var sb = new StringBuilder("From: a@example.com\r\nTo: b@example.net\r\nSubject: random\r\nMIME-Version: 1.0\r\n");
            Render(root, sb);
            byte[] raw = Encoding.ASCII.GetBytes(sb.ToString());

            var ours = MimeMessage.Parse(raw);
            Assert.True(ours.Anomalies == MimeAnomaly.None, $"seed {seed} iteration {iteration}: {ours.Anomalies}\n{sb}");
            using var stream = new MemoryStream(raw);
            var theirs = Mk.MimeMessage.Load(stream);
            Compare(root, ours.Root, theirs.Body!, $"seed {seed} iteration {iteration}");
        }
    }
}
