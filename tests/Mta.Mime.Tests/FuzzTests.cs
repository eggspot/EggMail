using System.Diagnostics;
using System.Text;

namespace Mta.Mime.Tests;

/// <summary>
/// Seeded, deterministic mutation fuzzing: valid messages are damaged in many ways and pushed through every parser.
/// Nothing may throw, hang or allocate without bound. A failure prints the seed, iteration and the input in base64
/// so it can be added to <see cref="NastyCorpus"/> as a regression test.
/// </summary>
public class FuzzTests
{
    private static readonly string[] Tokens =
    [
        "\r", "\n", "\r\n", "\0", "--", "boundary=", "=?", "?=", "=?utf-8?B?", "=?utf-8?Q?", "?Q?", "?B?", ":", ";", "\"", "(", ")", "<", ">",
        "=\r\n", "\t", " ", "\u00ff", "\u0080", "multipart/mixed", "multipart/alternative", "message/rfc822", "Content-Type:", "Content-Transfer-Encoding:",
        "base64", "quoted-printable", "Content-Disposition: attachment; filename=", "--B", "--B--", "\r\n--B\r\n", "\r\n\r\n", "name*0*=", "name*1=", "''",
        "@", ",", "Received: x\r\n", "From: x@y.example\r\n", "Subject: ", "charset=", "utf-7", "=3D", "=ZZ", "%41", "\\", "[", "]",
    ];

    private const string Alphabet = "=0123456789ABCDEFabcdef \t\r\n+/_-AZaz\u00e9";

    private static readonly byte[][] Seeds = BuildSeeds();

    private static byte[][] BuildSeeds()
    {
        var list = new List<byte[]>
        {
            T.Crlf(T.SimpleMessage),
            T.Crlf(T.Multipart("B", "Content-Type: text/plain\n\nfirst", "Content-Type: text/html\nContent-Transfer-Encoding: quoted-printable\n\n<b>caf=C3=A9</b>", "Content-Type: application/pdf; name=\"a.pdf\"\nContent-Disposition: attachment; filename=\"a.pdf\"\nContent-Transfer-Encoding: base64\n\nQUJDREVGRw==")),
            T.Crlf("From: =?utf-8?Q?J=C3=BCrgen?= <j@example.com>\nTo: \"Doe, John\" <john@example.com>, Team: a@example.org, b@example.org;\nSubject: =?utf-8?B?SGVsbG8=?=\nDate: Mon, 05 Oct 2026 14:03:09 +0200\nContent-Type: multipart/alternative; boundary=\"B\"\n\n--B\nContent-Type: text/plain; charset=utf-8\n\nplain\n--B\nContent-Type: multipart/related; boundary=R\n\n--R\nContent-Type: text/html\n\n<img src=cid:x>\n--R\nContent-Type: message/rfc822\n\nFrom: z@example.com\nSubject: inner\n\ninner\n--R--\n--B--\n"),
        };

        var b = new MessageBuilder(new MessageBuilderOptions { MessageIdDomain = "example.com" }) { From = Mailbox.Create("Alice É", "alice@example.com"), Subject = "Grüße 世界", TextBody = "text é", HtmlBody = "<p>html</p>" };
        b.To.Add(Mailbox.Create("Bob", "bob@example.net"));
        b.Attachments.Add(new BuilderAttachment("résumé.bin", "application/octet-stream", Enumerable.Range(0, 300).Select(i => (byte)i).ToArray()));
        list.Add(b.Build().Content);
        return list.ToArray();
    }

    private static byte[] Mutate(Random rng, byte[] source)
    {
        var data = new List<byte>(source);
        int rounds = rng.Next(1, 8);
        for (int r = 0; r < rounds && data.Count > 0; r++)
        {
            switch (rng.Next(9))
            {
                case 0: // flip bytes
                    for (int i = rng.Next(1, 6); i > 0; i--)
                    {
                        data[rng.Next(data.Count)] = (byte)rng.Next(256);
                    }

                    break;
                case 1: // delete a range
                    {
                        int start = rng.Next(data.Count);
                        data.RemoveRange(start, Math.Min(data.Count - start, rng.Next(1, 60)));
                        break;
                    }

                case 2: // duplicate a range
                    {
                        int start = rng.Next(data.Count);
                        int len = Math.Min(data.Count - start, rng.Next(1, 100));
                        data.InsertRange(rng.Next(data.Count), data.GetRange(start, len));
                        break;
                    }

                case 3: // insert a structural token
                case 4:
                    data.InsertRange(rng.Next(data.Count + 1), Encoding.Latin1.GetBytes(Tokens[rng.Next(Tokens.Length)]));
                    break;
                case 5: // truncate
                    {
                        int keep = rng.Next(data.Count);
                        data.RemoveRange(keep, data.Count - keep);
                        break;
                    }

                case 6: // splice with another seed
                    {
                        var other = Seeds[rng.Next(Seeds.Length)];
                        int from = rng.Next(other.Length);
                        data.InsertRange(rng.Next(data.Count + 1), other.AsSpan(from, Math.Min(other.Length - from, rng.Next(1, 300))).ToArray());
                        break;
                    }

                case 7: // amplify a range (repeat many times)
                    {
                        int start = rng.Next(data.Count);
                        var piece = data.GetRange(start, Math.Min(data.Count - start, rng.Next(1, 40)));
                        int times = rng.Next(2, 400);
                        var big = new List<byte>(piece.Count * times);
                        for (int t = 0; t < times; t++)
                        {
                            big.AddRange(piece);
                        }

                        data.InsertRange(rng.Next(data.Count + 1), big);
                        break;
                    }

                default: // replace one line ending style
                    {
                        string s = Encoding.Latin1.GetString(data.ToArray());
                        s = rng.Next(3) switch
                        {
                            0 => s.Replace("\r\n", "\n", StringComparison.Ordinal),
                            1 => s.Replace("\r\n", "\r", StringComparison.Ordinal),
                            _ => s.Replace("\r\n", "\r\r\n", StringComparison.Ordinal),
                        };
                        data = new List<byte>(Encoding.Latin1.GetBytes(s));
                        break;
                    }
            }
        }

        return data.ToArray();
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(20260101)]
    public void Mutated_messages_never_throw_hang_or_balloon(int seed)
    {
        HangGuard.Run(() => MutatedMessagesRun(seed), $"seed {seed}");
    }

    private static void MutatedMessagesRun(int seed)
    {
        var rng = new Random(seed);
        for (int iteration = 0; iteration < 1500; iteration++)
        {
            byte[] input = Mutate(rng, Seeds[rng.Next(Seeds.Length)]);
            long before = GC.GetAllocatedBytesForCurrentThread();
            try
            {
                Pipeline.RunEverything(input);
            }
            catch (Exception ex)
            {
                throw new Xunit.Sdk.XunitException($"seed {seed} iteration {iteration}: {ex.GetType().Name}: {ex.Message}\nbase64 input: {Convert.ToBase64String(input)}", ex);
            }

            long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
            Assert.True(allocated < (96L * input.Length) + (8L << 20), $"seed {seed} iteration {iteration} allocated {allocated / 1024} KiB for {input.Length} bytes; base64 input: {Convert.ToBase64String(input)}");
        }
    }

    [Fact]
    public void Random_bytes_never_throw()
    {
        var rng = new Random(99);
        for (int i = 0; i < 500; i++)
        {
            var data = new byte[rng.Next(0, 2000)];
            rng.NextBytes(data);
            Pipeline.RunEverything(data);
        }
    }

    [Fact]
    public void Every_prefix_of_a_complex_message_never_throws()
    {
        // Every prefix of a complex message (including cuts inside boundaries, encoded words and escapes).
        byte[] message = Seeds[2];
        for (int cut = 0; cut <= message.Length; cut++)
        {
            Pipeline.RunEverything(message.AsSpan(0, cut).ToArray());
        }
    }

    [Fact]
    public void Every_single_byte_deletion_of_a_complex_message_never_throws()
    {
        byte[] message = Seeds[1];
        for (int i = 0; i < message.Length; i++)
        {
            var copy = message.Take(i).Concat(message.Skip(i + 1)).ToArray();
            Pipeline.RunEverything(copy);
        }
    }

    [Fact]
    public void Decoders_never_throw_on_random_chunking()
    {
        var rng = new Random(5);
        foreach (var cte in new[] { ContentTransferEncoding.Base64, ContentTransferEncoding.QuotedPrintable, ContentTransferEncoding.Unknown })
        {
            for (int i = 0; i < 300; i++)
            {
                var data = new byte[rng.Next(0, 500)];
                for (int j = 0; j < data.Length; j++)
                {
                    data[j] = (byte)Alphabet[rng.Next(Alphabet.Length)];
                }

                var w = new System.Buffers.ArrayBufferWriter<byte>();
                var result = BodyDecoder.Decode(data, cte, w, rng.Next(0, 600));
                Assert.True(result.BytesWritten <= 600);
            }
        }
    }
}
