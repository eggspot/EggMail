using System.Text;

namespace Mta.Mime.Tests;

/// <summary>
/// Hand-written hostile and malformed messages. Every one must be processed by every public parser within bounded time
/// and memory, without any exception, and respect the configured limits (see <see cref="NastyCorpusTests"/>).
/// </summary>
internal static class NastyCorpus
{
    public static IEnumerable<(string Name, byte[] Data)> All()
    {
        var items = new List<(string, byte[])>();
        void Add(string name, string text) => items.Add((name, Encoding.Latin1.GetBytes(text)));
        void AddBytes(string name, byte[] data) => items.Add((name, data));
        string Hdr(string extra) => "From: a@example.com\r\nTo: b@example.net\r\nSubject: nasty\r\n" + extra;
        string Mp(string boundary, string body) => Hdr($"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n") + body;

        // ---- structure of the header block
        Add("01-empty", string.Empty);
        Add("02-only-crlf", "\r\n");
        Add("03-only-blank-lines", "\r\n\r\n\r\n\r\n");
        Add("04-headers-without-separator", "From: a@example.com\r\nSubject: cut off");
        Add("05-ten-thousand-header-lines", string.Concat(Enumerable.Range(0, 10_000).Select(i => $"X-H{i}: v{i}\r\n")) + "\r\nbody");
        Add("06-one-hundred-thousand-tiny-headers", string.Concat(Enumerable.Repeat("a:b\r\n", 100_000)) + "\r\nbody");
        Add("07-megabyte-header-line", "Subject: " + new string('a', 1 << 20) + "\r\n\r\nbody");
        Add("08-header-block-without-end-5mb", string.Concat(Enumerable.Repeat("X-Pad: " + new string('p', 1000) + "\r\n", 5000)));
        Add("09-hundred-thousand-continuation-lines", "Subject: x\r\n" + string.Concat(Enumerable.Repeat(" y\r\n", 100_000)) + "\r\nbody");
        Add("10-whitespace-only-continuations", "Subject: x\r\n \r\n \t \r\n\t\r\nTo: a@example.com\r\n\r\nbody");
        Add("11-mbox-from-line", "From bob@example.com Mon Oct  5 14:03:09 2026\r\nFrom: a@example.com\r\n\r\nbody");
        Add("12-header-without-name", ": value\r\n:\r\n::\r\nFrom: a@example.com\r\n\r\nbody");
        Add("13-space-in-header-name", "From : a@example.com\r\nSub ject: x\r\nTo\t: b@example.net\r\n\r\nbody");
        Add("14-truncated-mid-name", "From: a@example.com\r\nSubj");
        Add("15-cr-only-line-endings", "From: a@example.com\rSubject: x\rContent-Type: text/plain\r\rbody\rbody2\r");
        Add("16-lf-only-line-endings", "From: a@example.com\nSubject: x\n\nbody\nbody2\n");
        Add("17-mixed-line-endings", "From: a@example.com\r\nSubject: x\nTo: b@example.net\r\n\nbody\r\nmore\n");
        Add("18-bare-cr-header-injection", "Subject: hi\rBcc: evil@example.com\r\nFrom: a@example.com\r\n\r\nbody");
        Add("19-crlf-injection-via-folding", "Subject: hi\r\n Bcc: evil@example.com\r\nFrom: a@example.com\r\n\r\nbody");
        Add("20-duplicate-singletons", "From: a@example.com\r\n" + string.Concat(Enumerable.Repeat("Subject: s\r\nDate: x\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\nFrom: z@example.com\r\n", 1000)) + "\r\nQUJD");
        Add("21-five-thousand-received", string.Concat(Enumerable.Repeat("Received: from a by b; Mon, 05 Oct 2026 14:03:09 +0000\r\n", 5000)) + "From: a@example.com\r\n\r\nbody");
        Add("22-nul-in-header-name-and-value", "Fr\0om: a@example.com\r\nSubject: a\0b\r\n\r\nbo\0dy");
        Add("23-header-8bit-latin1", "From: a@example.com\r\nSubject: caf\u00e9 \u00fcber\r\n\r\nbody");
        AddBytes("24-header-valid-utf8", Encoding.UTF8.GetBytes("From: \u7528\u6237 <\u7528\u6237@b\u00fccher.example>\r\nSubject: \u4e16\u754c \U0001F600\r\n\r\nbody"));
        AddBytes("25-header-invalid-utf8", new byte[] { (byte)'S', (byte)':', (byte)' ', 0xC3, 0x28, 0xA0, 0xA1, 0xE2, 0x82, (byte)'\r', (byte)'\n', (byte)'\r', (byte)'\n', (byte)'x' });
        AddBytes("26-unicode-line-separators", Encoding.UTF8.GetBytes("Subject: a\u2028b\u2029c\u0085d\r\nFrom: a@example.com\r\n\r\nbody"));

        // ---- encoded words
        Add("27-encoded-word-crlf-injection", "Subject: =?utf-8?Q?hi=0D=0ABcc:_evil@example.com?=\r\nFrom: =?utf-8?Q?x=0D=0ATo:_y?= <a@example.com>\r\n\r\nbody");
        Add("28-hundred-thousand-encoded-words", "Subject: " + string.Concat(Enumerable.Repeat("=?utf-8?Q?a?=", 100_000)) + "\r\n\r\nbody");
        Add("29-encoded-word-megabyte-payload", "Subject: =?utf-8?B?" + new string('A', 1 << 20) + "?=\r\n\r\nbody");
        Add("30-unterminated-encoded-words", "Subject: =?utf-8?B?" + string.Concat(Enumerable.Repeat("=?x?", 100_000)) + "\r\n\r\nbody");
        Add("31-encoded-word-weird-charsets", "Subject: =?utf-7?Q?+2D3cAA-?= =?x-unknown?Q?=E9?= =?" + new string('c', 5000) + "?Q?x?= =?utf-8\0?Q?x?= =?cp037?Q?=C1=C2?= =?iso-2022-jp?B?GyRCJDMkcyRLJEEkTxsoQg==?= =?utf-32?B?AAAAQQ==?=\r\n\r\nbody");
        Add("32-encoded-word-bad-base64-and-qp", "Subject: =?utf-8?B?!!!!?= =?utf-8?B?a?= =?utf-8?Q?=?= =?utf-8?Q?=Z?= =?utf-8?Q?==?= =?utf-8??=\r\n\r\nbody");

        // ---- addresses
        Add("33-comment-bomb-in-from", "From: " + new string('(', 500_000) + "a@example.com\r\n\r\nbody");
        Add("34-quote-bomb-in-to", "To: " + string.Concat(Enumerable.Repeat("\"a", 200_000)) + "\r\n\r\nbody");
        Add("35-angle-bomb", "To: " + new string('<', 300_000) + "\r\n\r\nbody");
        Add("36-group-colon-bomb", "To: " + string.Concat(Enumerable.Repeat("a:", 200_000)) + "\r\n\r\nbody");
        Add("37-fifty-thousand-addresses", "To: " + string.Join(", ", Enumerable.Range(0, 50_000).Select(i => $"u{i}@example.com")) + "\r\n\r\nbody");
        Add("38-empty-address-list-commas", "To: " + new string(',', 100_000) + "\r\n\r\nbody");
        Add("39-from-injection-attempts", "From: a@example.com>\r\n <evil@example.org\r\nTo: <a@example.com>, <\"x@y\"@z>, <@a:b@c>, <a@b@c>\r\n\r\nbody");

        // ---- Content-Type and parameters
        Add("40-content-type-garbage", Hdr("Content-Type: ;;;;\r\n\r\nbody"));
        Add("41-content-type-hundred-thousand-params", Hdr("Content-Type: text/plain" + string.Concat(Enumerable.Range(0, 100_000).Select(i => $"; p{i}=v")) + "\r\n\r\nbody"));
        Add("42-rfc2231-continuation-bomb", Hdr("Content-Type: application/x; name*99999999=a" + string.Concat(Enumerable.Range(0, 500).Select(i => $"; name*{i}*=%41")) + "\r\n\r\nbody"));
        Add("43-rfc2231-absurd-charset", Hdr("Content-Type: application/x; name*=" + new string('x', 70_000) + "''abc\r\n\r\nbody"));
        Add("44-unterminated-quoted-param", Hdr("Content-Type: text/plain; charset=\"utf-8; name=\"x\r\n\r\nbody"));
        Add("45-content-type-comment-bomb", Hdr("Content-Type: text/plain " + new string('(', 100_000) + "\r\n\r\nbody"));
        Add("46-content-type-multiple-conflicting", Hdr("Content-Type: text/plain\r\nContent-Type: multipart/mixed; boundary=x\r\nContent-Type: application/pdf\r\n\r\n--x\r\nfoo\r\n--x--"));
        Add("47-cte-garbage", Hdr("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64 base64\r\n\r\nQUJD"));
        Add("48-charset-garbage", Hdr("Content-Type: text/plain; charset=\"utf-8; rm -rf /\"\r\n\r\nbody"));

        // ---- multipart structure
        Add("49-nesting-bomb-multipart-5000", NestingBomb(5000));
        Add("50-nesting-bomb-rfc822-3000", RfcNestingBomb(3000));
        Add("51-ten-thousand-parts", Mp("B", string.Concat(Enumerable.Repeat("--B\r\nContent-Type: text/plain\r\n\r\nx\r\n", 10_000)) + "--B--\r\n"));
        Add("52-hundred-thousand-empty-parts", Mp("B", string.Concat(Enumerable.Repeat("--B\r\n", 100_000)) + "--B--\r\n"));
        Add("53-huge-boundary-100k", Mp(new string('b', 100_000), "--" + new string('b', 100_000) + "\r\nx\r\n--" + new string('b', 100_000) + "--\r\n"));
        Add("54-boundary-with-embedded-newline", Hdr("Content-Type: multipart/mixed; boundary=\"a\r\n b\"\r\n\r\n--a b\r\nx\r\n--a b--\r\n"));
        Add("55-missing-boundary-param", Hdr("Content-Type: multipart/mixed\r\n\r\n--x\r\ny\r\n--x--\r\n"));
        Add("56-no-closing-delimiter", Mp("B", "--B\r\nContent-Type: text/plain\r\n\r\nonly part\r\n"));
        Add("57-duplicate-boundaries-nested", Mp("B", "--B\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\ninner\r\n--B--\r\n--B--\r\n"));
        Add("58-boundary-is-dash", Mp("-", "---\r\nx\r\n-----\r\n"));
        Add("59-boundary-lines-everywhere", Mp("b", string.Concat(Enumerable.Repeat("--\r\n--b-\r\n--bb\r\n---b\r\n--b --\r\n", 20_000))));
        Add("60-delimiter-lookalike-prefix-attack", Mp(new string('a', 190), string.Concat(Enumerable.Repeat("--" + new string('a', 189) + "b\r\n", 20_000))));
        Add("61-three-byte-needle-pathology", Mp("x", string.Concat(Enumerable.Repeat("\n--\n--\n--\n-", 100_000))));
        Add("62-close-delimiter-then-garbage", Mp("B", "--B\r\nContent-Type: text/plain\r\n\r\nx\r\n--B--\r\n--B\r\nContent-Type: text/plain\r\n\r\nhidden\r\n--B--\r\n"));
        Add("63-preamble-contains-boundary-text", Mp("B", "preamble --B not at line start\r\n--B\r\n\r\nx\r\n--B--\r\n"));
        Add("64-part-headers-one-megabyte", Mp("B", "--B\r\nX-Pad: " + new string('p', 1 << 20) + "\r\n\r\nx\r\n--B--\r\n"));
        Add("65-cte-base64-on-multipart", Hdr("Content-Type: multipart/mixed; boundary=B\r\nContent-Transfer-Encoding: base64\r\n\r\n--B\r\n\r\nx\r\n--B--\r\n"));
        Add("66-rfc822-with-base64", Hdr("Content-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\nRnJvbTogYUBleGFtcGxlLmNvbQ0KDQpoaQ=="));
        Add("67-digest-without-types", Hdr("Content-Type: multipart/digest; boundary=D\r\n\r\n--D\r\n\r\nFrom: x@example.com\r\n\r\nbody\r\n--D\r\n\r\n--D--\r\n"));
        Add("68-external-body-and-partial", Mp("B", "--B\r\nContent-Type: message/external-body; access-type=URL; URL=\"http://x\"\r\n\r\nContent-Type: text/plain\r\n\r\n--B\r\nContent-Type: message/partial; id=x; number=1; total=2\r\n\r\ndata\r\n--B--\r\n"));

        // ---- transfer encodings and bodies
        Add("69-truncated-base64", Hdr("Content-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJDREVGRw"));
        Add("70-base64-only-padding", Hdr("Content-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n====\r\n=\r\n"));
        Add("71-base64-garbage-and-unicode", Hdr("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\u00e9\u00e8\u0000!!!@@@###QUJD"));
        Add("72-base64-two-megabytes", Hdr("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=big.bin\r\n\r\n") + string.Concat(Enumerable.Repeat(new string('A', 76) + "\r\n", 27_000)));
        Add("73-qp-edge-cases", Hdr("Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=\r\n=4\r\n=ZZ\r\n=3d=3D=\r\n== \r\n=\r"));
        Add("74-qp-megabyte-of-equals", Hdr("Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n") + new string('=', 1 << 20));
        Add("75-qp-megabyte-of-soft-breaks", Hdr("Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n") + string.Concat(Enumerable.Repeat("=\r\n", 500_000)));
        Add("76-qp-huge-trailing-whitespace", Hdr("Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nx") + new string(' ', 1 << 20) + "\r\ny");
        Add("77-base64-dump-in-text-plain-utf7", Hdr("Content-Type: text/plain; charset=utf-7\r\nContent-Transfer-Encoding: base64\r\n\r\nKzJEM2NBQS0=\r\n"));
        AddBytes("78-utf16-body-no-bom", Concat("From: a@example.com\r\nContent-Type: text/plain; charset=utf-16\r\n\r\n", Encoding.Unicode.GetBytes("h\u00e9llo w\u00f6rld")));
        AddBytes("79-utf32-body-and-gb18030", Concat("From: a@example.com\r\nContent-Type: text/plain; charset=utf-32\r\n\r\n", Encoding.UTF32.GetBytes("\U0001F600 emoji")));
        AddBytes("80-gb18030-body", Concat("From: a@example.com\r\nContent-Type: text/plain; charset=gb18030\r\n\r\n", new byte[] { 0x81, 0x30, 0x81, 0x30, 0xD6, 0xD0, 0xCE, 0xC4, 0xFF, 0xFE }));
        AddBytes("81-ebcdic-body", Concat("From: a@example.com\r\nContent-Type: text/plain; charset=ibm037\r\n\r\n", new byte[] { 0xC1, 0xC2, 0xC3, 0x40, 0x81, 0x82 }));
        AddBytes("82-iso2022jp-body", Concat("From: a@example.com\r\nContent-Type: text/plain; charset=iso-2022-jp\r\n\r\n", Encoding.ASCII.GetBytes("\u001b$B$3$s$K$A$O\u001b(B hello")));
        AddBytes("83-nul-and-binary-in-text-body", Concat("From: a@example.com\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n", new byte[] { 0, 1, 2, 0xFF, 0xFE, (byte)'a', 0, 0 }));
        AddBytes("84-text-html-with-nul-and-8bit", Concat("From: a@example.com\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: 8bit\r\n\r\n", Encoding.UTF8.GetBytes("<p>\0caf\u00e9 \uFFFE \uD83D\uDE00</p>")));

        // ---- attachment metadata
        Add("85-filename-path-traversal-and-controls", Mp("B", "--B\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename=\"..\\..\\..\\etc\\passwd\\0.zip\"\r\n\r\nPK\r\n--B\r\nContent-Type: application/zip; name*=utf-8''%2E%2E%2Fevil%0D%0AX%00.zip\r\n\r\nPK\r\n--B--\r\n"));
        Add("86-thousand-attachments", Mp("B", string.Concat(Enumerable.Range(0, 1000).Select(i => $"--B\r\nContent-Type: application/octet-stream; name=f{i}.bin\r\nContent-ID: <same@id>\r\nContent-Disposition: attachment; filename=f{i}.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n")) + "--B--\r\n"));
        Add("87-content-id-huge", Mp("B", "--B\r\nContent-Type: image/png\r\nContent-ID: <" + new string('i', 200_000) + ">\r\n\r\nPNG\r\n--B--\r\n"));
        Add("88-filename-two-megabytes", Mp("B", "--B\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=\"" + new string('f', 2 << 20) + "\"\r\n\r\nPNG\r\n--B--\r\n"));

        // ---- raw byte floods
        AddBytes("89-one-megabyte-of-nul", new byte[1 << 20]);
        AddBytes("90-one-megabyte-of-ff", Enumerable.Repeat((byte)0xFF, 1 << 20).ToArray());
        Add("91-one-megabyte-of-lf", new string('\n', 1 << 20));
        Add("92-one-megabyte-of-cr", new string('\r', 1 << 20));
        Add("93-one-megabyte-of-colon", new string(':', 1 << 20));
        Add("94-one-megabyte-of-crlf-pairs", string.Concat(Enumerable.Repeat("\r\n", 500_000)));
        Add("95-subject-one-megabyte-of-spaces", "Subject:" + new string(' ', 1 << 20) + "x\r\n\r\nbody");
        Add("96-date-garbage", Hdr("Date: " + new string('9', 100_000) + "\r\nMessage-ID: " + new string('<', 50_000) + "\r\n\r\nbody"));
        var rng = new Random(1234);
        var random = new byte[1 << 20];
        rng.NextBytes(random);
        AddBytes("97-random-binary-1mb", random);
        var ascii = new byte[1 << 18];
        for (int i = 0; i < ascii.Length; i++)
        {
            ascii[i] = (byte)Structural[rng.Next(Structural.Length)];
        }

        AddBytes("98-random-structural-chars-256k", ascii);
        Add("99-alternating-boundary-and-headers", Mp("B", string.Concat(Enumerable.Repeat("--B\r\nContent-Type: multipart/mixed; boundary=\"C\"\r\n\r\n--C\r\nContent-Type: text/plain\r\n\r\nx\r\n", 500))));
        return items;
    }

    private const string Structural = ":-=\"<>;,()@ \r\n\tabcdefMIME";

    private static string NestingBomb(int depth)
    {
        var sb = new StringBuilder("From: a@example.com\r\n");
        for (int i = 0; i < depth; i++)
        {
            sb.Append($"Content-Type: multipart/mixed; boundary=b{i}\r\n\r\n--b{i}\r\n");
        }

        sb.Append("Content-Type: text/plain\r\n\r\nx\r\n");
        return sb.ToString();
    }

    private static string RfcNestingBomb(int depth)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < depth; i++)
        {
            sb.Append("From: a@example.com\r\nContent-Type: message/rfc822\r\n\r\n");
        }

        sb.Append("Subject: innermost\r\n\r\nx\r\n");
        return sb.ToString();
    }

    private static byte[] Concat(string head, byte[] tail) => Encoding.ASCII.GetBytes(head).Concat(tail).ToArray();
}
