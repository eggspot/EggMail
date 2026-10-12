using System.Text;
using BenchmarkDotNet.Attributes;
using Mta.Mime;

namespace Mta.Benchmarks.Mime;

/// <summary>
/// Micro-benchmarks for the receive path: splitting headers from body, parsing the header list, and extracting the
/// content that message history stores. Run with
/// <c>dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*MimeBenchmarks*"</c>.
/// </summary>
[MemoryDiagnoser]
public class MimeBenchmarks
{
    private byte[] _small = [];
    private byte[] _withAttachment = [];

    [GlobalSetup]
    public void Setup()
    {
        var small = new StringBuilder();
        small.Append("Received: from client.example.com (client.example.com [192.0.2.10])\r\n\tby mx.example.net with ESMTPS id 1234567890; Mon, 05 Oct 2026 14:03:09 +0000\r\n");
        small.Append("From: Alice <alice@example.com>\r\nTo: Bob <bob@example.net>, carol@example.org\r\nSubject: =?utf-8?B?SGVsbG8gV8O2cmxk?=\r\n");
        small.Append("Date: Mon, 05 Oct 2026 14:03:00 +0000\r\nMessage-ID: <abc123@example.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n");
        for (int i = 0; i < 20; i++)
        {
            small.Append("Gr=C3=BC=C3=9Fe aus M=C3=BCnchen, this is a line of ordinary body text number ").Append(i).Append("\r\n");
        }

        _small = Encoding.ASCII.GetBytes(small.ToString());

        var builder = new MessageBuilder(new MessageBuilderOptions { MessageIdDomain = "example.com" })
        {
            From = Mailbox.Create("Alice", "alice@example.com"),
            Subject = "Report",
            TextBody = string.Concat(Enumerable.Repeat("Quarterly numbers are attached, please review. é\n", 40)),
            HtmlBody = "<p>Quarterly numbers are attached.</p>",
        };
        builder.To.Add(Mailbox.Create("Bob", "bob@example.net"));
        builder.Attachments.Add(new BuilderAttachment("report.pdf", "application/pdf", new byte[200_000]));
        _withAttachment = builder.Build().Content;
    }

    [Benchmark]
    public int FindBodyOffset() => HeaderList.FindBodyOffset(_small);

    [Benchmark]
    public int ParseHeaders() => HeaderList.Parse(_small).Count;

    [Benchmark]
    public int ParseHeadersAndReadFrom()
    {
        var headers = HeaderList.Parse(_small);
        return AddressList.Parse(headers.GetFirstValue(HeaderId.From)).MailboxCount;
    }

    [Benchmark]
    public int ParseMimeTree() => MimeMessage.Parse(_withAttachment).PartCount;

    [Benchmark]
    public int ExtractSmall() => MessageContentExtractor.Extract(_small).TextBody!.Length;

    [Benchmark]
    public int ExtractWithAttachment() => MessageContentExtractor.Extract(_withAttachment).Attachments.Count;

    [Benchmark]
    public int PrependTraceHeaders() => new MessageHeaderEditor(_small).PrependReceived("from a by b").PrependReturnPath("a@example.com").ToArray().Length;
}
