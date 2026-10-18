using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Mta.Dkim;
using Mta.Dns;
using Mta.Mime;
using Mta.TestSupport;
using Xunit.Abstractions;

namespace Mta.Host.Tests.Leaks;

/// <summary>
/// Accelerated lifecycle, leaks: the hand-written protocol libraries rent their working memory from <c>ArrayPool&lt;T&gt;.Shared</c> (message segments,
/// DKIM canonicalization buffers, MIME parse buffers, DNS packets). A rental that is not returned is not a memory leak (the array is simply collected) but it
/// turns a pooled hot path into an allocating one, which is what the pooling exists to avoid. The runtime reports every rent and return of the shared pool; each
/// flow is repeated thousands of times and the number of outstanding rentals must not grow, and it must be zero when the flow is not holding anything.
/// </summary>
[Collection(LeakCollection.Name)]
public sealed class PooledBufferLeakTests(ITestOutputHelper output)
{
    private static byte[] Message(int i) => Encoding.UTF8.GetBytes(
        "From: Acme <news@example.org>\r\nTo: rcpt@dest.example\r\nSubject: Leak check " + i + "\r\nMessage-ID: <leak" + i + "@example.org>\r\nDate: Mon, 12 Oct 2026 12:30:00 +0000\r\n" +
        "MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"b1\"\r\n\r\n" +
        "--b1\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHello =E2=9C=93 from EggMail\r\n" +
        "--b1\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hello from EggMail</p>\r\n--b1--\r\n");

    [Fact]
    public async Task Leak_dkim_signing_and_verifying_return_every_pooled_array()
    {
        using RSA key = DkimKeyTools.GenerateRsa2048();
        using var signer = new DkimSigner(new DkimSignerOptions { Domain = "example.org", Selector = "leak" }, key);
        var dns = new StaticDnsResolver();
        dns.AddTxt("leak._domainkey.example.org", DkimKeyTools.FormatDnsTxtValue(key));
        var verifier = new DkimVerifier(dns);

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance();
        LeakReport report = await probe.RunAsync(async i =>
        {
            byte[] raw = Message(i);
            string header = signer.Sign(raw);
            Assert.StartsWith("DKIM-Signature:", header);
            Assert.False(signer.SignToBytes(raw).IsEmpty);
            byte[] prepended = signer.SignPrepended(raw, out int length);
            Assert.True(length > raw.Length);
            DkimVerificationResult result = Assert.Single(await verifier.VerifyAsync(prepended.AsMemory(0, length)));
            Assert.Equal(DkimStatus.Pass, result.Status);
            ArrayPool<byte>.Shared.Return(prepended);   // SignPrepended hands the caller a rented array
        }, Accelerated.Scaled(150));
        report.AssertNoGrowth();
        Assert.Equal(0, report["ArrayPool rentals outstanding"].B3);
    }

    [Fact]
    public async Task Leak_mime_parsing_and_content_extraction_return_every_pooled_array()
    {
        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance();
        LeakReport report = await probe.RunAsync(i =>
        {
            ReadOnlyMemory<byte> raw = Message(i);
            ExtractedContent content = MessageContentExtractor.Extract(raw);
            Assert.Equal("Leak check " + i, content.Subject);
            Assert.Contains("Hello", content.TextBody);
        }, Accelerated.Scaled(2000));
        report.AssertNoGrowth();
        Assert.Equal(0, report["ArrayPool rentals outstanding"].B3);
    }

    [Fact]
    public async Task Leak_dns_client_rentals_are_returned_for_answers_errors_and_timeouts()
    {
        var clock = new VirtualClock();
        int n = 0;
        var client = new DnsClient(new Failing(() => Interlocked.Increment(ref n)), new DnsResolverOptions { MaxCacheEntries = 0, Attempts = 1, EdnsUdpPayloadSize = 1232 }, clock);

        using var probe = new LeakProbe(output.WriteLine);
        probe.TrackArrayPoolBalance();
        LeakReport report = await probe.RunAsync(async i =>
        {
            // The transport answers garbage, an empty packet, a refused-looking packet or throws; each ends in an exception or a failure answer, none may keep a buffer.
            try
            {
                await client.QueryAsync($"host{i}.example.test", DnsRecordType.A);
            }
            catch (DnsException)
            {
            }
        }, Accelerated.Scaled(2000));
        report.AssertNoGrowth();
        Assert.Equal(0, report["ArrayPool rentals outstanding"].B3);
    }

    private sealed class Failing(Func<int> next) : IDnsTransport
    {
        public ValueTask<ReadOnlyMemory<byte>> ExchangeAsync(ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
        {
            switch (next() % 4)
            {
                case 0:
                    return ValueTask.FromResult<ReadOnlyMemory<byte>>(new byte[] { 1, 2, 3 });
                case 1:
                    return ValueTask.FromResult(ReadOnlyMemory<byte>.Empty);
                case 2:
                    byte[] echoed = query.ToArray();   // the question itself, not a response (QR bit clear)
                    return ValueTask.FromResult<ReadOnlyMemory<byte>>(echoed);
                default:
                    throw new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.ConnectionRefused);
            }
        }
    }
}
