using System.Buffers;
using System.Diagnostics;
using System.Text;
using Xunit.Abstractions;

namespace Mta.Dkim.Tests;

/// <summary>Coarse performance and allocation guards. Limits are deliberately loose so they only catch order-of-magnitude regressions.</summary>
public class PerformanceTests
{
    /// <summary>
    /// Documented allocation budget for DkimSigner.Sign(message, IBufferWriter) on a warmed-up thread, excluding the caller's output buffer.
    /// The hash, header table and header builder come from pools; what remains is a few small objects from the platform RSA implementation (64 bytes measured on macOS arm64; the budget leaves room for other platforms).
    /// </summary>
    private const int SignAllocationBudgetBytes = 2048;

    private readonly ITestOutputHelper _output;

    public PerformanceTests(ITestOutputHelper output) => _output = output;

    private static string MessageOfSize(int bodyBytes)
    {
        var sb = new StringBuilder();
        int i = 0;
        while (sb.Length < bodyBytes) { sb.Append("Line ").Append(i++).Append(" of the message body with   some  spacing and words.  \r\n"); }
        return Msg.Simple(sb.ToString());
    }

    [Fact]
    public void Signing_a_50_kb_message_allocates_only_a_small_bounded_amount()
    {
        var signer = Msg.Signer();
        byte[] message = Msg.Bytes(MessageOfSize(50 * 1024));
        var output = new ArrayBufferWriter<byte>(4096);

        for (int i = 0; i < 20; i++) { output.Clear(); signer.Sign(message, output); } // warm up pools and JIT

        long worst = 0;
        for (int i = 0; i < 20; i++)
        {
            output.Clear();
            long before = GC.GetAllocatedBytesForCurrentThread();
            signer.Sign(message, output);
            worst = Math.Max(worst, GC.GetAllocatedBytesForCurrentThread() - before);
        }

        _output.WriteLine($"Sign(50 KB) allocated at most {worst} bytes besides the output buffer");
        Assert.True(worst <= SignAllocationBudgetBytes, $"allocated {worst} bytes, budget {SignAllocationBudgetBytes}");
    }

    [Fact]
    public void Allocation_does_not_grow_with_message_size()
    {
        var signer = Msg.Signer();
        var output = new ArrayBufferWriter<byte>(4096);
        long Measure(int size)
        {
            byte[] message = Msg.Bytes(MessageOfSize(size));
            for (int i = 0; i < 10; i++) { output.Clear(); signer.Sign(message, output); }
            long before = GC.GetAllocatedBytesForCurrentThread();
            output.Clear();
            signer.Sign(message, output);
            return GC.GetAllocatedBytesForCurrentThread() - before;
        }

        long small = Measure(1024);
        long large = Measure(2 * 1024 * 1024);
        _output.WriteLine($"1 KB: {small} bytes, 2 MB: {large} bytes");
        Assert.True(large <= small + 512, $"allocation grew with the message: {small} -> {large}");
    }

    [Fact]
    public void Body_canonicalization_and_hashing_allocate_nothing_after_warmup()
    {
        byte[] body = Msg.Bytes(MessageOfSize(200 * 1024));
        Span<byte> hash = stackalloc byte[32];
        for (int i = 0; i < 5; i++) { DkimVerifier.HashBody(body, true, long.MaxValue, hash, out _); }
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 20; i++) { DkimVerifier.HashBody(body, true, long.MaxValue, hash, out _); }
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal(0, allocated);
    }

    [Fact]
    public void Canonicalizing_and_hashing_runs_at_a_sane_speed()
    {
        byte[] body = Msg.Bytes(MessageOfSize(1024 * 1024));
        Span<byte> hash = stackalloc byte[32];
        DkimVerifier.HashBody(body, true, long.MaxValue, hash, out _);
        var sw = Stopwatch.StartNew();
        const int rounds = 50;
        for (int i = 0; i < rounds; i++) { DkimVerifier.HashBody(body, true, long.MaxValue, hash, out _); }
        sw.Stop();
        double mbPerSecond = rounds * (body.Length / 1048576.0) / sw.Elapsed.TotalSeconds;
        _output.WriteLine($"relaxed body canonicalization + SHA-256: {mbPerSecond:F0} MB/s");
        Assert.True(mbPerSecond > 20, $"too slow: {mbPerSecond:F1} MB/s");
    }

    [Fact]
    public async Task Sign_and_verify_throughput_is_sane()
    {
        var signer = Msg.Signer();
        var verifier = Msg.Verifier(Msg.Dns(TestKeys.Rsa2048));
        string message = MessageOfSize(1024);
        byte[] bytes = Msg.Bytes(message);
        signer.Sign(bytes);

        var sw = Stopwatch.StartNew();
        const int count = 200;
        for (int i = 0; i < count; i++) { signer.Sign(bytes); }
        double signPerSecond = count / sw.Elapsed.TotalSeconds;

        byte[] signed = Msg.Bytes(Msg.Sign(signer, message));
        await verifier.VerifyAsync(signed);
        sw.Restart();
        for (int i = 0; i < count; i++) { await verifier.VerifyAsync(signed); }
        double verifyPerSecond = count / sw.Elapsed.TotalSeconds;

        _output.WriteLine($"sign {signPerSecond:F0}/s, verify {verifyPerSecond:F0}/s (1 KB message, RSA-2048, single thread)");
        Assert.True(signPerSecond > 20, $"signing too slow: {signPerSecond:F1}/s");
        Assert.True(verifyPerSecond > 50, $"verification too slow: {verifyPerSecond:F1}/s");
    }

    [Fact]
    public async Task Hostile_message_with_many_headers_and_signatures_is_processed_quickly()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) { sb.Append("DKIM-Signature: v=1; a=rsa-sha256; d=d.example; s=s; h=").Append(string.Join(":", Enumerable.Repeat("x-a", 400))).Append("; bh=AAAA; b=AAAA\r\n"); }
        sb.Append(Msg.Simple());
        var verifier = Msg.Verifier(new Mta.Dns.StaticDnsResolver(), configure: o => o.MaxHeaderCount = 2000);
        var sw = Stopwatch.StartNew();
        var results = await verifier.VerifyAsync(Msg.Bytes(sb.ToString()));
        sw.Stop();
        Assert.Equal(1000, results.Count);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"took {sw.Elapsed}");
    }
}
