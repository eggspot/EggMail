using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Xunit.Abstractions;

namespace Mta.Dkim.Tests;

/// <summary>Allocation and work guards. Nothing here asserts wall-clock time or throughput: those depend on the load of the machine, not on the code (see bench/Mta.Benchmarks for measurements).</summary>
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
    public void Canonicalizing_and_hashing_a_large_body_matches_the_reference_in_one_pass()
    {
        // No wall-clock threshold: throughput under a loaded CI runner is not a property of the code. What is checked is the
        // result (byte-exact against the independent reference canonicalizer) and the work (one pass: the canonical byte
        // count equals the reference length, and nothing is allocated, see Body_canonicalization_and_hashing_allocate_nothing_after_warmup).
        // Throughput numbers belong to the benchmark project (bench/Mta.Benchmarks).
        string body = MessageOfSize(1024 * 1024);
        Span<byte> hash = stackalloc byte[32];
        foreach (bool relaxed in new[] { true, false })
        {
            DkimVerifier.HashBody(Msg.Bytes(body), relaxed, long.MaxValue, hash, out long total);
            byte[] expected = Msg.Bytes(Reference.Body(body, relaxed));
            Assert.Equal(expected.Length, total);
            Assert.Equal(Convert.ToBase64String(SHA256.HashData(expected)), Convert.ToBase64String(hash));
        }
    }

    [Fact]
    public async Task Repeated_signing_and_verification_stays_correct()
    {
        // The former version asserted signatures per second, which depends on the host load rather than on the code.
        var signer = Msg.Signer();
        var verifier = Msg.Verifier(Msg.Dns(TestKeys.Rsa2048));
        string message = MessageOfSize(1024);
        const int count = 100;
        for (int i = 0; i < count; i++)
        {
            byte[] signed = Msg.Bytes(Msg.Sign(signer, message + i));
            var results = await verifier.VerifyAsync(signed);
            Assert.Equal(DkimStatus.Pass, Assert.Single(results).Status);
        }
    }

    [Fact]
    public async Task Hostile_message_with_many_headers_and_signatures_is_bounded_by_the_limits_not_by_the_clock()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) { sb.Append("DKIM-Signature: v=1; a=rsa-sha256; d=d.example; s=s; h=").Append(string.Join(":", Enumerable.Repeat("x-a", 400))).Append("; bh=AAAA; b=AAAA\r\n"); }
        sb.Append(Msg.Simple());
        var dns = new Mta.Dns.StaticDnsResolver();
        var verifier = Msg.Verifier(dns, configure: o => o.MaxHeaderCount = 2000);

        // The deterministic bound is the work done, not the time it took: every signature is reported, but at most the
        // configured number of them reaches the DNS (the key lookup) and none passes. The wait is only a hang guard.
        var results = await verifier.VerifyAsync(Msg.Bytes(sb.ToString())).AsTask().WaitAsync(TimeSpan.FromMinutes(5));
        Assert.Equal(1000, results.Count);
        Assert.DoesNotContain(results, r => r.Status == DkimStatus.Pass);
        Assert.True(dns.QueryCount <= 5, $"{dns.QueryCount} DNS queries for one hostile message");
    }
}
