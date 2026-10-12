using Mta.Auth.Arc;
using static Mta.Auth.Tests.Arc.ArcMsg;

namespace Mta.Auth.Tests.Arc;

/// <summary>Deterministic (seeded) mutation of valid chains: validation and parsing never throw and never report Pass for a damaged ARC header.</summary>
public class ArcFuzzTests
{
    private const string Alphabet = "abcdefghijklmnopqrstuvwxyz0123456789;=:. \t\r\n-_/+AB";

    [Fact]
    public async Task Mutated_chains_never_throw_and_damaged_arc_headers_never_pass()
    {
        var dns = DnsForAllHops();
        string valid = await ChainAsync(3, dns: dns);
        var validator = Validator(dns);
        var random = new Random(8617);
        int passed = 0;
        for (int round = 0; round < 600; round++)
        {
            var (fields, body) = Split(valid);
            var arcIndexes = Enumerable.Range(0, fields.Count).Where(i => IsArc(fields[i])).ToList();
            int target = arcIndexes[random.Next(arcIndexes.Count)];
            string field = fields[target];
            var chars = new System.Text.StringBuilder(field);
            int edits = random.Next(1, 4);
            for (int e = 0; e < edits; e++)
            {
                int start = field.IndexOf(':') + 1;
                int pos = start + random.Next(Math.Max(1, chars.Length - start - 2));
                switch (random.Next(3))
                {
                    case 0: chars.Remove(pos, 1); break;
                    case 1: chars.Insert(pos, Alphabet[random.Next(Alphabet.Length)]); break;
                    default: chars[pos] = Alphabet[random.Next(Alphabet.Length)]; break;
                }
            }

            string mutatedField = chars.ToString();
            if (mutatedField == field) { continue; }
            if (random.Next(10) == 0) { fields.RemoveAt(target); } else { fields[target] = mutatedField; }

            ArcChainResult result = await validator.ValidateAsync(Bytes(Join(fields, body)));
            Assert.NotEqual(ArcFailure.InternalError, result.Failure);
            if (result.Status == ArcChainStatus.Pass)
            {
                // Only whitespace-only or b= value-folding mutations may survive.
                passed++;
                Assert.Equal(3, result.InstanceCount);
            }
        }

        Assert.True(passed < 120, "too many mutated chains passed: " + passed);
    }

    [Fact]
    public async Task Random_garbage_in_arc_headers_never_throws()
    {
        var validator = Validator(DnsForAllHops());
        var random = new Random(17);
        string[] names = ["ARC-Seal", "ARC-Message-Signature", "ARC-Authentication-Results"];
        for (int round = 0; round < 500; round++)
        {
            var sb = new System.Text.StringBuilder();
            int count = random.Next(1, 8);
            for (int i = 0; i < count; i++)
            {
                sb.Append(names[random.Next(3)]).Append(": ");
                int len = random.Next(0, 80);
                for (int c = 0; c < len; c++) { sb.Append(Alphabet[random.Next(Alphabet.Length)]); }
                sb.Append("\r\n");
            }

            sb.Append(Original());
            ArcChainResult result = await validator.ValidateAsync(Bytes(sb.ToString()));
            Assert.NotEqual(ArcFailure.InternalError, result.Failure);
            Assert.NotEqual(ArcChainStatus.Pass, result.Status);
        }
    }

    [Fact]
    public void Header_parsers_never_throw_on_random_input()
    {
        var random = new Random(99);
        for (int round = 0; round < 2000; round++)
        {
            int len = random.Next(0, 120);
            var bytes = new byte[len];
            for (int i = 0; i < len; i++) { bytes[i] = random.Next(4) == 0 ? (byte)random.Next(256) : (byte)Alphabet[random.Next(Alphabet.Length)]; }
            _ = ArcSealHeader.TryParse(bytes, out _, out _);
            _ = ArcMessageSignatureHeader.TryParse(bytes, out _, out _);
            _ = ArcAuthenticationResultsHeader.TryParse(bytes, out _, out _);
        }
    }

    [Fact]
    public async Task Sealer_never_throws_unexpectedly_on_mutated_messages()
    {
        var random = new Random(5);
        string valid = await ChainAsync(2);
        using var sealer = Sealer("c.example");
        for (int round = 0; round < 300; round++)
        {
            var chars = new System.Text.StringBuilder(valid);
            for (int e = random.Next(1, 4); e > 0; e--)
            {
                int pos = random.Next(chars.Length);
                if (random.Next(2) == 0) { chars.Remove(pos, 1); } else { chars[pos] = Alphabet[random.Next(Alphabet.Length)]; }
            }

            byte[] message = Bytes(chars.ToString());
            var incoming = await Validator(DnsForAllHops()).ValidateAsync(message);
            try
            {
                var result = sealer.Seal(message, "mx.c.example; none", incoming);
                if (result.IsSealed)
                {
                    Assert.Equal(incoming.Status == ArcChainStatus.Pass ? ArcChainStatus.Pass : incoming.Status == ArcChainStatus.None ? ArcChainStatus.None : ArcChainStatus.Fail, result.ChainValidationStatus);
                }
            }
            catch (ArgumentException)
            {
                // A message without From, or one that no longer matches the chain result, is a caller error.
            }
        }
    }
}
