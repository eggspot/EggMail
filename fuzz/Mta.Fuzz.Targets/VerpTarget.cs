using System.Text;
using Mta.Dsn;

namespace Mta.Fuzz;

/// <summary>
/// The VERP bounce address decoder: the local part of every message that reaches the bounce listener goes through
/// <see cref="VerpCodec.TryDecode"/> before anything is authenticated. The input is <c>local-part</c> or <c>local-part@domain</c>; the
/// domain is compared with the token's destination tag (<see cref="VerpCodec.CheckDestination"/>).
/// <para>The codec has fixed keys and a fixed clock, so the tokens it issued are known: the main invariant is that nothing else decodes.
/// A forged MAC is out of reach for a fuzzer, so an input that decodes without being (case-insensitively) one of the issued tokens means
/// the decoder accepts a second spelling of a token (padding bits, alphabet, length), which would break the one-token-one-address rule.</para>
/// </summary>
internal static class VerpTarget
{
    private static readonly DateTimeOffset Now = new(2026, 10, 13, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan MaxAge = TimeSpan.FromDays(14);
    private static readonly Guid TenantA = Guid.Parse("0192a5c0-0000-7000-8000-000000000001");
    private static readonly Guid TenantB = Guid.Parse("0192a5c0-0000-7000-8000-0000000000b2");
    private static readonly Guid DomainA = Guid.Parse("0192a5c0-1111-7000-8000-00000000000a");
    private static readonly Guid DomainB = Guid.Parse("0192a5c0-2222-7000-8000-00000000000b");

    // Retired key 3 and active key 0, as after one rotation. Fixed bytes: the seeds must be the same on every machine.
    private static readonly VerpCodec Codec = new(
        new Dictionary<int, byte[]>
        {
            [0] = Enumerable.Range(0, 32).Select(i => (byte)(i * 7 + 1)).ToArray(),
            [3] = Enumerable.Range(0, 32).Select(i => (byte)(255 - i)).ToArray(),
        },
        activeKeyId: 0);

    private static readonly VerpCodec RetiredCodec = new(
        new Dictionary<int, byte[]> { [3] = Enumerable.Range(0, 32).Select(i => (byte)(255 - i)).ToArray() },
        activeKeyId: 3);

    private static readonly Lazy<Issued[]> AllIssued = new(IssueTokens);

    public static FuzzTarget Create() => new("verp", "VERP bounce address decoder (unauthenticated input of the bounce listener) and destination check", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 150000,
        MaxInputLength = 4 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        string text = input.Length > 0 && (input[0] & 1) == 1 ? Encoding.Latin1.GetString(input) : Encoding.UTF8.GetString(input);
        int at = text.LastIndexOf('@');
        string localPart = at >= 0 ? text[..at] : text;
        string? domain = at >= 0 ? text[(at + 1)..] : null;

        var issued = AllIssued.Value.FirstOrDefault(i => string.Equals(i.LocalPart, localPart, StringComparison.OrdinalIgnoreCase));
        bool decoded = Codec.TryDecode(localPart, Now, MaxAge, out var token);
        if (!decoded)
        {
            Guard.Check(issued is null || !issued.Valid, $"an issued, unexpired token did not decode: {localPart}");
            Guard.Check(token == default, "a refused token must leave the output at its default");
            return;
        }

        Guard.Check(issued is not null, $"a local part that was never issued decoded: {localPart}");
        Guard.Check(issued.Valid, $"an expired token decoded: {localPart}");
        Guard.Check(token.TenantId == issued.Tenant, "decoded tenant differs from the issued one");
        Guard.Check(VerpCodec.MatchesDomain(token, issued.Domain), "decoded domain prefix differs from the issued one");
        Guard.Check(token.KeyId is 0 or 3, "decoded key id outside the ring");
        Guard.Check(token.IssuedAt <= Now.AddHours(1) && Now - token.IssuedAt <= MaxAge, "decoded timestamp outside the accepted window");
        Guard.Check(token.BoundToDestination == (issued.Destination is not null), "decoded version differs from the issued one");

        if (domain is not null)
        {
            var check = Codec.CheckDestination(token, domain);
            if (issued.Destination is null)
            {
                Guard.Check(check == VerpDestinationCheck.Unbound, "a version 1 token must not claim a destination");
            }
            else if (check == VerpDestinationCheck.Match)
            {
                // A 32-bit tag can collide by chance, but not for the handful of names a fuzzer splices in.
                Guard.Check(SameDomain(domain, issued.Destination), $"destination check matched another domain: {domain} for {issued.Destination}");
            }
        }
    }

    /// <summary>The names the codec treats as one: case, a trailing dot, surrounding blanks and the U-label of an IDN.</summary>
    private static bool SameDomain(string candidate, string destination)
    {
        static string Normalize(string d)
        {
            d = d.Trim().TrimEnd('.').ToLowerInvariant();
            try
            {
                return d.All(char.IsAscii) ? d : new System.Globalization.IdnMapping().GetAscii(d).ToLowerInvariant();
            }
            catch (ArgumentException)
            {
                return d;
            }
        }

        return Normalize(candidate) == Normalize(destination);
    }

    private sealed record Issued(string LocalPart, Guid Tenant, Guid Domain, string? Destination, bool Valid);

    private static Issued[] IssueTokens() =>
    [
        new(Codec.CreateLocalPart(TenantA, DomainA, Now, "gmail.com"), TenantA, DomainA, "gmail.com", true),
        new(Codec.CreateLocalPart(TenantA, DomainA, Now), TenantA, DomainA, null, true),
        new(Codec.CreateLocalPart(TenantB, DomainB, Now.AddDays(-13), "bücher.example"), TenantB, DomainB, "bücher.example", true),
        new(Codec.CreateLocalPart(TenantB, DomainA, Now.AddMinutes(50), "example.net"), TenantB, DomainA, "example.net", true),
        new(RetiredCodec.CreateLocalPart(TenantA, DomainB, Now.AddDays(-2), "example.org"), TenantA, DomainB, "example.org", true),
        new(RetiredCodec.CreateLocalPart(TenantB, DomainB, Now.AddDays(-1)), TenantB, DomainB, null, true),

        // Refused: too old, too far in the future.
        new(Codec.CreateLocalPart(TenantA, DomainA, Now.AddDays(-15), "gmail.com"), TenantA, DomainA, "gmail.com", false),
        new(Codec.CreateLocalPart(TenantA, DomainB, Now.AddHours(3)), TenantA, DomainB, null, false),
    ];

    private static IReadOnlyList<byte[]> Seeds()
    {
        var issued = AllIssued.Value;
        var seeds = new List<string>
        {
            issued[0].LocalPart + "@gmail.com",
            issued[0].LocalPart + "@GMAIL.COM.",
            issued[0].LocalPart + "@outlook.com",
            issued[1].LocalPart + "@gmail.com",
            issued[2].LocalPart.ToUpperInvariant() + "@xn--bcher-kva.example",
            issued[3].LocalPart,
            issued[4].LocalPart + "@example.org",
            issued[5].LocalPart,
            issued[6].LocalPart + "@gmail.com",
            issued[7].LocalPart,
            "b+",
            "b+aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "postmaster",
        };

        // A valid token behind another prefix; an odd first byte ('c') also makes the target read the input as Latin-1 instead of UTF-8.
        seeds.Add("c" + issued[0].LocalPart[1..]);
        return seeds.Select(s => Encoding.UTF8.GetBytes(s)).ToList();
    }

    private static IReadOnlyList<byte[]> Tokens() =>
        new[] { "b+", "B+", "@", "@gmail.com", "@example.org", ".", "a", "z", "2", "7", "8", "1", "0", "=", "q", "ı", "ſ", "K", "K", "xn--" }
            .Select(s => Encoding.UTF8.GetBytes(s)).ToList();
}
