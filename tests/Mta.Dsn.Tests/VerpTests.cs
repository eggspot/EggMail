using Mta.Core;
using Mta.Dsn;

namespace Mta.Dsn.Tests;

public class VerpTests
{
    private static VerpCodec Codec(params (int Id, byte[] Key)[] extra)
    {
        var keys = new Dictionary<int, byte[]> { [1] = VerpCodec.GenerateKey() };
        foreach (var (id, key) in extra) { keys[id] = key; }
        return new VerpCodec(keys, 1);
    }

    private static readonly DateTimeOffset Now = new(2026, 10, 12, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Roundtrip_and_length_fits_local_part_limit()
    {
        var codec = Codec();
        var tenant = Ids.New();
        var domain = Ids.New();
        string local = codec.CreateLocalPart(tenant, domain, Now);
        Assert.StartsWith("b+", local);
        Assert.True(local.Length <= 64, $"local part is {local.Length} chars");
        Assert.True(local.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '+'));
        Assert.True(codec.TryDecode(local, Now.AddHours(30), TimeSpan.FromDays(14), out var t));
        Assert.Equal(tenant, t.TenantId);
        Assert.True(VerpCodec.MatchesDomain(t, domain));
        Assert.False(VerpCodec.MatchesDomain(t, Ids.New()));
        Assert.True(EmailAddress.TryParse(codec.CreateAddress(tenant, domain, "bounces.example.com", Now), false, out _));
    }

    [Fact]
    public void A_token_bound_to_a_destination_domain_fits_the_local_part_limit_and_round_trips()
    {
        var codec = Codec();
        var tenant = Ids.New();
        var domain = Ids.New();

        string local = codec.CreateLocalPart(tenant, domain, Now, "dest.example");

        Assert.Equal(63, local.Length);   // b+ and 61 characters: 38 bytes
        Assert.True(local.Length <= 64);
        Assert.True(local.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '+'));
        Assert.True(codec.TryDecode(local, Now.AddHours(30), TimeSpan.FromDays(14), out var t));
        Assert.Equal(tenant, t.TenantId);
        Assert.True(VerpCodec.MatchesDomain(t, domain));
        Assert.True(t.BoundToDestination);
        Assert.True(EmailAddress.TryParse(codec.CreateAddress(tenant, domain, "bounces.example.com", Now, "dest.example"), false, out _));
    }

    [Theory]
    [InlineData("dest.example", "dest.example", VerpDestinationCheck.Match)]
    [InlineData("dest.example", "DEST.Example", VerpDestinationCheck.Match)]
    [InlineData("dest.example", "dest.example.", VerpDestinationCheck.Match)]
    [InlineData("Bücher.example", "xn--bcher-kva.example", VerpDestinationCheck.Match)]
    [InlineData("xn--bcher-kva.example", "BÜCHER.example", VerpDestinationCheck.Match)]
    [InlineData("dest.example", "other.example", VerpDestinationCheck.Mismatch)]
    [InlineData("dest.example", "sub.dest.example", VerpDestinationCheck.Mismatch)]
    [InlineData("dest.example", "dest.example.evil.example", VerpDestinationCheck.Mismatch)]
    [InlineData("dest.example", "", VerpDestinationCheck.Mismatch)]
    public void The_destination_check_compares_normalised_domains(string issuedFor, string named, VerpDestinationCheck expected)
    {
        var codec = Codec();
        Assert.True(codec.TryDecode(codec.CreateLocalPart(Ids.New(), Ids.New(), Now, issuedFor), Now, TimeSpan.FromDays(1), out var token));

        Assert.Equal(expected, codec.CheckDestination(token, named));
    }

    [Fact]
    public void The_destination_tag_is_keyed_so_a_tag_cannot_be_computed_from_another_installations_token()
    {
        var a = Codec();
        var b = Codec();
        Assert.True(a.TryDecode(a.CreateLocalPart(Ids.New(), Ids.New(), Now, "dest.example"), Now, TimeSpan.FromDays(1), out var tokenA));
        Assert.True(b.TryDecode(b.CreateLocalPart(Ids.New(), Ids.New(), Now, "dest.example"), Now, TimeSpan.FromDays(1), out var tokenB));

        Assert.NotEqual(tokenA.DestinationTag, tokenB.DestinationTag);
    }

    [Fact]
    public void Tampering_with_any_character_of_a_bound_token_is_rejected()
    {
        var codec = Codec();
        string local = codec.CreateLocalPart(Ids.New(), Ids.New(), Now, "dest.example");
        for (int i = 2; i < local.Length; i++)
        {
            var copy = local.ToCharArray();
            copy[i] = copy[i] == 'a' ? 'b' : 'a';
            Assert.False(codec.TryDecode(new string(copy), Now, TimeSpan.FromDays(1), out _), $"flip at {i}");
        }

        Assert.False(codec.TryDecode(local + "a", Now, TimeSpan.FromDays(1), out _));
        Assert.False(codec.TryDecode(local[..^1], Now, TimeSpan.FromDays(1), out _));
    }

    [Fact]
    public void A_token_without_a_destination_is_still_accepted_and_says_nothing_about_the_destination()
    {
        var codec = Codec();
        string local = codec.CreateLocalPart(Ids.New(), Ids.New(), Now);

        Assert.Equal(58 + 2, local.Length);
        Assert.True(codec.TryDecode(local, Now, TimeSpan.FromDays(1), out var token));
        Assert.False(token.BoundToDestination);
        Assert.Equal(VerpDestinationCheck.Unbound, codec.CheckDestination(token, "anything.example"));
    }

    [Fact]
    public void A_version_1_token_cannot_be_turned_into_a_bound_one_by_changing_its_length_or_version_nibble()
    {
        var codec = Codec();
        string v1 = codec.CreateLocalPart(Ids.New(), Ids.New(), Now);
        string v2 = codec.CreateLocalPart(Ids.New(), Ids.New(), Now, "dest.example");

        // The version nibble is the first character's high bits: swap the first characters between the two kinds of token.
        Assert.False(codec.TryDecode("b+" + v2[2] + v1[3..], Now, TimeSpan.FromDays(1), out _));
        Assert.False(codec.TryDecode("b+" + v1[2] + v2[3..], Now, TimeSpan.FromDays(1), out _));
    }

    [Fact]
    public void Decoding_is_case_insensitive_because_mail_systems_fold_case()
    {
        var codec = Codec();
        string local = codec.CreateLocalPart(Ids.New(), Ids.New(), Now);
        Assert.True(codec.TryDecode(local.ToUpperInvariant(), Now, TimeSpan.FromDays(1), out _));
    }

    [Theory]
    [InlineData('k', '\u212A')] // Kelvin sign, lowercased to 'k' by char.ToLowerInvariant
    [InlineData('i', '\u0130')] // capital I with dot above
    [InlineData('s', '\u017F')] // long s, uppercased to 'S'
    public void A_non_ascii_look_alike_of_a_base32_letter_is_not_another_spelling_of_the_token(char ascii, char lookAlike)
    {
        var codec = Codec();
        string local = Enumerable.Range(0, 200)
            .Select(_ => codec.CreateLocalPart(Ids.New(), Ids.New(), Now))
            .First(l => l.IndexOf(ascii, 2) >= 0);
        int at = local.IndexOf(ascii, 2);
        string spoofed = string.Concat(local.AsSpan(0, at), lookAlike.ToString(), local.AsSpan(at + 1));

        Assert.True(codec.TryDecode(local, Now, TimeSpan.FromDays(1), out _));
        Assert.False(codec.TryDecode(spoofed, Now, TimeSpan.FromDays(1), out var token));
        Assert.Equal(default, token);
    }

    [Fact]
    public void Tampering_expiry_and_foreign_keys_are_rejected()
    {
        var codec = Codec();
        string local = codec.CreateLocalPart(Ids.New(), Ids.New(), Now);
        var chars = local.ToCharArray();
        for (int i = 2; i < chars.Length; i++)
        {
            var copy = (char[])chars.Clone();
            copy[i] = copy[i] == 'a' ? 'b' : 'a';
            Assert.False(codec.TryDecode(new string(copy), Now, TimeSpan.FromDays(1), out _), $"flip at {i}");
        }

        Assert.False(codec.TryDecode(local, Now.AddDays(20), TimeSpan.FromDays(14), out _));      // too old
        Assert.False(codec.TryDecode(local, Now.AddHours(-5), TimeSpan.FromDays(14), out _));      // from the future
        Assert.False(Codec().TryDecode(local, Now, TimeSpan.FromDays(1), out _));                  // other key
        Assert.False(codec.TryDecode("b+", Now, TimeSpan.FromDays(1), out _));
        Assert.False(codec.TryDecode("x+" + local[2..], Now, TimeSpan.FromDays(1), out _));
        Assert.False(codec.TryDecode(local + "a", Now, TimeSpan.FromDays(1), out _));
        Assert.False(codec.TryDecode("b+!!!!", Now, TimeSpan.FromDays(1), out _));
    }

    [Fact]
    public void Key_rotation_keeps_old_tokens_valid()
    {
        byte[] oldKey = VerpCodec.GenerateKey();
        var oldCodec = new VerpCodec(new Dictionary<int, byte[]> { [2] = oldKey }, 2);
        string local = oldCodec.CreateLocalPart(Ids.New(), Ids.New(), Now);
        var rotated = new VerpCodec(new Dictionary<int, byte[]> { [2] = oldKey, [3] = VerpCodec.GenerateKey() }, 3);
        Assert.True(rotated.TryDecode(local, Now, TimeSpan.FromDays(1), out var t));
        Assert.Equal(2, t.KeyId);
        Assert.StartsWith("b+", rotated.CreateLocalPart(Ids.New(), Ids.New(), Now));
        // Dropping the old key invalidates in-flight tokens.
        Assert.False(new VerpCodec(new Dictionary<int, byte[]> { [3] = VerpCodec.GenerateKey() }, 3).TryDecode(local, Now, TimeSpan.FromDays(1), out _));
    }

    [Fact]
    public void Random_input_never_throws()
    {
        var codec = Codec();
        var rng = new Random(5);
        for (int i = 0; i < 5000; i++)
        {
            var chars = new char[rng.Next(0, 80)];
            for (int j = 0; j < chars.Length; j++) { chars[j] = (char)rng.Next(32, 127); }
            codec.TryDecode(new string(chars), Now, TimeSpan.FromDays(1), out _);
            codec.TryDecode("b+" + new string(chars), Now, TimeSpan.FromDays(1), out _);
        }
    }
}
