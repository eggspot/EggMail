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
    public void Decoding_is_case_insensitive_because_mail_systems_fold_case()
    {
        var codec = Codec();
        string local = codec.CreateLocalPart(Ids.New(), Ids.New(), Now);
        Assert.True(codec.TryDecode(local.ToUpperInvariant(), Now, TimeSpan.FromDays(1), out _));
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
