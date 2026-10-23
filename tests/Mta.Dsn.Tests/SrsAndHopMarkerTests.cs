using System.Text;

namespace Mta.Dsn.Tests;

public class SrsAndHopMarkerTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 16, 12, 0, 0, TimeSpan.Zero);

    private static VerpCodec Ring(params int[] ids) => new(ids.ToDictionary(i => i, _ => VerpCodec.GenerateKey()), ids[0]);

    // ------------------------------------------------------------------ SRS

    [Fact]
    public void An_address_is_srs0_with_a_hash_a_two_character_day_and_the_original_domain_and_local_part()
    {
        var srs = new SrsCodec(Ring(1));

        string local = srs.CreateLocalPart("Sender.Test", "Bob.Smith+tag", Now);

        Assert.Matches(@"^SRS0=[a-z2-7]{8}=[a-z2-7]{2}=sender\.test=bob\.smith\+tag$", local);
        Assert.True(srs.TryVerify(local, Now));
        Assert.Equal(local + "@forward.example", srs.CreateAddress("sender.test", "Bob.Smith+tag", "forward.example", Now));
    }

    [Fact]
    public void A_hash_that_does_not_verify_is_invalid_whatever_part_was_changed()
    {
        var srs = new SrsCodec(Ring(1));
        string valid = srs.CreateLocalPart("sender.test", "bob", Now);

        foreach (string forged in new[]
        {
            valid.Replace("sender.test", "sender.tesu", StringComparison.Ordinal),
            valid.Replace("=bob", "=rob", StringComparison.Ordinal),
            valid[..5] + (valid[5] == 'a' ? 'b' : 'a') + valid[6..],
            valid[..14] + (valid[14] == 'a' ? 'b' : 'a') + valid[15..],   // the day
            valid + "x",
            valid[..^1],
            "SRS0=",
            "SRS0=abcdefgh=ab=x",
            "SRS1=" + valid[5..],
            "bob",
        })
        {
            Assert.False(srs.TryVerify(forged, Now));
        }

        Assert.True(srs.TryVerify(valid.ToUpperInvariant(), Now));   // a server that folds case does not break it
    }

    [Fact]
    public void An_address_is_valid_for_the_configured_number_of_days_and_a_day_ahead_and_then_expired_across_the_wrap_of_the_day_counter()
    {
        var srs = new SrsCodec(Ring(1), maxAgeDays: 21);
        string local = srs.CreateLocalPart("sender.test", "bob", Now);

        Assert.True(srs.TryVerify(local, Now.AddDays(20).AddHours(11)));   // the current day and the 20 before it: 21 days in all
        Assert.False(srs.TryVerify(local, Now.AddDays(21)));
        Assert.False(srs.TryVerify(local, Now.AddDays(200)));
        Assert.False(srs.TryVerify(local, Now.AddDays(-1)));   // dated in the future (the same clock made it): not valid
        Assert.False(srs.TryVerify(local, Now.AddDays(-5)));
        Assert.True(srs.TryVerify(srs.CreateLocalPart("sender.test", "bob", Now.AddDays(1020)), Now.AddDays(1030)));   // the counter wraps every 1024 days
    }

    [Fact]
    public void A_long_original_address_is_shortened_to_at_most_64_octets_and_is_still_verified()
    {
        var srs = new SrsCodec(Ring(1));
        string longLocal = new('a', 64);
        string longDomain = string.Join('.', Enumerable.Repeat(new string('d', 60), 4)) + ".test";

        string local = srs.CreateLocalPart(longDomain, longLocal, Now);

        Assert.True(local.Length <= 64);
        Assert.Matches(@"^SRS0=[a-z2-7]{8}=[a-z2-7]{2}=x=[0-9a-f]{32}$", local);
        Assert.Equal(51, local.Length);
        Assert.True(srs.TryVerify(local, Now));
        Assert.NotEqual(local[^32..], srs.CreateLocalPart(longDomain, longLocal[..63] + "b", Now)[^32..]);   // the digest covers the original domain and local part
        Assert.NotEqual(local[^32..], srs.CreateLocalPart(longDomain + "m", longLocal, Now)[^32..]);
        Assert.False(srs.TryVerify(local[..^1] + (local[^1] == '0' ? '1' : '0'), Now));
    }

    [Fact]
    public void A_rotated_key_does_not_invalidate_addresses_in_flight_but_a_stranger_key_does()
    {
        var oldKey = VerpCodec.GenerateKey();
        var before = new SrsCodec(new VerpCodec(new Dictionary<int, byte[]> { [1] = oldKey }, 1));
        string local = before.CreateLocalPart("sender.test", "bob", Now);

        var after = new SrsCodec(new VerpCodec(new Dictionary<int, byte[]> { [1] = oldKey, [2] = VerpCodec.GenerateKey() }, 2));
        Assert.True(after.TryVerify(local, Now));   // the old key is still in the ring
        Assert.False(before.TryVerify(after.CreateLocalPart("sender.test", "bob", Now), Now));   // a ring without key 2 cannot read the new key's addresses

        var stranger = new SrsCodec(Ring(1));
        Assert.False(stranger.TryVerify(local, Now));
    }

    // ------------------------------------------------------------------ hop marker

    [Fact]
    public void A_marker_verifies_for_the_body_it_was_made_for_and_for_no_other()
    {
        var hops = new ForwardHopMarker(Ring(1));
        string hash = ForwardHopMarker.BodyHash(Encoding.UTF8.GetBytes("body\r\n"));

        string value = hops.CreateValue(2, hash);

        Assert.Matches(@"^2; [0-9a-f]{16}$", value);
        Assert.True(hops.TryVerify(value, hash, out int count));
        Assert.Equal(2, count);
        Assert.False(hops.TryVerify(value, ForwardHopMarker.BodyHash(Encoding.UTF8.GetBytes("other\r\n")), out _));
        Assert.False(hops.TryVerify(value.Replace("2;", "1;", StringComparison.Ordinal), hash, out _));   // the count is signed
        Assert.True(hops.TryVerify("  " + value + " ", hash, out _));   // surrounding white space is tolerated
    }

    [Theory]
    [InlineData("")]
    [InlineData("3")]
    [InlineData("3;")]
    [InlineData("; 0123456789abcdef")]
    [InlineData("x; 0123456789abcdef")]
    [InlineData("-1; 0123456789abcdef")]
    [InlineData("99999; 0123456789abcdef")]
    [InlineData("3; 0123456789abcde")]
    [InlineData("3; 0123456789abcdef0")]
    public void A_malformed_or_forged_marker_never_verifies(string value)
    {
        var hops = new ForwardHopMarker(Ring(1));

        Assert.False(hops.TryVerify(value, ForwardHopMarker.BodyHash("body"u8), out int count));
        Assert.Equal(0, count);
    }

    [Fact]
    public void The_marker_is_verified_under_every_key_of_the_ring_and_signed_with_the_active_one()
    {
        byte[] oldKey = VerpCodec.GenerateKey();
        string hash = ForwardHopMarker.BodyHash("body"u8);
        string fromOld = new ForwardHopMarker(new VerpCodec(new Dictionary<int, byte[]> { [1] = oldKey }, 1)).CreateValue(1, hash);
        var rotated = new ForwardHopMarker(new VerpCodec(new Dictionary<int, byte[]> { [1] = oldKey, [2] = VerpCodec.GenerateKey() }, 2));

        Assert.True(rotated.TryVerify(fromOld, hash, out _));
        Assert.NotEqual(fromOld, rotated.CreateValue(1, hash));   // new markers are signed with key 2
        Assert.False(new ForwardHopMarker(Ring(1)).TryVerify(fromOld, hash, out _));
    }

    [Fact]
    public void The_srs_key_and_the_hop_key_are_not_the_bounce_token_key_and_not_each_other()
    {
        VerpCodec ring = Ring(1);
        byte[] srs = ring.DeriveKey(1, SrsCodec.Purpose);
        byte[] hops = ring.DeriveKey(1, ForwardHopMarker.Purpose);

        Assert.Equal(32, srs.Length);
        Assert.NotEqual(srs, hops);
        Assert.NotEqual(srs, ring.DeriveKey(1, "other"));
        Assert.Equal(srs, ring.DeriveKey(1, SrsCodec.Purpose));
        Assert.NotEqual(srs, Ring(1).DeriveKey(1, SrsCodec.Purpose));
    }

    // ------------------------------------------------------------------ octets, quoting, boundaries

    [Theory]
    [InlineData("bob smith")]            // would need quoting
    [InlineData("\"bob\"")]
    [InlineData("b@b")]
    [InlineData("a..b")]
    [InlineData(".bob")]
    [InlineData("bob.")]
    [InlineData("b=b")]                  // the separator inside the local part
    [InlineData("bj\u00f6rn")]            // not ASCII: one character, two octets
    [InlineData("\u65e5\u672c\u8a9e")]
    public void An_original_local_part_that_is_not_plain_gets_the_short_form_whose_length_is_in_octets(string original)
    {
        var srs = new SrsCodec(Ring(1));

        string local = srs.CreateLocalPart("sender.test", original, Now);

        Assert.Matches(@"^SRS0=[a-z2-7]{8}=[a-z2-7]{2}=x=[0-9a-f]{32}$", local);
        Assert.True(Encoding.UTF8.GetByteCount(local) <= SrsCodec.MaxLocalPartLength);
        Assert.True(srs.TryVerify(local, Now));
        Assert.NotEqual(local[^32..], srs.CreateLocalPart("sender.test", original + "x", Now)[^32..]);
    }

    [Fact]
    public void A_non_ascii_internationalized_domain_uses_the_short_form_and_an_address_with_non_ascii_never_verifies()
    {
        var srs = new SrsCodec(Ring(1));

        string local = srs.CreateLocalPart("b\u00fccher.example", "bob", Now);

        Assert.StartsWith("SRS0=", local, StringComparison.Ordinal);
        Assert.Contains("=x=", local, StringComparison.Ordinal);
        Assert.True(srs.TryVerify(local, Now));
        // 40 octets of two-octet characters is 80 octets: over the limit although it is only 40 characters; and it is not something we issue.
        Assert.False(srs.TryVerify("SRS0=abcdefgh=ab=" + new string('\u00e4', 20) + "=bob", Now));
        Assert.False(srs.TryVerify("SRS0=abcdefgh=ab=sender.test=" + new string('a', 45), Now));   // 66 octets
    }

    [Fact]
    public void The_fields_are_separated_in_the_hash_so_moving_a_character_between_domain_and_local_part_does_not_verify()
    {
        var srs = new SrsCodec(Ring(1));
        string local = srs.CreateLocalPart("ab.test", "cd", Now);   // SRS0=hash=tt=ab.test=cd
        string moved = local.Replace("=ab.test=cd", "=ab.testc=d", StringComparison.Ordinal);

        Assert.True(srs.TryVerify(local, Now));
        Assert.False(srs.TryVerify(moved, Now));
    }

    [Fact]
    public void The_age_can_be_set_and_the_explicit_overload_wins()
    {
        var strict = new SrsCodec(Ring(1), maxAgeDays: 2);
        string local = strict.CreateLocalPart("sender.test", "bob", Now);

        Assert.True(strict.TryVerify(local, Now.AddDays(1)));
        Assert.False(strict.TryVerify(local, Now.AddDays(2)));
        Assert.True(strict.TryVerify(local, Now.AddDays(2), maxAgeDays: 5));
        Assert.True(SrsCodec.HasSrsPrefix("srs1=x"));
        Assert.False(SrsCodec.HasSrsPrefix("sr=x"));
    }

    [Fact]
    public void The_hop_count_is_one_to_three_digits_and_the_message_level_helpers_agree_with_the_field_check()
    {
        var hops = new ForwardHopMarker(Ring(1));
        byte[] message = Encoding.ASCII.GetBytes("From: a@sender.test\r\nSubject: s\r\n\r\nbody\r\n");

        byte[] once = hops.Apply(message, 1);
        byte[] twice = hops.Apply(once, 2);

        Assert.Equal(0, hops.ReadValidHops(message));
        Assert.Equal(1, hops.ReadValidHops(once));
        Assert.Equal(2, hops.ReadValidHops(twice));
        Assert.Equal(1, Encoding.ASCII.GetString(twice).Split("X-EggMail-Hops").Length - 1);   // a forward replaces the marker, it never adds a second one
        string hash = ForwardHopMarker.BodyHash("x"u8);
        Assert.True(hops.TryVerify(hops.CreateValue(999, hash), hash, out int n) && n == 999);
        Assert.False(hops.TryVerify(hops.CreateValue(1000, hash), hash, out _));   // four digits
        Assert.False(hops.TryVerify("0; " + hops.CreateValue(0, hash).Split("; ")[1], hash, out _));
        Assert.Equal(3, ForwardHopMarker.MaxHops);
    }

    // ------------------------------------------------------------------ a ring whose key set is replaced (rotation, decision 110)

    [Fact]
    public void After_the_ring_is_replaced_srs_and_the_hop_marker_sign_with_the_new_key_and_verify_with_every_key_it_holds()
    {
        byte[] oldKey = VerpCodec.GenerateKey();
        byte[] newKey = VerpCodec.GenerateKey();
        var ring = new VerpCodec(new Dictionary<int, byte[]> { [1] = oldKey }, 1);
        var srs = new SrsCodec(ring);
        var hops = new ForwardHopMarker(ring);
        string hash = ForwardHopMarker.BodyHash(Encoding.UTF8.GetBytes("body\r\n"));
        string oldAddress = srs.CreateLocalPart("sender.test", "bob", Now);
        string oldMarker = hops.CreateValue(1, hash);

        ring.Replace(new Dictionary<int, byte[]> { [1] = oldKey, [2] = newKey }, 2);

        var newOnly = new VerpCodec(new Dictionary<int, byte[]> { [2] = newKey }, 2);
        string newAddress = srs.CreateLocalPart("sender.test", "bob", Now);
        Assert.Equal(new SrsCodec(newOnly).CreateLocalPart("sender.test", "bob", Now), newAddress);   // signed with key 2
        Assert.Equal(new ForwardHopMarker(newOnly).CreateValue(1, hash), hops.CreateValue(1, hash));
        Assert.True(srs.TryVerify(oldAddress, Now), "an address of the retired key verifies while the ring holds it");
        Assert.True(srs.TryVerify(newAddress, Now));
        Assert.True(hops.TryVerify(oldMarker, hash, out _));

        // The old key is pruned: what it signed no longer verifies.
        ring.Replace(new Dictionary<int, byte[]> { [2] = newKey }, 2);
        Assert.False(srs.TryVerify(oldAddress, Now));
        Assert.False(hops.TryVerify(oldMarker, hash, out _));
        Assert.True(srs.TryVerify(newAddress, Now));
    }
}
