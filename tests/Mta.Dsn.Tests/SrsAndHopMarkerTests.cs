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

        Assert.Matches(@"^SRS0=[a-z2-7]{8}=[a-z2-7]{2}=sender\.test=Bob\.Smith\+tag$", local);
        Assert.Equal(SrsCheck.Valid, srs.Verify(local, Now));
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
            Assert.Equal(SrsCheck.Invalid, srs.Verify(forged, Now));
        }

        Assert.Equal(SrsCheck.Valid, srs.Verify(valid.ToUpperInvariant(), Now));   // a server that folds case does not break it
    }

    [Fact]
    public void An_address_is_valid_for_the_configured_number_of_days_and_a_day_ahead_and_then_expired_across_the_wrap_of_the_day_counter()
    {
        var srs = new SrsCodec(Ring(1), maxAgeDays: 21);
        string local = srs.CreateLocalPart("sender.test", "bob", Now);

        Assert.Equal(SrsCheck.Valid, srs.Verify(local, Now.AddDays(21).AddHours(11)));
        Assert.Equal(SrsCheck.Expired, srs.Verify(local, Now.AddDays(22)));
        Assert.Equal(SrsCheck.Expired, srs.Verify(local, Now.AddDays(200)));
        Assert.Equal(SrsCheck.Valid, srs.Verify(local, Now.AddDays(-1)));   // clocks and time zones: a day early is fine
        Assert.Equal(SrsCheck.Expired, srs.Verify(local, Now.AddDays(-5)));
        Assert.Equal(SrsCheck.Valid, srs.Verify(srs.CreateLocalPart("sender.test", "bob", Now.AddDays(1020)), Now.AddDays(1030)));   // the counter wraps every 1024 days
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
        Assert.Equal(SrsCheck.Valid, srs.Verify(local, Now));
        Assert.NotEqual(local[^32..], srs.CreateLocalPart(longDomain, longLocal[..63] + "b", Now)[^32..]);   // the digest covers the original domain and local part
        Assert.NotEqual(local[^32..], srs.CreateLocalPart(longDomain + "m", longLocal, Now)[^32..]);
        Assert.Equal(SrsCheck.Invalid, srs.Verify(local[..^1] + (local[^1] == '0' ? '1' : '0'), Now));
    }

    [Fact]
    public void A_rotated_key_does_not_invalidate_addresses_in_flight_but_a_stranger_key_does()
    {
        var oldKey = VerpCodec.GenerateKey();
        var before = new SrsCodec(new VerpCodec(new Dictionary<int, byte[]> { [1] = oldKey }, 1));
        string local = before.CreateLocalPart("sender.test", "bob", Now);

        var after = new SrsCodec(new VerpCodec(new Dictionary<int, byte[]> { [1] = oldKey, [2] = VerpCodec.GenerateKey() }, 2));
        Assert.Equal(SrsCheck.Valid, after.Verify(local, Now));   // the old key is still in the ring
        Assert.Equal(SrsCheck.Invalid, before.Verify(after.CreateLocalPart("sender.test", "bob", Now), Now));   // a ring without key 2 cannot read the new key's addresses

        var stranger = new SrsCodec(Ring(1));
        Assert.Equal(SrsCheck.Invalid, stranger.Verify(local, Now));
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
}
