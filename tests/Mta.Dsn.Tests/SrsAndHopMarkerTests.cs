using System.Text;
using System.Text.RegularExpressions;
using Mta.Dsn;

namespace Mta.Dsn.Tests;

/// <summary>The stateless codecs of forwarded mail (design section 11.7): the SRS0 envelope sender and the signed hop marker.</summary>
public class SrsAndHopMarkerTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 16, 8, 0, 0, TimeSpan.Zero);

    private static VerpCodec Ring(params int[] ids) => new(ids.ToDictionary(i => i, _ => VerpCodec.GenerateKey()), ids[^1]);

    // SRS

    [Fact]
    public void A_short_address_is_the_long_form_and_verifies()
    {
        var srs = new SrsCodec(Ring(1));
        string local = srs.CreateLocalPart("Sender.Test", "Alice", Now);

        Assert.StartsWith("SRS0=", local, StringComparison.Ordinal);
        Assert.EndsWith("=sender.test=alice", local, StringComparison.Ordinal);
        Assert.True(srs.TryVerify(local, Now));
        Assert.True(srs.TryVerify(local.ToUpperInvariant(), Now));   // relays fold case
    }

    [Theory]
    [InlineData("a-very-long-domain-name-that-goes-on.and-on.example.org", "and-a-very-long-local-part-too")]
    [InlineData("x.test", "ünïcode")]
    [InlineData("x.test", "with space")]
    [InlineData("x.test", "dots..inside")]
    [InlineData("x.test", "trailing.")]
    [InlineData("x.test", "a=b=c")]
    public void A_long_or_awkward_original_gives_the_short_form_of_at_most_64_octets_that_verifies(string domain, string local)
    {
        var srs = new SrsCodec(Ring(1));
        string made = srs.CreateLocalPart(domain, local, Now);

        Assert.True(made.Length <= 64, made);
        Assert.True(srs.TryVerify(made, Now));
        Assert.All(made, c => Assert.True(c is > ' ' and < '\u007f'));
    }

    [Fact]
    public void Whatever_the_original_the_address_is_at_most_64_octets()
    {
        var srs = new SrsCodec(Ring(1));
        string huge = new string('a', 255) + ".example";
        Assert.True(srs.CreateLocalPart(huge, new string('l', 64), Now).Length <= 64);
        Assert.True(srs.CreateLocalPart("d.test", new string('l', 64), Now).Length <= 64);
        Assert.True(srs.CreateLocalPart("d.test", "", Now).Length <= 64);
    }

    [Fact]
    public void The_short_form_is_bound_to_the_original_so_it_is_not_a_token_for_anything_else()
    {
        var srs = new SrsCodec(Ring(1));
        string one = srs.CreateLocalPart("x.test", "ünïcode", Now);
        string two = srs.CreateLocalPart("x.test", "ünïcodE-other", Now);
        Assert.NotEqual(one, two);

        // Changing a field of a valid address invalidates it.
        string[] parts = one.Split('=');
        Assert.False(srs.TryVerify(string.Join('=', parts[0], parts[1], parts[2], parts[3], new string('0', 32)), Now));
        Assert.False(srs.TryVerify(string.Join('=', parts[0], parts[1], parts[2], "y", parts[4]), Now));
    }

    [Fact]
    public void An_address_expires_after_the_window_and_is_never_dated_in_the_future()
    {
        var srs = new SrsCodec(Ring(1));
        string local = srs.CreateLocalPart("sender.test", "alice", Now);

        Assert.True(srs.TryVerify(local, Now.AddDays(20)));
        Assert.False(srs.TryVerify(local, Now.AddDays(21)));
        Assert.False(srs.TryVerify(local, Now.AddDays(-1)));
        Assert.False(srs.TryVerify(local, Now.AddDays(21 + 1024)));   // the day number wraps; a year-old address is not the same as a recent one only by accident of the modulus
    }

    [Fact]
    public void Forged_malformed_and_foreign_addresses_do_not_verify()
    {
        var srs = new SrsCodec(Ring(1));
        var other = new SrsCodec(Ring(1));   // another deployment: another key
        string local = srs.CreateLocalPart("sender.test", "alice", Now);

        Assert.False(other.TryVerify(local, Now));
        Assert.False(srs.TryVerify("SRS0=aaaaaaaa=aa=sender.test=alice", Now));
        Assert.False(srs.TryVerify("SRS1=" + local[5..], Now));   // this server issues no SRS1 address
        foreach (string bad in new[] { "", "SRS0=", "SRS0=a=b=c=d", "SRS0=1111111=aa=d=l", "SRS0=zzzzzzzz=!!=d=l", "SRS0=aaaaaaaa=aa==x", "plain", "b+token" })
        {
            Assert.False(srs.TryVerify(bad, Now), bad);
        }

        Assert.False(srs.TryVerify(new string('x', 600), Now));
    }

    [Fact]
    public void Rotating_the_ring_keeps_addresses_in_flight_valid()
    {
        var oldKey = VerpCodec.GenerateKey();
        var before = new SrsCodec(new VerpCodec(new Dictionary<int, byte[]> { [2] = oldKey }, 2));
        string inFlight = before.CreateLocalPart("sender.test", "alice", Now);

        var rotated = new SrsCodec(new VerpCodec(new Dictionary<int, byte[]> { [2] = oldKey, [3] = VerpCodec.GenerateKey() }, 3));
        Assert.True(rotated.TryVerify(inFlight, Now));
        Assert.NotEqual(before.CreateLocalPart("sender.test", "alice", Now), rotated.CreateLocalPart("sender.test", "alice", Now));   // new ones use the new key

        var dropped = new SrsCodec(new VerpCodec(new Dictionary<int, byte[]> { [3] = VerpCodec.GenerateKey() }, 3));
        Assert.False(dropped.TryVerify(inFlight, Now));
    }

    [Fact]
    public void The_srs_key_is_not_the_bounce_key_and_a_bounce_token_is_not_an_srs_address()
    {
        VerpCodec ring = Ring(1);
        Assert.NotEqual(ring.DeriveKey(1, SrsCodec.Purpose), ring.DeriveKey(1, ForwardHopMarker.Purpose));
        Assert.False(new SrsCodec(ring).TryVerify(ring.CreateLocalPart(Guid.NewGuid(), Guid.NewGuid(), Now, "x.test"), Now));
        Assert.True(SrsCodec.HasSrsPrefix("srs0=abc"));
        Assert.True(SrsCodec.HasSrsPrefix("SRS1=abc"));
        Assert.False(SrsCodec.HasSrsPrefix("b+abc"));
    }

    // Hop marker

    private static byte[] Message(string extraHeaders = "", string body = "Hello\r\nworld\r\n") =>
        Encoding.UTF8.GetBytes("Received: from a by b\r\nFrom: x@other.test\r\nSubject: s\r\n" + extraHeaders + "\r\n" + body);

    [Fact]
    public void A_forward_writes_one_marker_that_proves_the_count_for_this_body()
    {
        var marker = new ForwardHopMarker(Ring(1));
        byte[] original = Message();
        Assert.Equal(0, marker.ReadValidHops(original));

        byte[] first = marker.Apply(original, 1);
        Assert.Equal(1, marker.ReadValidHops(first));
        Assert.StartsWith("X-EggMail-Hops: 1; ", Encoding.UTF8.GetString(first), StringComparison.Ordinal);
        Assert.EndsWith(Encoding.UTF8.GetString(original), Encoding.UTF8.GetString(first), StringComparison.Ordinal);   // everything else, the body byte for byte, is untouched
    }

    [Fact]
    public void A_forward_replaces_the_old_marker_and_the_message_never_carries_two()
    {
        var marker = new ForwardHopMarker(Ring(1));
        byte[] once = marker.Apply(Message(), 1);
        byte[] twice = marker.Apply(once, 2);

        Assert.Equal(2, marker.ReadValidHops(twice));
        Assert.Single(Regex.Matches(Encoding.UTF8.GetString(twice), "(?im)^X-EggMail-Hops:"));
    }

    [Fact]
    public void A_forged_marker_or_a_changed_body_counts_for_nothing()
    {
        var marker = new ForwardHopMarker(Ring(1));
        byte[] valid = marker.Apply(Message(), 2);
        string text = Encoding.UTF8.GetString(valid);

        // The sender cannot lower the count by dropping the header (it is just zero), cannot raise it with a made-up signature, and cannot reuse a signature on another body.
        Assert.Equal(0, marker.ReadValidHops(Message("X-EggMail-Hops: 99; 0123456789abcdef\r\n")));
        Assert.Equal(0, marker.ReadValidHops(Encoding.UTF8.GetBytes(text.Replace("Hello", "Hullo", StringComparison.Ordinal))));
        Assert.Equal(0, marker.ReadValidHops(Encoding.UTF8.GetBytes(text.Replace("; ", "; 0", StringComparison.Ordinal))));
        Assert.Equal(0, marker.ReadValidHops(Message("X-EggMail-Hops: 1\r\n")));
        Assert.Equal(0, marker.ReadValidHops(Message("X-EggMail-Hops: ; \r\n")));
        Assert.Equal(0, marker.ReadValidHops(new ForwardHopMarker(Ring(1)).Apply(Message(), 2)));   // another deployment's marker
    }

    [Fact]
    public void Of_several_markers_the_highest_valid_one_counts_and_a_forged_high_one_is_ignored()
    {
        var marker = new ForwardHopMarker(Ring(1));
        byte[] body = Encoding.UTF8.GetBytes("body\r\n");
        string one = marker.CreateValue(1, body);
        string two = marker.CreateValue(2, body);
        byte[] message = Encoding.UTF8.GetBytes($"X-EggMail-Hops: {one}\r\nX-EggMail-Hops: 9; ffffffffffffffff\r\nX-EggMail-Hops: {two}\r\nFrom: a@b.test\r\n\r\nbody\r\n");

        Assert.Equal(2, marker.ReadValidHops(message));
        byte[] next = marker.Apply(message, 3);
        Assert.Equal(3, marker.ReadValidHops(next));
        Assert.Single(Regex.Matches(Encoding.UTF8.GetString(next), "(?im)^X-EggMail-Hops:"));
    }

    [Fact]
    public void A_folded_marker_is_read_and_removed_whole()
    {
        var marker = new ForwardHopMarker(Ring(1));
        string value = marker.CreateValue(1, Encoding.UTF8.GetBytes("b\r\n"));
        string folded = value.Replace("; ", ";\r\n ", StringComparison.Ordinal);
        byte[] message = Encoding.UTF8.GetBytes($"X-EggMail-Hops: {folded}\r\nFrom: a@b.test\r\n\r\nb\r\n");

        Assert.Equal(1, marker.ReadValidHops(message));
        string result = Encoding.UTF8.GetString(marker.Apply(message, 2));
        Assert.DoesNotContain(folded, result, StringComparison.Ordinal);
        Assert.Single(Regex.Matches(result, "(?im)^X-EggMail-Hops:"));
    }

    [Fact]
    public void A_message_without_a_body_or_headers_is_handled()
    {
        var marker = new ForwardHopMarker(Ring(1));
        Assert.Equal(0, marker.ReadValidHops([]));
        Assert.Equal(1, marker.ReadValidHops(marker.Apply(Encoding.UTF8.GetBytes("From: a@b.test\r\n\r\n"), 1)));
        Assert.Equal(1, marker.ReadValidHops(marker.Apply(Encoding.UTF8.GetBytes("\r\nbody"), 1)));
    }

    [Fact]
    public void Rotating_the_ring_keeps_markers_valid()
    {
        var oldKey = VerpCodec.GenerateKey();
        var before = new ForwardHopMarker(new VerpCodec(new Dictionary<int, byte[]> { [2] = oldKey }, 2));
        byte[] message = before.Apply(Message(), 2);
        var rotated = new ForwardHopMarker(new VerpCodec(new Dictionary<int, byte[]> { [2] = oldKey, [3] = VerpCodec.GenerateKey() }, 3));
        Assert.Equal(2, rotated.ReadValidHops(message));
    }
}
