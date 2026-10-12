namespace Mta.Mime.Tests;

public class MimeDateTests
{
    [Theory]
    [InlineData("Mon, 05 Oct 2026 14:03:09 +0200", "2026-10-05T14:03:09+02:00")]
    [InlineData("5 Oct 2026 14:03 +0000", "2026-10-05T14:03:00+00:00")]
    [InlineData("Mon, 5 Oct 2026 14:03:09 -0530", "2026-10-05T14:03:09-05:30")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 GMT", "2026-10-05T14:03:09+00:00")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 UT", "2026-10-05T14:03:09+00:00")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 EST", "2026-10-05T14:03:09-05:00")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 EDT", "2026-10-05T14:03:09-04:00")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 CST", "2026-10-05T14:03:09-06:00")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 PDT", "2026-10-05T14:03:09-07:00")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 MST", "2026-10-05T14:03:09-07:00")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 Z", "2026-10-05T14:03:09+00:00")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 J", "2026-10-05T14:03:09+00:00")]
    [InlineData("Mon, 05 Oct 26 14:03:09 +0000", "2026-10-05T14:03:09+00:00")]
    [InlineData("Mon, 05 Oct 99 14:03:09 +0000", "1999-10-05T14:03:09+00:00")]
    [InlineData("Mon, 05 Oct 126 14:03:09 +0000", "2026-10-05T14:03:09+00:00")]
    [InlineData("Mon, 05 Oct 2026 14:03:09", "2026-10-05T14:03:09+00:00")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 +0200 (CEST)", "2026-10-05T14:03:09+02:00")]
    [InlineData("(c) Mon, (c) 05 Oct 2026 14:03:09 +0200", "2026-10-05T14:03:09+02:00")]
    [InlineData("mon, 05 OCT 2026 14:03:09 +0200", "2026-10-05T14:03:09+02:00")]
    [InlineData("Tue, 29 Feb 2028 23:59:60 +0000", "2028-02-29T23:59:59+00:00")]
    [InlineData("05 Oct 2026 14:03:09 +02", "2026-10-05T14:03:09+02:00")]
    public void Parses(string text, string expectedIso)
    {
        Assert.True(MimeDate.TryParse(text, out var value), text);
        Assert.Equal(DateTimeOffset.Parse(expectedIso, System.Globalization.CultureInfo.InvariantCulture), value);
        Assert.Equal(DateTimeOffset.Parse(expectedIso, System.Globalization.CultureInfo.InvariantCulture).Offset, value.Offset);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a date")]
    [InlineData("Mon, 32 Oct 2026 14:03:09 +0000")]
    [InlineData("Mon, 05 Foo 2026 14:03:09 +0000")]
    [InlineData("Mon, 05 Oct 2026 25:03:09 +0000")]
    [InlineData("Mon, 05 Oct 2026 14:61:09 +0000")]
    [InlineData("Mon, 31 Feb 2026 14:03:09 +0000")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 +9900")]
    [InlineData("Mon, 05 Oct 2026 14:03:09 +1")]
    [InlineData("Mon, 05 Oct 2026")]
    [InlineData("14:03:09")]
    public void Rejects(string text) => Assert.False(MimeDate.TryParse(text, out _), text);

    [Fact]
    public void Null_is_rejected() => Assert.False(MimeDate.TryParse((string?)null, out _));

    [Fact]
    public void Formats_rfc5322()
    {
        var d = new DateTimeOffset(2026, 10, 5, 14, 3, 9, TimeSpan.FromHours(2));
        Assert.Equal("Mon, 05 Oct 2026 14:03:09 +0200", MimeDate.Format(d));
        Assert.Equal("Sun, 01 Jan 2023 00:00:00 +0000", MimeDate.Format(new DateTimeOffset(2023, 1, 1, 0, 0, 0, TimeSpan.Zero)));
        Assert.Equal("Wed, 31 Dec 2025 23:59:59 -0930", MimeDate.Format(new DateTimeOffset(2025, 12, 31, 23, 59, 59, TimeSpan.FromMinutes(-570))));
    }

    [Fact]
    public void Format_always_uses_english_names_and_round_trips()
    {
        var saved = System.Globalization.CultureInfo.CurrentCulture;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("de-DE");
            var d = new DateTimeOffset(2026, 3, 4, 5, 6, 7, TimeSpan.FromMinutes(330));
            string s = MimeDate.Format(d);
            Assert.Equal("Wed, 04 Mar 2026 05:06:07 +0530", s);
            Assert.True(MimeDate.TryParse(s, out var back));
            Assert.Equal(d, back);
            Assert.Equal(d.Offset, back.Offset);
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = saved;
        }
    }

    [Fact]
    public void TryFormat_needs_enough_space()
    {
        Span<char> small = stackalloc char[10];
        Assert.False(MimeDate.TryFormat(DateTimeOffset.UnixEpoch, small, out int written));
        Assert.Equal(0, written);
        Span<char> enough = stackalloc char[MimeDate.MaxFormattedLength];
        Assert.True(MimeDate.TryFormat(DateTimeOffset.UnixEpoch, enough, out written));
        Assert.Equal("Thu, 01 Jan 1970 00:00:00 +0000", enough[..written].ToString());
    }

    [Fact]
    public void Pathological_input_terminates()
    {
        Assert.False(MimeDate.TryParse(new string('(', 100_000), out _));
        Assert.False(MimeDate.TryParse(new string('9', 100_000), out _));
    }
}
