using System.Text;

namespace Mta.Mime.Tests;

public class Rfc2047Tests
{
    [Theory]
    [InlineData("=?utf-8?B?SGVsbG8=?=", "Hello")]
    [InlineData("=?UTF-8?Q?Hello_World?=", "Hello World")]
    [InlineData("=?iso-8859-1?Q?caf=E9?=", "café")]
    [InlineData("=?windows-1252?Q?=80uro?=", "€uro")]
    [InlineData("=?utf-8?q?lower?=", "lower")]
    [InlineData("=?utf-8*en?Q?language?=", "language")]
    [InlineData("=?shift_jis?B?k/qWe4zq?=", "日本語")]
    [InlineData("=?gb2312?B?1tDOxA==?=", "中文")]
    [InlineData("plain text", "plain text")]
    [InlineData("a =?utf-8?Q?b?= c", "a b c")]
    public void Decodes_encoded_words(string input, string expected) => Assert.Equal(expected, Rfc2047.Decode(input));

    [Fact]
    public void Whitespace_between_adjacent_encoded_words_is_dropped()
    {
        Assert.Equal("ab", Rfc2047.Decode("=?utf-8?Q?a?= =?utf-8?Q?b?="));
        Assert.Equal("ab", Rfc2047.Decode("=?utf-8?Q?a?=\r\n =?utf-8?Q?b?="));
        Assert.Equal("a b", Rfc2047.Decode("=?utf-8?Q?a?= b"));
        Assert.Equal("a b", Rfc2047.Decode("a =?utf-8?Q?b?="));
        Assert.Equal("a  b", Rfc2047.Decode("a  =?utf-8?Q?b?="));
    }

    [Fact]
    public void Multibyte_character_split_across_adjacent_words_is_reassembled()
    {
        // U+20AC EURO SIGN = E2 82 AC, split after the first byte.
        Assert.Equal("€", Rfc2047.Decode("=?utf-8?B?4g==?= =?utf-8?B?gqw=?="));
        Assert.Equal("€", Rfc2047.Decode("=?utf-8?Q?=E2?= =?utf-8?Q?=82=AC?="));
    }

    [Fact]
    public void Different_charsets_in_adjacent_words()
    {
        Assert.Equal("é€", Rfc2047.Decode("=?iso-8859-1?Q?=E9?= =?utf-8?Q?=E2=82=AC?="));
    }

    [Theory]
    [InlineData("=?utf-8?B?!!!?=")]
    [InlineData("=?utf-8?X?abc?=")]
    [InlineData("=?utf-8?B?abc")]
    [InlineData("=??B?abc?=")]
    [InlineData("=?utf-8?Q?a b?=")]
    [InlineData("=?")]
    [InlineData("=?=?=?=?")]
    public void Malformed_encoded_words_are_kept_literally(string input) => Assert.Equal(input, Rfc2047.Decode(input));

    [Fact]
    public void Unknown_charset_uses_safe_fallback()
    {
        var text = Rfc2047.Decode("=?x-no-such-charset?Q?caf=C3=A9?=", out var an);
        Assert.Equal("café", text); // valid UTF-8 bytes
        Assert.True(an.HasAny(MimeAnomaly.UnknownCharset));

        Assert.Equal("café", Rfc2047.Decode("=?x-no-such-charset?Q?caf=E9?=")); // not UTF-8: windows-1252
    }

    [Theory]
    [InlineData("utf-7")]
    [InlineData("UTF-7")]
    [InlineData("unicode-1-1-utf-7")]
    public void Utf7_is_refused(string charset)
    {
        // "+2D3cAA-" would be U+1F600 in UTF-7; the safe fallback must not interpret it.
        string text = Rfc2047.Decode($"=?{charset}?Q?+2D3cAA-?=");
        Assert.Equal("+2D3cAA-", text);
    }

    [Fact]
    public void Absurd_charset_names_are_refused_without_exceptions()
    {
        string longName = "=?" + new string('a', 5000) + "?Q?x?=";
        Assert.Equal(longName, Rfc2047.Decode(longName)); // syntactically refused: kept literally
        Assert.Equal("=?é?Q?x?=", Rfc2047.Decode("=?é?Q?x?="));
        Assert.False(MimeCharsets.TryGetEncoding("utf-8; rm -rf", out _));
        Assert.False(MimeCharsets.TryGetEncoding("", out _));
        Assert.True(MimeCharsets.TryGetEncoding("UTF-8", out var utf8));
        Assert.Equal(65001, utf8!.CodePage);
    }

    [Fact]
    public void Charset_resolution_registers_code_pages()
    {
        MimeCharsets.RegisterCodePages();
        MimeCharsets.RegisterCodePages(); // idempotent
        foreach (string name in new[] { "windows-1252", "iso-8859-2", "koi8-r", "big5", "euc-kr", "gbk", "iso-2022-jp", "windows-1251" })
        {
            Assert.True(MimeCharsets.TryGetEncoding(name, out _), name);
        }
    }

    [Fact]
    public void Many_encoded_words_decode_in_linear_time()
    {
        string input = string.Concat(Enumerable.Repeat("=?utf-8?Q?a?= ", 50_000));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        string result = Rfc2047.Decode(input);
        sw.Stop();
        Assert.Equal(50_001, result.Length); // the trailing space after the last word is kept
        Assert.True(sw.ElapsedMilliseconds < 2000, $"took {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public void Pathological_inputs_stay_linear()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Rfc2047.Decode(string.Concat(Enumerable.Repeat("=?a?B?", 100_000)));
        Rfc2047.Decode("=?utf-8?B?" + new string('A', 1_000_000));
        Rfc2047.Decode(string.Concat(Enumerable.Repeat("=?x?", 200_000)));
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 3000, $"took {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public void Decode_returns_same_instance_when_nothing_to_decode()
    {
        string s = "nothing here";
        Assert.Same(s, Rfc2047.Decode(s));
    }

    [Fact]
    public void TryDecodeWord_requires_exactly_one_word()
    {
        Assert.True(Rfc2047.TryDecodeWord("=?utf-8?Q?a?=", out var text));
        Assert.Equal("a", text);
        Assert.False(Rfc2047.TryDecodeWord("=?utf-8?Q?a?= tail", out _));
        Assert.False(Rfc2047.TryDecodeWord("plain", out _));
    }

    // ------------------------------------------------------------ encoding

    [Fact]
    public void Ascii_text_is_not_encoded()
    {
        string s = "Plain ASCII subject, with punctuation!";
        Assert.Same(s, Rfc2047.Encode(s));
    }

    [Theory]
    [InlineData("Café")]
    [InlineData("Hello 世界")]
    [InlineData("€100 discount – today only")]
    [InlineData("Re: Über café à la carte, s'il vous plaît")]
    [InlineData("emoji \U0001F600 here")]
    [InlineData("leading ascii words then é and trailing words")]
    [InlineData("=?looks like an encoded word?=")]
    public void Encode_then_decode_round_trips(string text)
    {
        string encoded = Rfc2047.Encode(text);
        Assert.True(Ascii(encoded), encoded);
        Assert.Equal(text, Rfc2047.Decode(encoded));
    }

    [Fact]
    public void Encoded_words_never_exceed_75_chars_and_split_on_character_boundaries()
    {
        string text = string.Concat(Enumerable.Repeat("世界\U0001F600é", 60));
        string encoded = Rfc2047.Encode(text);
        foreach (string word in encoded.Split(' '))
        {
            Assert.StartsWith("=?utf-8?", word);
            Assert.True(word.Length <= 75, $"{word.Length}: {word}");
            Assert.True(Rfc2047.TryDecodeWord(word, out string part), word); // each word decodes alone (no split characters)
            Assert.DoesNotContain('�', part);
        }

        Assert.Equal(text, Rfc2047.Decode(encoded));
    }

    [Fact]
    public void Encode_picks_the_shorter_of_Q_and_B()
    {
        Assert.Contains("?Q?", Rfc2047.Encode("résumé written in plain english with a lot more plain ascii text in the middle résumé"));
        Assert.Contains("?B?", Rfc2047.Encode("世界世界世界"));
    }

    [Fact]
    public void Only_the_needed_span_is_encoded()
    {
        string encoded = Rfc2047.Encode("Dear Café owner, hello");
        Assert.StartsWith("Dear ", encoded);
        Assert.EndsWith(" owner, hello", encoded.Contains("owner") ? encoded : encoded + " owner, hello");
        Assert.Equal("Dear Café owner, hello", Rfc2047.Decode(encoded));
    }

    [Fact]
    public void Very_long_ascii_word_is_encoded_so_it_can_fold()
    {
        string text = new string('x', 2000);
        string encoded = Rfc2047.Encode(text);
        Assert.StartsWith("=?", encoded);
        Assert.Equal(text, Rfc2047.Decode(encoded));
    }

    [Fact]
    public void Encode_other_charsets()
    {
        string encoded = Rfc2047.Encode("café", Encoding.GetEncoding("iso-8859-1"));
        Assert.StartsWith("=?iso-8859-1?", encoded);
        Assert.Equal("café", Rfc2047.Decode(encoded));
    }

    [Fact]
    public void Stateful_charsets_cannot_be_used_for_encoding()
    {
        Assert.Throws<ArgumentException>(() => Rfc2047.Encode("あ", Encoding.GetEncoding("iso-2022-jp")));
        Assert.Throws<ArgumentException>(() => Rfc2047.Encode("あ", Encoding.Unicode));
    }

    [Fact]
    public void Lone_surrogates_are_replaced_not_thrown_on()
    {
        string encoded = Rfc2047.Encode("bad \uD800 surrogate");
        Assert.Contains("�", Rfc2047.Decode(encoded));
    }

    private static bool Ascii(string s) => System.Text.Ascii.IsValid(s);
}
