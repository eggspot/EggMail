using System.Net;
using Mta.Host.Api;
using Mta.Host.Tests.Api;

namespace Mta.Host.Tests.Security;

/// <summary>
/// The rule for text a caller may put into a name, a tag, a file name or a filter (<see cref="ApiText"/>, decision 97), tested in both directions: what it refuses,
/// edge by edge, and the real-world text it must accept (every script, joiners, direction marks, emoji). Explicit embedding controls and isolates
/// (LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI) are refused as a set: no name in any language needs them, and they are how a file name or a user name is made to
/// read differently from what it is; the plain direction marks (LRM, RLM, ALM) and the joiners are what real text uses and stay.
/// </summary>
public class UnsafeTextRuleTests
{
    public static TheoryData<string> Refused() => new()
    {
        "a\0b", "\0", "a\u0001b", "a\u001fb", "a\tb", "a\nb", "a\rb", "a\u007fb", "a\u0080b", "a\u0085b", "a\u009fb",
        "a\u2028b", "a\u2029b",
        "a\u202ab", "a\u202bb", "a\u202cb", "a\u202db", "a\u202eb",          // LRE RLE PDF LRO RLO
        "a\u2066b", "a\u2067b", "a\u2068b", "a\u2069b",                      // LRI RLI FSI PDI
    };

    public static TheoryData<string> Accepted() => new()
    {
        "plain name", "Müller & Söhne", "Zoë", "名前", "株式会社 Example", "한국어", "ไทย", "हिन्दी",
        "עברית", "דוח רבעוני", "العربية", "تقرير", "فارسی", "مي\u200cخواهم",       // Hebrew, Arabic, Persian with a zero-width non-joiner
        "ශ්\u200dරී",                                                          // Sinhala with a zero-width joiner
        "a\u200eb", "a\u200fb", "a\u061cb",                                    // LRM, RLM, ALM
        "😀 emoji", "👨\u200d👩\u200d👧", "\u2764\ufe0f",
        "e\u0301", "a\u00a0b", "a\u2003b",                                       // combining accent, no-break space, em space (spaces are not control characters)
    };

    [Theory]
    [MemberData(nameof(Refused))]
    public void Text_with_a_control_character_a_line_separator_a_direction_override_or_an_unpaired_surrogate_is_refused(string text) =>
        Assert.True(ApiText.HasUnsafeCharacter(text));

    [Theory]
    [MemberData(nameof(Accepted))]
    public void Text_in_any_script_with_joiners_direction_marks_and_emoji_is_accepted(string text) =>
        Assert.False(ApiText.HasUnsafeCharacter(text));

    [Fact]
    public void An_unpaired_surrogate_is_refused_wherever_it_stands_and_a_pair_is_not()
    {
        // Built from numbers: a test data row cannot carry an unpaired surrogate (the runner would replace it).
        string high = ((char)0xD800).ToString(), highMax = ((char)0xDBFF).ToString(), low = ((char)0xDC00).ToString(), lowMax = ((char)0xDFFF).ToString();
        foreach (string lone in new[] { high, highMax, low, lowMax })
        {
            Assert.True(ApiText.HasUnsafeCharacter("a" + lone + "b"));
            Assert.True(ApiText.HasUnsafeCharacter(lone));            // alone
            Assert.True(ApiText.HasUnsafeCharacter("a" + lone));      // a high surrogate at the end has no partner
            Assert.True(ApiText.HasUnsafeCharacter(lone + "a"));      // a low surrogate at the start has none either
        }

        Assert.True(ApiText.HasUnsafeCharacter(low + high));          // in the wrong order
        Assert.True(ApiText.HasUnsafeCharacter(high + high + low));   // the first high one is alone
        Assert.False(ApiText.HasUnsafeCharacter(high + low));
        Assert.False(ApiText.HasUnsafeCharacter("a" + highMax + lowMax + "b"));
    }

    [Fact]
    public void Nothing_is_refused_in_nothing()
    {
        Assert.False(ApiText.HasUnsafeCharacter(null));
        Assert.False(ApiText.HasUnsafeCharacter(""));
    }

    [Fact]
    public void The_bidirectional_range_is_refused_whole_and_its_neighbours_are_not()
    {
        for (char c = ' '; c <= '⁯'; c++)
        {
            bool expected = c is '\u2028' or '\u2029' || (c >= '\u202a' && c <= '\u202e') || (c >= '\u2066' && c <= '\u2069');
            Assert.Equal(expected, ApiText.HasUnsafeCharacter("a" + c + "b"));
        }
    }
}

/// <summary>The same rule, as the API applies it to names, tags and file names of real text.</summary>
[Collection("api")]
public class UnsafeTextThroughTheApiTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _alice = null!;
    private ApiClient _root = null!;
    private ApiClient _key = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.PasswordHashIterations = 1000 });
        _alice = await _f.SignedInAsync("alice");
        _root = await _f.SignedInAsync("root");
        _key = await _f.KeyClientAsync(ApiFixture.TenantAId);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    [Theory]
    [InlineData("名前の鍵")]
    [InlineData("מפתח CI")]
    [InlineData("مفتاح التكامل")]
    [InlineData("Schlüssel 🔑")]
    [InlineData("a\u200eb\u200fc")]
    public async Task Names_in_any_script_are_accepted_for_keys_tenants_and_users(string name)
    {
        Assert.Equal(HttpStatusCode.Created, (await _alice.PostAsync("/api/v1/api-keys", new { name, scopes = new[] { "read" } })).Status);
        Assert.Equal(HttpStatusCode.Created, (await _root.PostAsync("/api/v1/admin/tenants", new { name = name + " Ltd" })).Status);
        Reply user = await _root.PostAsync("/api/v1/admin/users", new { userName = name, role = "admin" });
        Assert.Equal(HttpStatusCode.Created, user.Status);
        Assert.Equal(HttpStatusCode.OK, (await _f.NewClient().SignInAsync(name, user.Str("password"))).Status);
    }

    [Theory]
    [InlineData("标签")]
    [InlineData("תגית")]
    [InlineData("وسم")]
    [InlineData("tag 😀")]
    public async Task Tags_in_any_script_are_accepted_and_found_again(string tag)
    {
        Reply sent = await _key.PostAsync("/api/v1/messages", new { from = "noreply@example.com", to = new[] { "a@gmail.test" }, subject = "s", text = "t", tags = new[] { tag } });
        Assert.Equal(HttpStatusCode.Accepted, sent.Status);

        Reply found = await _key.GetAsync("/api/v1/messages?tag=" + Uri.EscapeDataString(tag));

        Assert.Equal(1, found["items"].GetArrayLength());
    }

    [Theory]
    [InlineData("文件.txt")]
    [InlineData("דוח.txt")]
    [InlineData("تقرير.txt")]
    [InlineData("Übersicht (final) \u2013 v2.txt")]
    public async Task File_names_in_any_script_are_accepted(string fileName)
    {
        Reply r = await _key.PostAsync("/api/v1/messages", new Dictionary<string, object?>
        {
            ["from"] = "noreply@example.com", ["to"] = new[] { "a@gmail.test" }, ["subject"] = "s", ["text"] = "t",
            ["attachments"] = new object[] { new Dictionary<string, object?> { ["filename"] = fileName, ["content_type"] = "text/plain", ["content"] = Convert.ToBase64String("d"u8.ToArray()) } },
        });

        Assert.Equal(HttpStatusCode.Accepted, r.Status);
    }

    [Theory]
    [InlineData("bücher.example")]
    [InlineData("例え.jp")]
    [InlineData("xn--bcher-kva.example")]
    public async Task Internationalized_domain_names_are_accepted(string name) =>
        Assert.Equal(HttpStatusCode.Created, (await _alice.PostAsync("/api/v1/domains", new { name })).Status);
}
