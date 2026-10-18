using System.Security.Cryptography;
using System.Text;
using Mta.Host.Api;
using Mta.Host.Security;
using Mta.Host.Tests.Api;
using Mta.Storage;

namespace Mta.Host.Tests.Security;

/// <summary>
/// Security regression tests for API keys, passwords and session secrets (docs/security-test-map.md, CRED-*): their format and entropy, that only a digest is
/// stored, and that the places that compare a secret do it in constant time. The in-house review, not an independent audit.
/// </summary>
public class CredentialHandlingTests
{
    [Fact]
    public void A_key_is_256_bits_of_randomness_with_a_48_bit_identifier_and_never_repeats()
    {
        var tokens = new HashSet<string>();
        var ids = new HashSet<string>();
        for (int i = 0; i < 20_000; i++)
        {
            var (token, prefix, digest) = ApiKeys.Generate();
            Assert.True(tokens.Add(token));
            Assert.True(ids.Add(prefix));
            Assert.Equal("egm_".Length + 8 + 1 + 43, token.Length);
            string secret = token[(token.Length - 43)..];
            byte[] bytes = Convert.FromBase64String(secret.Replace('-', '+').Replace('_', '/') + "=");
            Assert.Equal(32, bytes.Length);
            Assert.Equal(12, prefix.Length);                                  // egm_ and the identifier: nothing of the secret
            Assert.DoesNotContain(secret[..8], prefix, StringComparison.Ordinal);
            Assert.Equal(32, digest.Length);
            Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(token)), digest);
            Assert.NotEqual(Encoding.UTF8.GetBytes(token)[..32], digest);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("egm_")]
    [InlineData("egm_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]       // one character short
    [InlineData("egm_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]     // one character long
    [InlineData("egm_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")]
    [InlineData(" egm_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("EGM_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("egm_AAAAAAAAxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]       // the separator is missing
    [InlineData("egm_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA١A")]  // an Arabic-Indic digit is not an ASCII digit
    [InlineData("egm_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+/")]
    [InlineData("egm_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0A")]
    public void Text_that_is_not_exactly_the_shape_of_a_key_is_never_looked_up(string text) => Assert.False(ApiKeys.LooksLikeKey(text));

    [Fact]
    public async Task A_key_is_stored_as_its_digest_only_and_its_listing_never_shows_more_than_the_prefix()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.PasswordHashIterations = 1000 });
        ApiClient alice = await f.SignedInAsync("alice");
        Reply created = await alice.PostAsync("/api/v1/api-keys", new { name = "ci", scopes = new[] { "read" } });
        string token = created.Str("key");

        Assert.Equal("no-store", created.Header("Cache-Control"));   // the one response that carries the secret is not kept by caches
        ApiKeyRecord stored = (await f.Storage.Config.GetApiKeysAsync(ApiFixture.TenantAId, default)).Single(k => k.Name == "ci");
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(token)), stored.KeyHash);
        Assert.Equal(token[..12], stored.Prefix);
        string row = string.Join('|', stored.Name, stored.Prefix, stored.Scopes, Convert.ToBase64String(stored.KeyHash), Convert.ToHexString(stored.KeyHash));
        Assert.DoesNotContain(token[16..], row, StringComparison.Ordinal);

        Reply list = await alice.GetAsync("/api/v1/api-keys");
        Assert.DoesNotContain(token[16..], list.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("\"key\"", list.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("keyHash", list.Body, StringComparison.OrdinalIgnoreCase);
        Reply me = await f.NewClient().WithBearer(token).GetAsync("/api/v1/me");
        Assert.DoesNotContain(token[16..], me.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void Passwords_are_hashed_slowly_with_a_salt_of_their_own_and_hashes_of_other_schemes_are_never_accepted()
    {
        string a = PasswordHasher.Hash("same password", 1000);
        string b = PasswordHasher.Hash("same password", 1000);
        Assert.NotEqual(a, b);
        Assert.True(PasswordHasher.Verify("same password", a) && PasswordHasher.Verify("same password", b));
        Assert.StartsWith("pbkdf2-sha256$600000$", PasswordHasher.Hash("x"), StringComparison.Ordinal);   // OWASP 2023
        Assert.False(PasswordHasher.NeedsRehash(PasswordHasher.Hash("x")));

        // A stored value of any other shape is a failure, never a pass: no empty hash, no plaintext, no other algorithm, no truncated hash.
        foreach (string stored in new[] { "", "same password", "plain:same password", "md5$1000$AAAA$AAAA", "pbkdf2-sha256$1000$AAAA", "pbkdf2-sha256$0$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "pbkdf2-sha256$-1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "pbkdf2-sha256$1000$$" })
        {
            Assert.False(PasswordHasher.Verify("same password", stored), stored);
            Assert.False(PasswordHasher.Verify("", stored), stored);
        }

        // A hash can only ever be as strong as stored, but a wrong guess never passes whatever the length of the guess.
        Assert.False(PasswordHasher.Verify("same password" + new string('x', 100_000), a));
    }

    [Fact]
    public void Everything_that_compares_a_secret_or_a_tag_does_it_in_constant_time()
    {
        string root = RepositoryRoot();
        foreach (string relative in new[]
        {
            "src/Mta.Host/Api/ApiAuth.cs", "src/Mta.Host/Security/PasswordHasher.cs", "src/Mta.Webhooks/StandardWebhooksSigner.cs", "src/Mta.Dsn/VerpCodec.cs",
        })
        {
            string source = File.ReadAllText(Path.Combine(root, relative));
            Assert.Contains("FixedTimeEquals", source, StringComparison.Ordinal);
            Assert.DoesNotContain(".SequenceEqual(", source, StringComparison.Ordinal);
        }
    }

    private static string RepositoryRoot()
    {
        string? dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "EggMail.slnx")))
        {
            dir = Path.GetDirectoryName(dir);
        }

        return dir ?? throw new InvalidOperationException("EggMail.slnx not found above " + AppContext.BaseDirectory);
    }
}
