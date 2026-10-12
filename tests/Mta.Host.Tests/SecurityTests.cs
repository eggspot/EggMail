using Mta.Core;
using Mta.Host.Security;

namespace Mta.Host.Tests;

public class SecurityTests
{
    [Fact]
    public void Password_hashing()
    {
        string h = PasswordHasher.Hash("correct horse", 2000);
        Assert.StartsWith("pbkdf2-sha256$2000$", h);
        Assert.True(PasswordHasher.Verify("correct horse", h));
        Assert.False(PasswordHasher.Verify("Correct horse", h));
        Assert.NotEqual(h, PasswordHasher.Hash("correct horse", 2000));        // random salt
        Assert.True(PasswordHasher.NeedsRehash(h));
        Assert.False(PasswordHasher.NeedsRehash(PasswordHasher.Hash("x", 700_000)));
        Assert.False(PasswordHasher.Verify("x", "garbage"));
        Assert.False(PasswordHasher.Verify("x", "pbkdf2-sha256$2000$!!$!!"));
        Assert.False(PasswordHasher.Verify("x", "pbkdf2-sha256$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="));
        PasswordHasher.VerifyDummy("anything");
    }

    [Fact]
    public void Api_keys()
    {
        var (token, prefix, digest) = ApiKeys.Generate();
        Assert.StartsWith("egm_", token);
        Assert.StartsWith(prefix, token);
        Assert.True(ApiKeys.LooksLikeKey(token));
        Assert.Equal(digest, ApiKeys.Digest(token));
        Assert.NotEqual(digest, ApiKeys.Digest(token + "x"));
        Assert.NotEqual(token, ApiKeys.Generate().Token);
        Assert.False(ApiKeys.LooksLikeKey("egm_short"));
        Assert.False(ApiKeys.LooksLikeKey(null));
        Assert.False(ApiKeys.LooksLikeKey("sk_" + new string('a', 50)));
    }

    [Fact]
    public void Generated_api_keys_always_look_like_keys()
    {
        // Base64url output can contain '_' and '-'; the syntax check must not depend on how often they appear.
        for (int i = 0; i < 2000; i++)
        {
            Assert.True(ApiKeys.LooksLikeKey(ApiKeys.Generate().Token));
        }
    }

    private sealed class FakeClock : IClock
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 12, 8, 0, 0, TimeSpan.Zero);
        public DateTimeOffset UtcNow => Now;
        public long Timestamp => Now.Ticks;
    }

    [Fact]
    public void Throttle_locks_out_and_recovers()
    {
        var clock = new FakeClock();
        var t = new AuthThrottle(clock, maxFailures: 3, window: TimeSpan.FromMinutes(10));
        Assert.False(t.IsLockedOut(out _, "1.2.3.4", "alice"));
        t.RecordFailure("1.2.3.4", "alice");
        clock.Now = clock.Now.AddMinutes(1);
        t.RecordFailure("1.2.3.4", "alice");
        clock.Now = clock.Now.AddMinutes(1);
        t.RecordFailure("1.2.3.4", "bob");
        // IP reached 3 failures although spread over users; alice only 2.
        Assert.True(t.IsLockedOut(out var wait, "1.2.3.4"));
        Assert.InRange(wait.TotalMinutes, 7.9, 8.1);
        Assert.False(t.IsLockedOut(out _, "alice"));
        Assert.True(t.IsLockedOut(out _, "alice", "1.2.3.4"));
        clock.Now = clock.Now.AddMinutes(9);       // oldest failure leaves the window
        Assert.False(t.IsLockedOut(out _, "1.2.3.4"));
        t.RecordFailure("x"); t.RecordFailure("x"); t.RecordFailure("x");
        Assert.True(t.IsLockedOut(out _, "x"));
        t.RecordSuccess("x");
        Assert.False(t.IsLockedOut(out _, "x"));
    }

    [Fact]
    public async Task Throttle_is_thread_safe_and_bounded()
    {
        var t = new AuthThrottle(maxFailures: 1_000_000, maxKeys: 500);
        await Task.WhenAll(Enumerable.Range(0, 8).Select(w => Task.Run(() =>
        {
            for (int i = 0; i < 5000; i++) { t.RecordFailure($"key{w}-{i % 800}"); t.IsLockedOut(out _, $"key{w}-{i % 800}"); }
        })));
    }
}
