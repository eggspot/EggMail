using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Cryptography;
using Mta.Core;
using Mta.Dkim;
using Mta.Storage;

namespace Mta.Delivery.Tests;

[Collection("delivery-pipeline")]
public class DkimKeyUnavailableDeliveryTests
{
    [Fact]
    public async Task A_domain_whose_dkim_key_cannot_be_read_has_its_mail_held_and_never_sent_unsigned()
    {
        var log = new RecordingLog();
        using var capture = new MeterCapture(m => m.Name == "Mta.Delivery");
        await using var f = new DeliveryFixture(dkim: s => new ConfigDkimSignerProvider(s.Storage.Config, new FailingProtector(), s.Clock), log: log);
        await AddDomainWithKeyAsync(f.Storage.Config, "example.org");

        DateTimeOffset enqueuedAt = DateTimeOffset.UtcNow;
        Guid id = await f.EnqueueAsync(["rcpt@dest.example"]);

        await DeliveryFixture.WaitAsync(() => capture.Sum("mta.delivery.held") >= 1);
        await DeliveryFixture.WaitAsync(() => f.Storage.Deliveries.GetQueueStatsAsync(default).AsTask().Result is { Deferred: 1 } or { Queued: 1, Leased: 0 });
        await Task.Delay(300);

        Assert.Empty(f.Remote.Messages);
        Assert.DoesNotContain(await f.EventsAsync(id), e => e.Type is MessageEventType.Deferred or MessageEventType.Delivered or MessageEventType.Bounced);
        Assert.Empty(await f.Storage.Deliveries.ClaimAsync("probe", 10, enqueuedAt.AddMinutes(4), TimeSpan.FromMinutes(1), default));
        Assert.Single(await f.Storage.Deliveries.ClaimAsync("probe", 10, enqueuedAt.AddMinutes(6), TimeSpan.FromMinutes(1), default));
        Assert.Equal(1, capture.Sum("mta.delivery.dkim.key.failures"));
        var error = Assert.Single(log.Entries, e => e.Level == MtaLogLevel.Error);
        Assert.Contains("example.org", error.Message);
        Assert.IsType<DkimKeyUnavailableException>(error.Exception);
        Assert.DoesNotContain(log.Entries, e => e.Message.Contains("unsigned", StringComparison.OrdinalIgnoreCase) && e.Level != MtaLogLevel.Error);
    }

    [Fact]
    public async Task A_signer_provider_that_fails_in_any_other_way_holds_the_mail_too()
    {
        await using var f = new DeliveryFixture(dkim: _ => new ThrowingProvider());
        Guid id = await f.EnqueueAsync(["rcpt@dest.example"]);

        await DeliveryFixture.WaitAsync(() => f.Storage.Deliveries.GetQueueStatsAsync(default).AsTask().Result is { Deferred: 1 } or { Queued: 1, Leased: 0 });
        await Task.Delay(300);

        Assert.Empty(f.Remote.Messages);
        Assert.DoesNotContain(await f.EventsAsync(id), e => e.Type is MessageEventType.Delivered);
    }

    [Fact]
    public async Task A_domain_with_no_active_key_still_sends_unsigned()
    {
        await using var f = new DeliveryFixture(dkim: s => new ConfigDkimSignerProvider(s.Storage.Config, new FailingProtector(), s.Clock));
        await AddDomainWithKeyAsync(f.Storage.Config, "example.org", active: false);

        Guid id = await f.EnqueueAsync(["rcpt@dest.example"]);
        await f.WaitForEventAsync(id, MessageEventType.Delivered);

        Assert.DoesNotContain("DKIM-Signature:", System.Text.Encoding.ASCII.GetString(Assert.Single(f.Remote.Messages).Body));
    }

    internal static async Task<Guid> AddDomainWithKeyAsync(IConfigStore config, string name, bool active = true, byte[]? privateKey = null)
    {
        var now = DateTimeOffset.UtcNow;
        var domainId = Ids.New();
        await config.UpsertDomainAsync(new DomainRecord(domainId, DeliveryFixture.Tenant, name, DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        using var rsa = DkimKeyTools.GenerateRsa2048();
        var keyId = Ids.New();
        await config.AddDkimKeyAsync(new Mta.Storage.DkimKeyRecord(keyId, domainId, "egg1", privateKey ?? rsa.ExportPkcs8PrivateKey(), DkimKeyTools.ExportPublicKeyBase64(rsa), now, active, null), default);
        return keyId;
    }

    private sealed class ThrowingProvider : IDkimSignerProvider
    {
        public ValueTask<DkimSigner?> GetSignerAsync(string sendingDomain, CancellationToken cancellationToken) => throw new InvalidOperationException("signer backend is down");
    }
}

public class ConfigDkimSignerProviderFailureTests
{
    [Fact]
    public async Task A_key_that_cannot_be_decrypted_throws_with_its_id_and_the_failure_is_cached_for_the_ttl()
    {
        var storage = await StorageAsync();
        Guid keyId = await DkimKeyUnavailableDeliveryTests.AddDomainWithKeyAsync(storage.Config, "example.org");
        var protector = new FailingProtector();
        using var provider = new ConfigDkimSignerProvider(storage.Config, protector, SystemClock.Instance, TimeSpan.FromHours(1));

        var first = await Assert.ThrowsAsync<DkimKeyUnavailableException>(() => provider.GetSignerAsync("mail.example.org", default).AsTask());
        var second = await Assert.ThrowsAsync<DkimKeyUnavailableException>(() => provider.GetSignerAsync("example.org", default).AsTask());
        var third = await Assert.ThrowsAsync<DkimKeyUnavailableException>(() => provider.GetSignerAsync("mail.example.org", default).AsTask());

        Assert.Equal(keyId, first.KeyId);
        Assert.Equal("example.org", first.Domain);
        Assert.False(first.Cached);
        Assert.IsType<CryptographicException>(first.InnerException);
        Assert.False(second.Cached);
        Assert.True(third.Cached);
        Assert.Equal(keyId, third.KeyId);
        Assert.Equal(2, protector.Calls);
    }

    [Fact]
    public async Task A_repaired_key_is_used_once_the_cached_failure_expires()
    {
        var storage = await StorageAsync();
        await DkimKeyUnavailableDeliveryTests.AddDomainWithKeyAsync(storage.Config, "example.org");
        var protector = new FailingProtector();
        using var provider = new ConfigDkimSignerProvider(storage.Config, protector, SystemClock.Instance, TimeSpan.Zero);

        await Assert.ThrowsAsync<DkimKeyUnavailableException>(() => provider.GetSignerAsync("example.org", default).AsTask());
        protector.Fail = false;

        DkimSigner? signer = await provider.GetSignerAsync("example.org", default);
        Assert.NotNull(signer);
        Assert.Equal("egg1", signer.Selector);
    }

    [Fact]
    public async Task A_stored_key_that_is_not_a_private_key_throws_instead_of_signing_nothing()
    {
        var storage = await StorageAsync();
        Guid keyId = await DkimKeyUnavailableDeliveryTests.AddDomainWithKeyAsync(storage.Config, "example.org", privateKey: [0x30, 0x03, 0x02, 0x01, 0x00]);
        var protector = new FailingProtector { Fail = false };
        using var provider = new ConfigDkimSignerProvider(storage.Config, protector, SystemClock.Instance);

        var failure = await Assert.ThrowsAsync<DkimKeyUnavailableException>(() => provider.GetSignerAsync("example.org", default).AsTask());
        Assert.Equal(keyId, failure.KeyId);
    }

    [Fact]
    public async Task A_configuration_store_failure_throws_without_a_key_id()
    {
        var storage = await StorageAsync();
        using var provider = new ConfigDkimSignerProvider(FailingConfigStore(storage.Config), new FailingProtector(), SystemClock.Instance);

        var failure = await Assert.ThrowsAsync<DkimKeyUnavailableException>(() => provider.GetSignerAsync("Example.ORG.", default).AsTask());
        Assert.Null(failure.KeyId);
        Assert.Equal("example.org", failure.Domain);
        Assert.IsType<StorageUnavailableException>(failure.InnerException);
    }

    [Fact]
    public async Task Cancellation_is_not_cached_as_a_key_failure()
    {
        var storage = await StorageAsync();
        await DkimKeyUnavailableDeliveryTests.AddDomainWithKeyAsync(storage.Config, "example.org");
        using var provider = new ConfigDkimSignerProvider(CancellingConfigStore(storage.Config), new FailingProtector { Fail = false }, SystemClock.Instance, TimeSpan.FromHours(1));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => provider.GetSignerAsync("example.org", default).AsTask());
        Assert.NotNull(await provider.GetSignerAsync("example.org", default));
    }

    private static async Task<Mta.Storage.InMemory.InMemoryStorage> StorageAsync()
    {
        var storage = new Mta.Storage.InMemory.InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        await storage.InitializeAsync(default);
        return storage;
    }

    private static IConfigStore FailingConfigStore(IConfigStore inner) =>
        ConfigStoreInterceptor.Wrap(inner, (method, args) => method.Name == nameof(IConfigStore.FindDomainByNameAsync) ? throw new StorageUnavailableException("config store is down") : null);

    private static IConfigStore CancellingConfigStore(IConfigStore inner)
    {
        int calls = 0;
        return ConfigStoreInterceptor.Wrap(inner, (method, args) =>
            method.Name == nameof(IConfigStore.FindDomainByNameAsync) && Interlocked.Increment(ref calls) == 1 ? throw new OperationCanceledException() : null);
    }
}

public class ConfigStoreInterceptor : DispatchProxy
{
    private IConfigStore _inner = null!;
    private Func<MethodInfo, object?[]?, object?> _before = null!;

    public static IConfigStore Wrap(IConfigStore inner, Func<MethodInfo, object?[]?, object?> before)
    {
        IConfigStore proxy = Create<IConfigStore, ConfigStoreInterceptor>();
        var interceptor = (ConfigStoreInterceptor)(object)proxy;
        interceptor._inner = inner;
        interceptor._before = before;
        return proxy;
    }

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        ArgumentNullException.ThrowIfNull(targetMethod);
        return _before(targetMethod, args) ?? targetMethod.Invoke(_inner, args);
    }
}

internal sealed class FailingProtector : ISecretProtector
{
    private int _calls;

    public bool Fail { get; set; } = true;

    public int Calls => _calls;

    public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => plaintext.ToArray();

    public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose)
    {
        Interlocked.Increment(ref _calls);
        return Fail ? throw new CryptographicException("the key ring cannot decrypt this secret") : protectedData.ToArray();
    }
}

internal sealed class RecordingLog : IMtaLog
{
    public sealed record Entry(MtaLogLevel Level, string Message, Exception? Exception);

    private readonly ConcurrentQueue<Entry> _entries = new();

    public IReadOnlyCollection<Entry> Entries => _entries.ToArray();

    public bool IsEnabled(MtaLogLevel level) => true;

    public void Write(MtaLogLevel level, string source, string message, Exception? exception = null) => _entries.Enqueue(new Entry(level, message, exception));
}
