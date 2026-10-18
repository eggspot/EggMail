using Mta.Core;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Webhooks.Tests;

public class DispatcherOwnerTests
{
    private sealed class PlainProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => plaintext.ToArray();

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) => protectedData.ToArray();
    }

    [Fact]
    public async Task Dispatchers_created_in_the_same_millisecond_never_share_a_lease_owner()
    {
        // Two replicas that start together must not be handed the same outbox items: the owner names the claim. The first 12 hex digits of a UUIDv7 are its
        // millisecond timestamp, so an owner built from them collided for every dispatcher created within one millisecond.
        await using var storage = new InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        var owners = new HashSet<string>();
        const int count = 500;
        for (int i = 0; i < count; i++)
        {
            var dispatcher = new WebhookDispatcher(storage.Webhooks, storage.Config, new PlainProtector());
            owners.Add(dispatcher.Owner);
            await dispatcher.DisposeAsync();
        }

        Assert.Equal(count, owners.Count);
    }
}
