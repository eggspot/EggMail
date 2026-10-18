using System.Reflection;
using Mta.Core;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Webhooks.Tests;

/// <summary>
/// The dispatcher names itself in the delivery leases it takes. Version 7 ids start with their millisecond timestamp, so an owner name cut from the front of one
/// is the same for dispatchers created in the same millisecond, and two replicas would then both be let into one lease.
/// </summary>
public sealed class WebhookOwnerTests
{
    [Fact]
    public async Task Dispatchers_created_back_to_back_never_share_an_owner_name()
    {
        var storage = new InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        await storage.InitializeAsync(default);
        var field = typeof(WebhookDispatcher).GetField("_owner", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var owners = new HashSet<string>();

        for (int i = 0; i < 500; i++)
        {
            await using var dispatcher = new WebhookDispatcher(storage.Webhooks, storage.Config, new PlainProtector());
            owners.Add((string)field.GetValue(dispatcher)!);
        }

        Assert.Equal(500, owners.Count);
    }

    private sealed class PlainProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => plaintext.ToArray();

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) => protectedData.ToArray();
    }
}
