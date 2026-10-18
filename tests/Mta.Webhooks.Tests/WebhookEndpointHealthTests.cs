using Mta.Core;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Webhooks.Tests;

/// <summary>What delivery results do to the endpoint (shared by the outbox dispatcher and the inbound route actions).</summary>
public class WebhookEndpointHealthTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 16, 8, 0, 0, TimeSpan.Zero);

    private static async Task<(InMemoryStorage Storage, WebhookEndpointRecord Endpoint)> StartAsync()
    {
        var storage = new InMemoryStorage(new StorageOptions(), SystemClock.Instance);
        await storage.InitializeAsync(default);
        var endpoint = new WebhookEndpointRecord(Ids.New(), Ids.New(), "https://hooks.example.test/x", [1, 2, 3], ["*"], true, null, null, Now, null);
        await storage.Config.UpsertWebhookEndpointAsync(endpoint, default);
        return (storage, endpoint);
    }

    [Fact]
    public async Task A_failure_starts_the_streak_and_a_success_ends_it()
    {
        (InMemoryStorage storage, WebhookEndpointRecord endpoint) = await StartAsync();
        var health = new WebhookEndpointHealth(storage.Config, new WebhookOptions());

        await health.RecordFailureAsync(endpoint, Now, default);
        WebhookEndpointRecord failing = (await storage.Config.GetWebhookEndpointAsync(endpoint.Id, default))!;
        Assert.Equal(Now, failing.FailingSince);

        await health.RecordFailureAsync(failing, Now.AddHours(1), default);   // the streak keeps its start
        Assert.Equal(Now, (await storage.Config.GetWebhookEndpointAsync(endpoint.Id, default))!.FailingSince);

        await health.RecordSuccessAsync(failing, default);
        Assert.Null((await storage.Config.GetWebhookEndpointAsync(endpoint.Id, default))!.FailingSince);
    }

    [Fact]
    public async Task A_streak_longer_than_the_window_disables_the_endpoint_and_tells_the_tenant()
    {
        (InMemoryStorage storage, WebhookEndpointRecord endpoint) = await StartAsync();
        var told = new List<string>();
        var health = new WebhookEndpointHealth(storage.Config, new WebhookOptions { DisableAfter = TimeSpan.FromDays(5) }, null, new Notifier(told));
        await health.RecordFailureAsync(endpoint, Now, default);

        await health.RecordFailureAsync(endpoint, Now.AddDays(5), default);

        WebhookEndpointRecord stored = (await storage.Config.GetWebhookEndpointAsync(endpoint.Id, default))!;
        Assert.False(stored.Enabled);
        Assert.Contains("Failing continuously", stored.DisabledReason, StringComparison.Ordinal);
        Assert.Single(told);
    }

    [Fact]
    public async Task A_change_made_while_a_call_was_in_flight_is_not_overwritten_by_the_copy_the_call_started_from()
    {
        (InMemoryStorage storage, WebhookEndpointRecord endpoint) = await StartAsync();
        var health = new WebhookEndpointHealth(storage.Config, new WebhookOptions());

        // The call started from `endpoint`; meanwhile the owner rotated the secret and changed the URL.
        WebhookEndpointRecord rotated = endpoint with { SecretProtected = [9, 9, 9], Url = "https://new.example.test/x" };
        await storage.Config.UpsertWebhookEndpointAsync(rotated, default);
        await health.RecordFailureAsync(endpoint, Now, default);

        WebhookEndpointRecord stored = (await storage.Config.GetWebhookEndpointAsync(endpoint.Id, default))!;
        Assert.Equal(new byte[] { 9, 9, 9 }, stored.SecretProtected);
        Assert.Equal("https://new.example.test/x", stored.Url);
        Assert.Equal(Now, stored.FailingSince);
    }

    [Fact]
    public async Task A_disabled_endpoint_does_not_start_a_streak()
    {
        (InMemoryStorage storage, WebhookEndpointRecord endpoint) = await StartAsync();
        await storage.Config.DisableWebhookEndpointAsync(endpoint.Id, "off", Now, default);
        var health = new WebhookEndpointHealth(storage.Config, new WebhookOptions());

        await health.RecordFailureAsync(endpoint, Now, default);

        WebhookEndpointRecord stored = (await storage.Config.GetWebhookEndpointAsync(endpoint.Id, default))!;
        Assert.False(stored.Enabled);
        Assert.Null(stored.FailingSince);
    }

    [Fact]
    public async Task Only_the_attempt_that_really_switched_the_endpoint_off_counts_and_tells_the_tenant()
    {
        (InMemoryStorage storage, WebhookEndpointRecord endpoint) = await StartAsync();
        var told = new List<string>();
        var health = new WebhookEndpointHealth(storage.Config, new WebhookOptions(), null, new Notifier(told));

        // Several attempts to the same dead endpoint all end in a 410 (or in the failure window) at about the same time.
        await health.DisableAsync(endpoint, "The receiver answered 410 Gone", Now, default);
        await health.DisableAsync(endpoint, "The receiver answered 410 Gone", Now, default);
        await health.DisableAsync(endpoint, "Failing continuously since x", Now, default);

        Assert.Single(told);
        WebhookEndpointRecord stored = (await storage.Config.GetWebhookEndpointAsync(endpoint.Id, default))!;
        Assert.False(stored.Enabled);
        Assert.Equal("The receiver answered 410 Gone", stored.DisabledReason);   // the first reason stays

        // An endpoint that was deleted meanwhile is nothing to switch off.
        await health.DisableAsync(endpoint with { Id = Ids.New() }, "x", Now, default);
        Assert.Single(told);
    }

    private sealed class Notifier(List<string> told) : IWebhookNotifier
    {
        public ValueTask EndpointDisabledAsync(WebhookEndpointRecord endpoint, string reason, CancellationToken cancellationToken)
        {
            told.Add(reason);
            return ValueTask.CompletedTask;
        }
    }
}
