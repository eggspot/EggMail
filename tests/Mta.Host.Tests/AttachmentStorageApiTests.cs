using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Tests.Api;
using Mta.Host.Ingest;
using Mta.Host.Security;
using Mta.Host.Submission;
using Mta.Policy;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

/// <summary>The tenant setting as the settings API writes it, end to end through the sending API.</summary>
[Collection("api")]
public class AttachmentStorageApiTests
{
    private static JsonElement Item(Reply r, string key) => r["items"].EnumerateArray().Single(i => i.GetProperty("key").GetString() == key);

    private static async Task<bool> SendAndCheckRetainedAsync(ApiFixture f, ApiClient key, bool? perSend, string from = "a@example.com")
    {
        var body = new Dictionary<string, object?>
        {
            ["from"] = from,
            ["to"] = new[] { "x@gmail.test" },
            ["subject"] = "s",
            ["text"] = "t",
            ["attachments"] = new[] { new { filename = "a.bin", content_type = "application/octet-stream", content = Convert.ToBase64String([1, 2, 3]) } },
        };
        if (perSend is { } flag)
        {
            body["store_attachments"] = flag;
        }

        Reply sent = await key.PostAsync("/api/v1/messages", body);
        foreach (ClaimedDelivery d in await f.Storage.Deliveries.ClaimAsync("t", 10, f.Clock.UtcNow, TimeSpan.FromMinutes(1), default))
        {
            await f.Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = f.Clock.UtcNow, SmtpCode = 250 }, default);
        }

        return (await key.GetAsync("/api/v1/messages/" + sent.Str("id")))["rawRetained"].GetBoolean();
    }

    [Fact]
    public async Task A_tenant_that_switched_storing_off_overrides_the_operator_default_and_one_that_never_chose_inherits_it()
    {
        await using var f = await ApiFixture.StartAsync(new ApiFixtureOptions { StoreAttachmentsByDefault = true });
        var alice = await f.SignedInAsync("alice");      // tenant A
        var keyA = await f.KeyClientAsync(ApiFixture.TenantAId);
        var keyB = await f.KeyClientAsync(ApiFixture.TenantBId);

        // Nobody chose anything: the operator default (store) applies, and the settings page shows what is in force.
        Assert.True(Item(await alice.GetAsync("/api/v1/settings"), "Content:StoreAttachments").GetProperty("value").GetBoolean());
        Assert.True(await SendAndCheckRetainedAsync(f, keyA, perSend: null));

        // Tenant A turns it off: its sends are no longer kept, tenant B (never chose) still inherits the default.
        var put = await alice.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Content:StoreAttachments"] = false } });
        Assert.False(Item(put, "Content:StoreAttachments").GetProperty("value").GetBoolean());
        Assert.False(await SendAndCheckRetainedAsync(f, keyA, perSend: null));
        Assert.True(await SendAndCheckRetainedAsync(f, keyB, perSend: null, from: "b@globex.test"));

        // The per-send flag still wins over the tenant's choice.
        Assert.True(await SendAndCheckRetainedAsync(f, keyA, perSend: true));
    }

    [Fact]
    public async Task A_tenant_can_turn_storing_on_while_the_operator_default_is_off()
    {
        await using var f = await ApiFixture.StartAsync(new ApiFixtureOptions { StoreAttachmentsByDefault = false });
        var alice = await f.SignedInAsync("alice");
        var keyA = await f.KeyClientAsync(ApiFixture.TenantAId);
        Assert.False(await SendAndCheckRetainedAsync(f, keyA, perSend: null));

        await alice.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Content:StoreAttachments"] = true } });

        Assert.True(await SendAndCheckRetainedAsync(f, keyA, perSend: null));
    }

    [Fact]
    public async Task A_resend_does_not_override_the_tenants_choice_not_to_store()
    {
        await using var f = await ApiFixture.StartAsync(new ApiFixtureOptions { StoreAttachmentsByDefault = true });
        var alice = await f.SignedInAsync("alice");
        var keyA = await f.KeyClientAsync(ApiFixture.TenantAId);

        // Sent while storing was on: the raw message is kept and can be resent verbatim.
        Reply first = await keyA.PostAsync("/api/v1/messages", new Dictionary<string, object?>
        {
            ["from"] = "a@example.com", ["to"] = new[] { "x@gmail.test" }, ["subject"] = "s", ["text"] = "t",
            ["attachments"] = new[] { new { filename = "a.bin", content_type = "application/octet-stream", content = Convert.ToBase64String([1, 2, 3]) } },
        });
        await DeliverAllAsync(f);
        Assert.True((await keyA.GetAsync("/api/v1/messages/" + first.Str("id")))["rawRetained"].GetBoolean());

        await alice.PutAsync("/api/v1/settings", new { values = new Dictionary<string, object> { ["Content:StoreAttachments"] = false } });
        Reply resent = await keyA.PostAsync($"/api/v1/messages/{first.Str("id")}/resend");
        Assert.Equal(System.Net.HttpStatusCode.Accepted, resent.Status);
        await DeliverAllAsync(f);

        Assert.False((await keyA.GetAsync("/api/v1/messages/" + resent.Str("id")))["rawRetained"].GetBoolean());
    }

    [Fact]
    public async Task A_tenant_that_only_has_the_older_column_set_is_shown_as_having_chosen_yes_under_an_operator_default_of_no()
    {
        await using var f = await ApiFixture.StartAsync(new ApiFixtureOptions { StoreAttachmentsByDefault = false });
        Tenant tenant = (await f.Storage.Config.GetTenantAsync(ApiFixture.TenantAId, default))!;
        await f.Storage.Config.UpsertTenantAsync(tenant with { StoreAttachments = true }, default);
        var alice = await f.SignedInAsync("alice");

        Assert.True(Item(await alice.GetAsync("/api/v1/settings"), "Content:StoreAttachments").GetProperty("value").GetBoolean());
        Assert.True(await SendAndCheckRetainedAsync(f, await f.KeyClientAsync(ApiFixture.TenantAId), perSend: null));
    }

    private static async Task DeliverAllAsync(ApiFixture f)
    {
        foreach (ClaimedDelivery d in await f.Storage.Deliveries.ClaimAsync("t", 10, f.Clock.UtcNow, TimeSpan.FromMinutes(1), default))
        {
            await f.Storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = f.Clock.UtcNow, SmtpCode = 250 }, default);
        }
    }
}
