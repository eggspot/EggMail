using System.Net;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Mta.Core;
using Mta.Dsn;
using Mta.Host.Api;
using Mta.Host.Hosting;
using Mta.Storage;
using Mta.Storage.Transfer;

namespace Mta.Host.Tests.Api;

/// <summary>The VERP key routes (decision 111): the list without key material, the rotation at once in both modes, and its refusals.</summary>
[Collection("api")]
public class ApiVerpKeyTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _admin = null!;
    private VerpCodec _codec = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync(new ApiFixtureOptions
        {
            Sqlite = true,   // a store with a switch state
            ConfigureServices = services => services.AddSingleton<IVerpKeyRing>(sp =>
            {
                IStorage storage = sp.GetRequiredService<IStorage>();
                IClock clock = sp.GetRequiredService<IClock>();
                ISecretProtector secrets = sp.GetRequiredService<ISecretProtector>();
                _codec = VerpKeyStore.LoadOrCreateAsync(storage.Config, secrets, default, clock).GetAwaiter().GetResult();
                return new VerpKeyRing(new VerpKeyRotation(storage.Config, secrets, _codec, clock, 90, 14), storage.Config, clock);
            }),
        });
        _admin = await _f.SignedInAsync("root");
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    [Fact]
    public async Task The_keys_are_listed_with_their_state_and_without_key_material()
    {
        Reply list = await _admin.GetAsync("/api/v1/admin/verp-keys");

        Assert.Equal(HttpStatusCode.OK, list.Status);
        JsonElement key = Assert.Single(list.Json.EnumerateArray());
        Assert.Equal(1, key.GetProperty("keyId").GetInt32());
        Assert.Equal("signing", key.GetProperty("state").GetString());
        Assert.Equal(["activatesAt", "createdAt", "keyId", "retiredAt", "state"], key.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task By_default_the_old_keys_are_revoked_and_the_new_key_signs_at_once()
    {
        string before = _codec.CreateLocalPart(ApiFixture.TenantAId, Guid.NewGuid(), _f.Clock.UtcNow, "example.net");

        Reply rotated = await _admin.PostAsync("/api/v1/admin/verp-keys/rotate", new { });

        Assert.Equal(HttpStatusCode.OK, rotated.Status);
        Assert.Equal(2, rotated.Json.GetProperty("keyId").GetInt32());
        Assert.Equal([1], rotated.Json.GetProperty("deletedKeyIds").EnumerateArray().Select(e => e.GetInt32()));
        Assert.Empty(rotated.Json.GetProperty("retiredKeyIds").EnumerateArray());
        Assert.Equal(_f.Clock.UtcNow, rotated.Json.GetProperty("signsFrom").GetDateTimeOffset());
        Assert.Equal(_f.Clock.UtcNow + VerpKeyRotation.ReloadInterval, rotated.Json.GetProperty("otherReplicasBy").GetDateTimeOffset());
        Assert.Equal(2, _codec.ActiveKeyId);
        Assert.False(_codec.TryDecode(before, _f.Clock.UtcNow, TimeSpan.FromDays(14), out _), "a revoked key verifies nothing");

        JsonElement key = Assert.Single((await _admin.GetAsync("/api/v1/admin/verp-keys")).Json.EnumerateArray());
        Assert.Equal((2, "signing"), (key.GetProperty("keyId").GetInt32(), key.GetProperty("state").GetString()));
    }

    [Fact]
    public async Task Retired_old_keys_still_verify_what_they_signed()
    {
        string before = _codec.CreateLocalPart(ApiFixture.TenantAId, Guid.NewGuid(), _f.Clock.UtcNow, "example.net");

        Reply rotated = await _admin.PostAsync("/api/v1/admin/verp-keys/rotate", new { oldKeys = "retire" });

        Assert.Equal([1], rotated.Json.GetProperty("retiredKeyIds").EnumerateArray().Select(e => e.GetInt32()));
        Assert.Empty(rotated.Json.GetProperty("deletedKeyIds").EnumerateArray());
        Assert.True(_codec.TryDecode(before, _f.Clock.UtcNow, TimeSpan.FromDays(14), out _));
        Assert.Equal(["retired", "signing"], (await _admin.GetAsync("/api/v1/admin/verp-keys")).Json.EnumerateArray().Select(k => k.GetProperty("state").GetString()));
    }

    [Fact]
    public async Task An_unknown_mode_is_refused_and_changes_nothing()
    {
        Reply refused = await _admin.PostAsync("/api/v1/admin/verp-keys/rotate", new { oldKeys = "delete" });

        refused.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["oldKeys"], refused.ErrorFields);
        Assert.Equal([1], (await _f.Storage.Config.GetVerpKeysAsync(default)).Select(k => k.KeyId));
    }

    [Fact]
    public async Task A_store_held_by_a_backend_switch_is_refused_but_a_draining_source_rotates()
    {
        IStorageTransfer transfer = _f.Storage.Transfer!;
        await transfer.SetStateAsync(new SwitchStateRecord(Guid.NewGuid(), SwitchRoles.Source, SwitchStates.Fenced, _f.Clock.UtcNow, null), default);
        Reply refused = await _admin.PostAsync("/api/v1/admin/verp-keys/rotate", new { });
        refused.Problem(HttpStatusCode.Conflict, "conflict");
        Assert.Equal([1], (await _f.Storage.Config.GetVerpKeysAsync(default)).Select(k => k.KeyId));

        await transfer.SetStateAsync(new SwitchStateRecord(Guid.NewGuid(), SwitchRoles.Target, SwitchStates.Importing, _f.Clock.UtcNow, null), default);
        (await _admin.PostAsync("/api/v1/admin/verp-keys/rotate", new { })).Problem(HttpStatusCode.Conflict, "conflict");

        // Draining still delivers what is queued, and its keys go into the bundle (decision 110 (b)).
        await transfer.SetStateAsync(new SwitchStateRecord(Guid.NewGuid(), SwitchRoles.Source, SwitchStates.Draining, _f.Clock.UtcNow, null), default);
        Assert.Equal(HttpStatusCode.OK, (await _admin.PostAsync("/api/v1/admin/verp-keys/rotate", new { })).Status);
    }

    [Fact]
    public async Task Tenant_users_cannot_list_or_rotate_the_keys()
    {
        ApiClient alice = await _f.SignedInAsync("alice");

        (await alice.GetAsync("/api/v1/admin/verp-keys")).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await alice.PostAsync("/api/v1/admin/verp-keys/rotate", new { })).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await _f.NewClient().PostAsync("/api/v1/admin/verp-keys/rotate", new { })).Problem(HttpStatusCode.Unauthorized, "unauthorized");
        Assert.Equal([1], (await _f.Storage.Config.GetVerpKeysAsync(default)).Select(k => k.KeyId));
    }

    [Fact]
    public async Task A_process_without_the_key_ring_answers_not_ready()
    {
        await using ApiFixture plain = await ApiFixture.StartAsync();
        ApiClient admin = await plain.SignedInAsync("root");

        (await admin.GetAsync("/api/v1/admin/verp-keys")).Problem(HttpStatusCode.ServiceUnavailable, "not_ready");
        (await admin.PostAsync("/api/v1/admin/verp-keys/rotate", new { })).Problem(HttpStatusCode.ServiceUnavailable, "not_ready");
    }
}
