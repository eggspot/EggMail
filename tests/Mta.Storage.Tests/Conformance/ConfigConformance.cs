using Mta.Core;

namespace Mta.Storage.Tests;

/// <summary>Configuration data: tenants, keys, domains, suppressions, endpoints, settings, certificates, leases.</summary>
public abstract class ConfigConformance : StorageTestBase
{
    private IConfigStore C => Storage.Config;

    private static readonly CancellationToken Ct = CancellationToken.None;

    private Tenant NewTenant(string name = "Acme", string? slug = null) => new(Ids.New(), name, slug ?? name.ToLowerInvariant(), true, Clock.UtcNow, false);

    // Tenants

    [Fact]
    public async Task Tenants_round_trip_and_are_found_by_id_and_slug()
    {
        var t = NewTenant("Acme Corp", "Acme-Corp");
        await C.UpsertTenantAsync(t, Ct);

        var byId = await C.GetTenantAsync(t.Id, Ct);
        Assert.Equal(t with { Slug = "acme-corp" }, byId);
        Assert.Equal(t.Id, (await C.GetTenantBySlugAsync("ACME-corp", Ct))!.Id);
        Assert.Null(await C.GetTenantAsync(Ids.New(), Ct));
        Assert.Null(await C.GetTenantBySlugAsync("nope", Ct));
    }

    [Fact]
    public async Task Tenant_upsert_replaces_and_listing_is_sorted_by_name()
    {
        var b = NewTenant("Bravo");
        var a = NewTenant("Alpha");
        await C.UpsertTenantAsync(b, Ct);
        await C.UpsertTenantAsync(a, Ct);
        await C.UpsertTenantAsync(b with { Enabled = false, StoreAttachments = true }, Ct);

        var all = await C.GetTenantsAsync(Ct);
        Assert.Equal(["Alpha", "Bravo"], all.Select(t => t.Name));
        Assert.False(all[1].Enabled);
        Assert.True(all[1].StoreAttachments);
    }

    [Fact]
    public async Task Tenant_slug_is_unique()
    {
        await C.UpsertTenantAsync(NewTenant("One", "same"), Ct);
        await Assert.ThrowsAsync<StorageConflictException>(async () => await C.UpsertTenantAsync(NewTenant("Two", "SAME"), Ct));
        Assert.Single(await C.GetTenantsAsync(Ct));
    }

    // API keys

    [Fact]
    public async Task Api_keys_are_found_by_hash_and_can_be_revoked_and_touched()
    {
        var tenant = NewTenant();
        await C.UpsertTenantAsync(tenant, Ct);
        byte[] hash = System.Security.Cryptography.SHA256.HashData("secret-key"u8);
        var key = new ApiKeyRecord(Ids.New(), tenant.Id, "ci", "eg_abc", hash, "send,read", Clock.UtcNow, null, null);
        await C.AddApiKeyAsync(key, Ct);

        Assert.Equal(key.Id, (await C.FindApiKeyAsync(hash, Ct))!.Id);
        Assert.Null(await C.FindApiKeyAsync(System.Security.Cryptography.SHA256.HashData("other"u8), Ct));
        Assert.Equal("send,read", (await C.GetApiKeysAsync(tenant.Id, Ct)).Single().Scopes);
        Assert.Empty(await C.GetApiKeysAsync(Ids.New(), Ct));

        DateTimeOffset touched = Clock.UtcNow.AddMinutes(3);
        await C.TouchApiKeyAsync(key.Id, touched, Ct);
        Assert.Equal(touched, (await C.FindApiKeyAsync(hash, Ct))!.LastUsedAt);

        Assert.False(await C.RevokeApiKeyAsync(Ids.New(), key.Id, Clock.UtcNow, Ct), "wrong tenant");
        Assert.True(await C.RevokeApiKeyAsync(tenant.Id, key.Id, Clock.UtcNow.AddMinutes(5), Ct));
        Assert.False(await C.RevokeApiKeyAsync(tenant.Id, key.Id, Clock.UtcNow.AddMinutes(6), Ct), "already revoked");
        Assert.Equal(Clock.UtcNow.AddMinutes(5), (await C.FindApiKeyAsync(hash, Ct))!.RevokedAt);
    }

    [Fact]
    public async Task Api_key_hash_is_unique()
    {
        byte[] hash = [1, 2, 3, 4];
        await C.AddApiKeyAsync(new ApiKeyRecord(Ids.New(), TenantA, "a", "p", hash, "", Clock.UtcNow, null, null), Ct);
        await Assert.ThrowsAsync<StorageConflictException>(async () =>
            await C.AddApiKeyAsync(new ApiKeyRecord(Ids.New(), TenantA, "b", "p", hash, "", Clock.UtcNow, null, null), Ct));
    }

    // SMTP credentials

    [Fact]
    public async Task Smtp_credentials_are_found_by_user_name()
    {
        var cred = new SmtpCredential(Ids.New(), TenantA, "mailer", "$argon$hash", true, Clock.UtcNow);
        await C.UpsertSmtpCredentialAsync(cred, Ct);
        Assert.Equal(cred, await C.FindSmtpCredentialAsync("mailer", Ct));
        Assert.Null(await C.FindSmtpCredentialAsync("Mailer", Ct));
        await C.UpsertSmtpCredentialAsync(cred with { Enabled = false }, Ct);
        Assert.False((await C.GetSmtpCredentialsAsync(TenantA, Ct)).Single().Enabled);
        await Assert.ThrowsAsync<StorageConflictException>(async () =>
            await C.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantB, "mailer", "x", true, Clock.UtcNow), Ct));
    }

    // Domains and DKIM

    private DomainRecord NewDomain(string name, Guid? tenant = null, DateTimeOffset? next = null) =>
        new(Ids.New(), tenant ?? TenantA, name, DomainStatus.Pending, "bounce." + name, false, Clock.UtcNow, null, next, 0, null, false, null);

    [Fact]
    public async Task Domains_round_trip_normalize_the_name_and_are_unique()
    {
        var d = NewDomain("Example.COM.");
        await C.UpsertDomainAsync(d, Ct);

        var back = (await C.FindDomainByNameAsync("EXAMPLE.com", Ct))!;
        Assert.Equal("example.com", back.Name);
        Assert.Equal(d.Id, (await C.GetDomainAsync(d.Id, Ct))!.Id);
        Assert.Equal("bounce.Example.COM.", back.ReturnPathHost);

        await C.UpsertDomainAsync(back with { Status = DomainStatus.Verified, ReturnPathVerified = true, ConsecutiveFailures = 2, LastError = "dns" }, Ct);
        var updated = (await C.GetDomainAsync(d.Id, Ct))!;
        Assert.Equal(DomainStatus.Verified, updated.Status);
        Assert.True(updated.ReturnPathVerified);
        Assert.Equal("dns", updated.LastError);

        await Assert.ThrowsAsync<StorageConflictException>(async () => await C.UpsertDomainAsync(NewDomain("example.com", TenantB), Ct));
    }

    [Fact]
    public async Task Domain_listing_can_be_filtered_by_tenant()
    {
        await C.UpsertDomainAsync(NewDomain("b.example", TenantA), Ct);
        await C.UpsertDomainAsync(NewDomain("a.example", TenantA), Ct);
        await C.UpsertDomainAsync(NewDomain("c.example", TenantB), Ct);
        Assert.Equal(["a.example", "b.example", "c.example"], (await C.GetDomainsAsync(null, Ct)).Select(d => d.Name));
        Assert.Equal(["a.example", "b.example"], (await C.GetDomainsAsync(TenantA, Ct)).Select(d => d.Name));
    }

    [Fact]
    public async Task Domains_due_for_a_check_are_returned_oldest_first_up_to_max()
    {
        await C.UpsertDomainAsync(NewDomain("never.example", next: null), Ct);
        await C.UpsertDomainAsync(NewDomain("late.example", next: Clock.UtcNow.AddHours(1)), Ct);
        await C.UpsertDomainAsync(NewDomain("due2.example", next: Clock.UtcNow.AddMinutes(-1)), Ct);
        await C.UpsertDomainAsync(NewDomain("due1.example", next: Clock.UtcNow.AddMinutes(-10)), Ct);
        await C.UpsertDomainAsync(NewDomain("due3.example", next: Clock.UtcNow), Ct);

        Assert.Equal(["due1.example", "due2.example", "due3.example"], (await C.GetDomainsDueForCheckAsync(Clock.UtcNow, 10, Ct)).Select(d => d.Name));
        Assert.Equal(["due1.example", "due2.example"], (await C.GetDomainsDueForCheckAsync(Clock.UtcNow, 2, Ct)).Select(d => d.Name));
    }

    [Fact]
    public async Task Dkim_keys_follow_the_domain_and_one_is_active_at_a_time()
    {
        var d = NewDomain("dkim.example");
        await C.UpsertDomainAsync(d, Ct);
        DkimKeyRecord K(string selector, bool active, int minute) => new(Ids.New(), d.Id, selector, [9, 9, 9], "PUBKEY", Clock.UtcNow.AddMinutes(minute), active, null);
        var k1 = K("s1", true, 0);
        var k2 = K("s2", false, 1);
        await C.AddDkimKeyAsync(k1, Ct);
        await C.AddDkimKeyAsync(k2, Ct);
        Assert.Equal(["s1", "s2"], (await C.GetDkimKeysAsync(d.Id, Ct)).Select(k => k.Selector));
        Assert.Equal<byte[]>([9, 9, 9], (await C.GetDkimKeysAsync(d.Id, Ct))[0].PrivateKeyProtected);

        DateTimeOffset at = Clock.UtcNow.AddHours(1);
        await C.SetActiveDkimKeyAsync(d.Id, k2.Id, at, Ct);
        var keys = await C.GetDkimKeysAsync(d.Id, Ct);
        Assert.False(keys[0].Active);
        Assert.Equal(at, keys[0].RetiredAt);
        Assert.True(keys[1].Active);
        Assert.Null(keys[1].RetiredAt);

        await C.SetActiveDkimKeyAsync(d.Id, k1.Id, at.AddHours(1), Ct);
        keys = await C.GetDkimKeysAsync(d.Id, Ct);
        Assert.True(keys[0].Active);
        Assert.Null(keys[0].RetiredAt);
        Assert.False(keys[1].Active);
        Assert.Equal(at.AddHours(1), keys[1].RetiredAt);

        await Assert.ThrowsAsync<KeyNotFoundException>(async () => await C.SetActiveDkimKeyAsync(d.Id, Ids.New(), at, Ct));
    }

    [Fact]
    public async Task Deleting_a_domain_removes_its_dkim_keys()
    {
        var d = NewDomain("gone.example");
        await C.UpsertDomainAsync(d, Ct);
        await C.AddDkimKeyAsync(new DkimKeyRecord(Ids.New(), d.Id, "s", [1], "P", Clock.UtcNow, true, null), Ct);
        await C.DeleteDomainAsync(d.Id, Ct);
        Assert.Null(await C.GetDomainAsync(d.Id, Ct));
        Assert.Empty(await C.GetDkimKeysAsync(d.Id, Ct));
    }

    // Suppressions

    [Fact]
    public async Task Suppressions_are_per_tenant_case_insensitive_and_removable()
    {
        await C.AddSuppressionAsync(new SuppressionRecord(TenantA, "Bounce@Example.ORG", SuppressionReason.HardBounce, "smtp 550", Clock.UtcNow, Ids.New()), Ct);

        Assert.True(await C.IsSuppressedAsync(TenantA, "bounce@example.org", Ct));
        Assert.True(await C.IsSuppressedAsync(TenantA, "BOUNCE@EXAMPLE.ORG", Ct));
        Assert.False(await C.IsSuppressedAsync(TenantB, "bounce@example.org", Ct));
        Assert.False(await C.IsSuppressedAsync(TenantA, "other@example.org", Ct));

        Assert.False(await C.RemoveSuppressionAsync(TenantB, "bounce@example.org", Ct));
        Assert.True(await C.RemoveSuppressionAsync(TenantA, "BOUNCE@example.org", Ct));
        Assert.False(await C.IsSuppressedAsync(TenantA, "bounce@example.org", Ct));
        Assert.False(await C.RemoveSuppressionAsync(TenantA, "bounce@example.org", Ct));
    }

    [Fact]
    public async Task Adding_a_suppression_twice_keeps_one_row_with_the_latest_values()
    {
        await C.AddSuppressionAsync(new SuppressionRecord(TenantA, "x@example.org", SuppressionReason.HardBounce, "first", Clock.UtcNow, null), Ct);
        await C.AddSuppressionAsync(new SuppressionRecord(TenantA, "X@example.org", SuppressionReason.Manual, "second", Clock.UtcNow.AddMinutes(1), null), Ct);
        var page = await C.GetSuppressionsAsync(TenantA, null, 10, Ct);
        var row = Assert.Single(page.Items);
        Assert.Equal(SuppressionReason.Manual, row.Reason);
        Assert.Equal("second", row.Source);
    }

    [Fact]
    public async Task Suppression_listing_pages_in_address_order()
    {
        for (int i = 0; i < 7; i++)
        {
            await C.AddSuppressionAsync(new SuppressionRecord(TenantA, $"user{i}@example.org", SuppressionReason.Manual, null, Clock.UtcNow, null), Ct);
        }

        await C.AddSuppressionAsync(new SuppressionRecord(TenantB, "other@example.org", SuppressionReason.Manual, null, Clock.UtcNow, null), Ct);

        var seen = new List<string>();
        string? cursor = null;
        int pages = 0;
        do
        {
            var page = await C.GetSuppressionsAsync(TenantA, cursor, 3, Ct);
            seen.AddRange(page.Items.Select(s => s.Address));
            cursor = page.NextCursor;
            pages++;
        }
        while (cursor is not null);

        Assert.Equal(3, pages);
        Assert.Equal(Enumerable.Range(0, 7).Select(i => $"user{i}@example.org"), seen);
    }

    // Webhook endpoints

    [Fact]
    public async Task Webhook_endpoints_round_trip_disable_and_delete()
    {
        var ep = new WebhookEndpointRecord(Ids.New(), TenantA, "https://hooks.example.com/x", [7, 7], ["message.delivered", "message.bounced"], true, null, null, Clock.UtcNow, null);
        await C.UpsertWebhookEndpointAsync(ep, Ct);
        Assert.Equal(ep.EventTypes, (await C.GetWebhookEndpointAsync(ep.Id, Ct))!.EventTypes);
        Assert.Equal<byte[]>([7, 7], (await C.GetWebhookEndpointAsync(ep.Id, Ct))!.SecretProtected);

        await C.UpsertWebhookEndpointAsync(ep with { FailingSince = Clock.UtcNow, Url = "https://hooks.example.com/y" }, Ct);
        var edited = (await C.GetWebhookEndpointsAsync(TenantA, Ct)).Single();
        Assert.Equal("https://hooks.example.com/y", edited.Url);
        Assert.Equal(Clock.UtcNow, edited.FailingSince);

        DateTimeOffset at = Clock.UtcNow.AddMinutes(1);
        await C.DisableWebhookEndpointAsync(ep.Id, "410 Gone", at, Ct);
        var disabled = (await C.GetWebhookEndpointAsync(ep.Id, Ct))!;
        Assert.False(disabled.Enabled);
        Assert.Equal("410 Gone", disabled.DisabledReason);
        Assert.Equal(at, disabled.DisabledAt);

        Assert.Empty(await C.GetWebhookEndpointsAsync(TenantB, Ct));
        await C.DeleteWebhookEndpointAsync(TenantB, ep.Id, Ct);
        Assert.NotNull(await C.GetWebhookEndpointAsync(ep.Id, Ct));
        await C.DeleteWebhookEndpointAsync(TenantA, ep.Id, Ct);
        Assert.Null(await C.GetWebhookEndpointAsync(ep.Id, Ct));
    }

    // Settings, policies, routes

    [Fact]
    public async Task Settings_are_scoped_global_or_per_tenant()
    {
        await C.SetSettingAsync(new SettingRecord("limits", null, "{\"max\":1}", Clock.UtcNow), Ct);
        await C.SetSettingAsync(new SettingRecord("limits", TenantA, "{\"max\":2}", Clock.UtcNow), Ct);
        await C.SetSettingAsync(new SettingRecord("limits", null, "{\"max\":3}", Clock.UtcNow.AddMinutes(1)), Ct);
        await C.SetSettingAsync(new SettingRecord("brand", null, "\"x\"", Clock.UtcNow), Ct);

        var global = await C.GetSettingsAsync(null, Ct);
        Assert.Equal(["brand", "limits"], global.Select(s => s.Key));
        Assert.Equal("{\"max\":3}", global.Single(s => s.Key == "limits").ValueJson);
        Assert.All(global, s => Assert.Null(s.TenantId));
        var tenant = (await C.GetSettingsAsync(TenantA, Ct)).Single();
        Assert.Equal(TenantA, tenant.TenantId);
        Assert.Equal("{\"max\":2}", tenant.ValueJson);
        Assert.Empty(await C.GetSettingsAsync(TenantB, Ct));
    }

    [Fact]
    public async Task Tls_policies_round_trip_are_unique_and_deletable()
    {
        var p = new TlsPolicyRecord(Ids.New(), "*.Bank.example", TlsLevel.Verify);
        await C.UpsertTlsPolicyAsync(p, Ct);
        await C.UpsertTlsPolicyAsync(new TlsPolicyRecord(Ids.New(), "plain.example", TlsLevel.None), Ct);
        await C.UpsertTlsPolicyAsync(p with { Level = TlsLevel.Encrypt }, Ct);

        var all = await C.GetTlsPoliciesAsync(Ct);
        Assert.Equal(["*.bank.example", "plain.example"], all.Select(x => x.DomainPattern));
        Assert.Equal(TlsLevel.Encrypt, all[0].Level);
        await Assert.ThrowsAsync<StorageConflictException>(async () => await C.UpsertTlsPolicyAsync(new TlsPolicyRecord(Ids.New(), "plain.example", TlsLevel.May), Ct));

        await C.DeleteTlsPolicyAsync(p.Id, Ct);
        Assert.Single(await C.GetTlsPoliciesAsync(Ct));
    }

    [Fact]
    public async Task Relay_routes_round_trip_in_priority_order()
    {
        var r1 = new RelayRouteRecord(Ids.New(), "backup", "smtp2.example", 2525, "starttls", "user", [5], 20, true, ["a.example", "b.example"]);
        var r2 = new RelayRouteRecord(Ids.New(), "primary", "smtp.example", 587, "starttls", null, null, 10, false, []);
        await C.UpsertRelayRouteAsync(r1, Ct);
        await C.UpsertRelayRouteAsync(r2, Ct);

        var all = await C.GetRelayRoutesAsync(Ct);
        Assert.Equal(["primary", "backup"], all.Select(r => r.Name));
        Assert.Equal(["a.example", "b.example"], all[1].Domains);
        Assert.Equal<byte[]>([5], all[1].PasswordProtected!);
        Assert.Null(all[0].PasswordProtected);

        await C.DeleteRelayRouteAsync(r2.Id, Ct);
        Assert.Equal("backup", (await C.GetRelayRoutesAsync(Ct)).Single().Name);
    }

    // Certificates and ACME

    private CertificateRecord Cert(string name, Guid? id = null) =>
        new(id ?? Ids.New(), name, ["mail.example.com", "*.example.com"], Clock.UtcNow.AddDays(-1), Clock.UtcNow.AddDays(60), "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", [4, 2], "acme", "AB:CD", true, 0, Clock.UtcNow);

    [Fact]
    public async Task Certificate_versions_increase_on_every_change_and_drive_the_poll()
    {
        Assert.Equal(0, await C.GetCertificateVersionAsync(Ct));
        var c1 = Cert("web");
        await C.UpsertCertificateAsync(c1, Ct);
        long v1 = await C.GetCertificateVersionAsync(Ct);
        Assert.True(v1 > 0);

        await C.UpsertCertificateAsync(Cert("smtp"), Ct);
        long v2 = await C.GetCertificateVersionAsync(Ct);
        Assert.True(v2 > v1);

        await C.UpsertCertificateAsync(c1 with { Thumbprint = "EF:01" }, Ct);
        long v3 = await C.GetCertificateVersionAsync(Ct);
        Assert.True(v3 > v2);

        var all = await C.GetCertificatesAsync(Ct);
        Assert.Equal(["smtp", "web"], all.Select(c => c.Name));
        var web = all.Single(c => c.Name == "web");
        Assert.Equal(v3, web.Version);
        Assert.Equal("EF:01", web.Thumbprint);
        Assert.Equal(["mail.example.com", "*.example.com"], web.Subjects);
        Assert.Equal<byte[]>([4, 2], web.PrivateKeyProtected);
        Assert.Equal(c1.NotAfter, web.NotAfter);
    }

    [Fact]
    public async Task Certificate_names_are_unique()
    {
        await C.UpsertCertificateAsync(Cert("web"), Ct);
        await Assert.ThrowsAsync<StorageConflictException>(async () => await C.UpsertCertificateAsync(Cert("web"), Ct));
    }

    [Fact]
    public async Task Acme_accounts_and_renewals_round_trip()
    {
        const string dir = "https://acme-v02.api.letsencrypt.org/directory";
        Assert.Null(await C.GetAcmeAccountAsync(dir, Ct));
        var account = new AcmeAccountRecord(Ids.New(), dir, "ops@example.com", [1, 1], "https://acme/acct/1", Clock.UtcNow);
        await C.UpsertAcmeAccountAsync(account, Ct);
        var stored = (await C.GetAcmeAccountAsync(dir, Ct))!;
        Assert.Equal(account with { AccountKeyProtected = [] }, stored with { AccountKeyProtected = [] });
        Assert.Equal<byte[]>(account.AccountKeyProtected, stored.AccountKeyProtected);
        await C.UpsertAcmeAccountAsync(account with { AccountUrl = "https://acme/acct/2" }, Ct);
        Assert.Equal("https://acme/acct/2", (await C.GetAcmeAccountAsync(dir, Ct))!.AccountUrl);

        var renewal = new AcmeRenewalRecord("web", "pending", Clock.UtcNow, Clock.UtcNow.AddDays(30), 1, "dns timeout", "{\"token\":1}", "{\"ari\":1}");
        await C.UpsertAcmeRenewalAsync(renewal, Ct);
        await C.UpsertAcmeRenewalAsync(renewal with { Status = "ok", Failures = 0, LastError = null }, Ct);
        await C.UpsertAcmeRenewalAsync(renewal with { CertificateName = "smtp" }, Ct);
        var all = await C.GetAcmeRenewalsAsync(Ct);
        Assert.Equal(["smtp", "web"], all.Select(r => r.CertificateName));
        var web = all.Single(r => r.CertificateName == "web");
        Assert.Equal("ok", web.Status);
        Assert.Null(web.LastError);
        Assert.Equal("{\"token\":1}", web.ChallengeStateJson);
    }

    // Leases

    [Fact]
    public async Task A_lease_is_exclusive_until_it_expires_and_the_fencing_token_increases()
    {
        var a = await C.TryAcquireLeaseAsync("renewal", "node-a", TimeSpan.FromMinutes(1), Clock.UtcNow, Ct);
        Assert.NotNull(a);
        Assert.Equal("node-a", a.Owner);
        Assert.Equal(Clock.UtcNow.AddMinutes(1), a.LeaseUntil);

        Assert.Null(await C.TryAcquireLeaseAsync("renewal", "node-b", TimeSpan.FromMinutes(1), Clock.UtcNow.AddSeconds(30), Ct));
        var reenter = await C.TryAcquireLeaseAsync("renewal", "node-a", TimeSpan.FromMinutes(1), Clock.UtcNow.AddSeconds(30), Ct);
        Assert.Equal(a.FencingToken, reenter!.FencingToken);

        DateTimeOffset later = Clock.UtcNow.AddMinutes(5);
        var b = await C.TryAcquireLeaseAsync("renewal", "node-b", TimeSpan.FromMinutes(1), later, Ct);
        Assert.NotNull(b);
        Assert.True(b.FencingToken > a.FencingToken);

        // The old holder can no longer renew with its stale token.
        Assert.False(await C.RenewLeaseAsync("renewal", "node-a", a.FencingToken, TimeSpan.FromMinutes(1), later, Ct));
        Assert.True(await C.RenewLeaseAsync("renewal", "node-b", b.FencingToken, TimeSpan.FromMinutes(1), later.AddSeconds(30), Ct));
        Assert.False(await C.RenewLeaseAsync("renewal", "node-b", b.FencingToken + 1, TimeSpan.FromMinutes(1), later.AddSeconds(30), Ct));
        Assert.False(await C.RenewLeaseAsync("unknown", "node-b", 1, TimeSpan.FromMinutes(1), later, Ct));
    }

    [Fact]
    public async Task Leases_with_different_names_are_independent()
    {
        Assert.NotNull(await C.TryAcquireLeaseAsync("one", "a", TimeSpan.FromMinutes(1), Clock.UtcNow, Ct));
        Assert.NotNull(await C.TryAcquireLeaseAsync("two", "b", TimeSpan.FromMinutes(1), Clock.UtcNow, Ct));
    }

    [Fact]
    public async Task A_released_lease_can_be_taken_over_and_tokens_never_go_backwards()
    {
        var a = (await C.TryAcquireLeaseAsync("job", "node-a", TimeSpan.FromHours(1), Clock.UtcNow, Ct))!;
        await C.ReleaseLeaseAsync("job", "node-b", Ct);
        Assert.Null(await C.TryAcquireLeaseAsync("job", "node-b", TimeSpan.FromHours(1), Clock.UtcNow, Ct));

        await C.ReleaseLeaseAsync("job", "node-a", Ct);
        var b = await C.TryAcquireLeaseAsync("job", "node-b", TimeSpan.FromHours(1), Clock.UtcNow, Ct);
        Assert.NotNull(b);
        Assert.True(b.FencingToken > a.FencingToken);
    }

    [Fact]
    public async Task Racing_lease_acquisitions_have_exactly_one_winner()
    {
        var results = await Task.WhenAll(Enumerable.Range(0, 16).Select(i =>
            C.TryAcquireLeaseAsync("race", "node-" + i, TimeSpan.FromMinutes(5), Clock.UtcNow, Ct).AsTask()));
        Assert.Single(results, r => r is not null);
    }

    // Switch state

    [Fact]
    public async Task Switch_state_is_a_single_replaceable_row()
    {
        Assert.Null(await C.GetSwitchStateAsync(Ct));
        var s1 = new SwitchStateRecord(Ids.New(), "source", "fenced", Clock.UtcNow, "exporting");
        await C.SetSwitchStateAsync(s1, Ct);
        Assert.Equal(s1, await C.GetSwitchStateAsync(Ct));
        var s2 = s1 with { State = "finalized", Detail = null };
        await C.SetSwitchStateAsync(s2, Ct);
        Assert.Equal(s2, await C.GetSwitchStateAsync(Ct));
    }
}
