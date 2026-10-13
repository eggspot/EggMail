using System.Net;
using System.Text.Json;
using Mta.Host.Api;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

/// <summary>
/// Domain verification across restarts and replicas: the per-record results of the last check are persisted, and a check or rotation holds a lease so two replicas never run one at the same time.
/// A restart or a second replica is a second API server over the storage and clock of the first (<see cref="ApiFixtureOptions.SharedWith"/>).
/// </summary>
[Collection("api")]
public class ApiDomainsPersistenceTests : IAsyncLifetime
{
    private ApiFixture _first = null!;
    private ApiFixture _second = null!;
    private ApiClient _a1 = null!;
    private ApiClient _a2 = null!;

    public async Task InitializeAsync()
    {
        _first = await ApiFixture.StartAsync();
        _second = await ApiFixture.StartAsync(new ApiFixtureOptions { SharedWith = _first });
        _a1 = await _first.KeyClientAsync(ApiFixture.TenantAId);
        _a2 = await _second.KeyClientAsync(ApiFixture.TenantAId);
    }

    public async Task DisposeAsync()
    {
        await _second.DisposeAsync();
        await _first.DisposeAsync();
    }

    private static JsonElement Record(JsonElement domain, string purpose) =>
        domain.GetProperty("records").EnumerateArray().Single(r => r.GetProperty("purpose").GetString() == purpose);

    private async Task<(string Id, JsonElement Domain)> CreateAsync(string name = "new.example")
    {
        Reply r = await _a1.PostAsync("/api/v1/domains", new { name });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        return (r.Str("id"), r.Json.Clone());
    }

    private void Publish(JsonElement domain, MutableDns dns, params string[] purposes)
    {
        foreach (JsonElement rec in domain.GetProperty("records").EnumerateArray().Where(r => purposes.Contains(r.GetProperty("purpose").GetString())))
        {
            if (rec.GetProperty("type").GetString() == "CNAME")
            {
                dns.AddCname(rec.GetProperty("host").GetString()!, rec.GetProperty("value").GetString()!);
            }
            else
            {
                dns.AddTxt(rec.GetProperty("host").GetString()!, rec.GetProperty("value").GetString()!);
            }
        }
    }

    [Fact]
    public async Task After_a_restart_the_domain_shows_what_the_last_check_really_found()
    {
        var (id, created) = await CreateAsync();
        Publish(created, _first.Dns, "dkim", "return_path");
        Reply checkedNow = await _a1.PostAsync($"/api/v1/domains/{id}/verify");
        Assert.Equal("verified", checkedNow.Str("status"));

        // The second server knows nothing from memory: the answer comes from the stored check results. Before they were stored a verified domain
        // showed its required records as ok and everything else as pending.
        JsonElement after = (await _a2.GetAsync($"/api/v1/domains/{id}")).Json.Clone();
        Assert.Equal("ok", Record(after, "dkim").GetProperty("status").GetString());
        Assert.StartsWith("v=DKIM1", Record(after, "dkim").GetProperty("found").GetString());
        Assert.Equal("ok", Record(after, "return_path").GetProperty("status").GetString());
        Assert.Equal("missing", Record(after, "spf").GetProperty("status").GetString());
        Assert.Equal("missing", Record(after, "dmarc").GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, Record(after, "spf").GetProperty("found").ValueKind);
    }

    [Fact]
    public async Task A_wrong_record_keeps_its_found_value_and_invalid_status_after_a_restart()
    {
        var (id, created) = await CreateAsync();
        string host = Record(created, "dkim").GetProperty("host").GetString()!;
        _first.Dns.AddTxt(host, "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwrong");
        await _a1.PostAsync($"/api/v1/domains/{id}/verify");

        JsonElement after = (await _a2.GetAsync($"/api/v1/domains/{id}")).Json.Clone();
        Assert.Equal("invalid", Record(after, "dkim").GetProperty("status").GetString());
        Assert.Contains("wrong", Record(after, "dkim").GetProperty("found").GetString());
        Assert.Equal("missing", Record(after, "return_path").GetProperty("status").GetString());
        Assert.Equal("verifying", after.GetProperty("status").GetString());
    }

    [Fact]
    public async Task A_dns_outage_leaves_the_stored_results_of_the_records_it_could_not_look_up()
    {
        var (id, created) = await CreateAsync();
        Publish(created, _first.Dns, "dkim", "return_path");
        await _a1.PostAsync($"/api/v1/domains/{id}/verify");

        _first.Clock.Advance(TimeSpan.FromMinutes(1));
        _first.Dns.ServerFailure = true;
        Reply outage = await _a1.PostAsync($"/api/v1/domains/{id}/verify");
        Assert.Equal(HttpStatusCode.OK, outage.Status);

        JsonElement after = (await _a2.GetAsync($"/api/v1/domains/{id}")).Json.Clone();
        Assert.Equal("verified", after.GetProperty("status").GetString());
        Assert.Equal("ok", Record(after, "dkim").GetProperty("status").GetString());
        Assert.Equal("ok", Record(after, "return_path").GetProperty("status").GetString());
        Assert.Equal("missing", Record(after, "spf").GetProperty("status").GetString());
    }

    [Fact]
    public async Task Deleting_a_domain_removes_its_stored_check_results()
    {
        var (id, _) = await CreateAsync();
        await _a1.PostAsync($"/api/v1/domains/{id}/verify");
        Guid domainId = Guid.ParseExact(id, "N");
        Assert.NotEmpty(await _first.Storage.Config.GetDomainRecordChecksAsync(domainId, default));

        Assert.Equal(HttpStatusCode.NoContent, (await _a1.DeleteAsync($"/api/v1/domains/{id}")).Status);
        Assert.Empty(await _first.Storage.Config.GetDomainRecordChecksAsync(domainId, default));
    }

    [Fact]
    public async Task A_domain_that_another_replica_is_checking_is_not_checked_or_rotated_here()
    {
        var (id, _) = await CreateAsync();
        Guid domainId = Guid.ParseExact(id, "N");
        _first.Clock.Advance(TimeSpan.FromSeconds(31));

        IAsyncDisposable? held = await _first.Get<DomainVerificationService>().TryLockAsync(domainId, default);
        Assert.NotNull(held);
        try
        {
            // The same replica refuses too (the in-process guard), and so does the other one (the lease in the store).
            Assert.Null(await _first.Get<DomainVerificationService>().TryLockAsync(domainId, default));
            Assert.Null(await _second.Get<DomainVerificationService>().TryLockAsync(domainId, default));
            (await _a2.PostAsync($"/api/v1/domains/{id}/verify")).Problem(HttpStatusCode.TooManyRequests, "rate_limited");
            (await _a2.PostAsync($"/api/v1/domains/{id}/dkim/rotate")).Problem(HttpStatusCode.Conflict, "conflict");

            // The scheduled pass of the other replica leaves it alone as well.
            _first.Clock.Advance(TimeSpan.FromMinutes(1));   // the first check is due now (90 s after creation), the lease (2 min) still holds
            Assert.Equal(0, await _second.Get<DomainVerificationService>().RunDueChecksAsync(default));
            Assert.Empty(await _first.Storage.Config.GetDomainRecordChecksAsync(domainId, default));
        }
        finally
        {
            await held!.DisposeAsync();
        }

        Assert.Equal(HttpStatusCode.OK, (await _a2.PostAsync($"/api/v1/domains/{id}/verify")).Status);
        Assert.Equal(HttpStatusCode.OK, (await _a2.PostAsync($"/api/v1/domains/{id}/dkim/rotate")).Status);
    }

    [Fact]
    public async Task A_domain_is_not_deleted_while_a_check_of_it_runs_on_another_replica()
    {
        var (id, _) = await CreateAsync();
        Guid domainId = Guid.ParseExact(id, "N");
        IAsyncDisposable? held = await _first.Get<DomainVerificationService>().TryLockAsync(domainId, default);
        Assert.NotNull(held);
        (await _a2.DeleteAsync($"/api/v1/domains/{id}")).Problem(HttpStatusCode.Conflict, "conflict");
        await held!.DisposeAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await _a2.DeleteAsync($"/api/v1/domains/{id}")).Status);
    }

    [Fact]
    public async Task A_replica_that_died_holding_the_lock_frees_the_domain_when_the_lease_expires()
    {
        var (id, _) = await CreateAsync();
        Guid domainId = Guid.ParseExact(id, "N");
        // A lease taken by a process that is gone (nobody releases it).
        Assert.NotNull(await _first.Storage.Config.TryAcquireLeaseAsync("domain-verification:" + domainId.ToString("N"), "dead-replica", DomainVerificationService.LockDuration, _first.Clock.UtcNow, default));
        _first.Clock.Advance(TimeSpan.FromSeconds(31));
        (await _a2.PostAsync($"/api/v1/domains/{id}/verify")).Problem(HttpStatusCode.TooManyRequests, "rate_limited");

        _first.Clock.Advance(DomainVerificationService.LockDuration + TimeSpan.FromSeconds(1));
        Assert.Equal(HttpStatusCode.OK, (await _a2.PostAsync($"/api/v1/domains/{id}/verify")).Status);
    }

    [Fact]
    public async Task The_scheduled_pass_skips_a_domain_another_replica_just_checked()
    {
        var (id, _) = await CreateAsync();
        Guid domainId = Guid.ParseExact(id, "N");
        _first.Clock.Advance(TimeSpan.FromMinutes(2));   // the first check is due (90 s after creation)
        DomainRecord due = (await _first.Storage.Config.GetDomainAsync(domainId, default))!;
        Assert.True(due.NextCheckAt <= _first.Clock.UtcNow);

        Assert.Equal(1, await _first.Get<DomainVerificationService>().RunDueChecksAsync(default));
        // The second replica read the due list before the first one finished: the domain is not due any more, so it is not checked twice.
        Assert.Equal(0, await _second.Get<DomainVerificationService>().RunDueChecksAsync(default));
    }
}
