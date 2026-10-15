using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Mta.Core;
using Mta.Dkim;
using Mta.Host.Api;
using Mta.Storage;

namespace Mta.Host.Tests.Api;

[Collection("api")]
public class ApiDomainsTests : IAsyncLifetime
{
    private ApiFixture _f = null!;
    private ApiClient _a = null!;

    public async Task InitializeAsync()
    {
        _f = await ApiFixture.StartAsync();
        _a = await _f.KeyClientAsync(ApiFixture.TenantAId);
    }

    public async Task DisposeAsync() => await _f.DisposeAsync();

    private DomainVerificationService Verification => _f.Get<DomainVerificationService>();

    private async Task<JsonElement> CreateAsync(string name = "new.example", ApiClient? client = null)
    {
        Reply r = await (client ?? _a).PostAsync("/api/v1/domains", new { name });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        return r.Json.Clone();
    }

    private void Publish(JsonElement domain, params string[] purposes)
    {
        foreach (JsonElement rec in domain.GetProperty("records").EnumerateArray())
        {
            if (!purposes.Contains(rec.GetProperty("purpose").GetString()))
            {
                continue;
            }

            string host = rec.GetProperty("host").GetString()!;
            string value = rec.GetProperty("value").GetString()!;
            switch (rec.GetProperty("type").GetString())
            {
                case "CNAME":
                    _f.Dns.AddCname(host, value);
                    break;
                case "MX":
                    _f.Dns.AddMx(host, ushort.Parse(value.Split(' ')[0]), value.Split(' ')[1]);
                    break;
                default:
                    _f.Dns.AddTxt(host, value);
                    break;
            }
        }
    }

    private static string StatusOf(JsonElement domain, string purpose, int index = 0) =>
        domain.GetProperty("records").EnumerateArray().Where(r => r.GetProperty("purpose").GetString() == purpose).ElementAt(index).GetProperty("status").GetString()!;

    private async Task<JsonElement> VerifyAsync(string id, ApiClient? client = null)
    {
        Reply r = await (client ?? _a).PostAsync($"/api/v1/domains/{id}/verify");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        return r.Json.Clone();
    }

    // Create

    [Fact]
    public async Task Creating_a_domain_generates_a_dkim_key_and_lists_the_records_to_publish()
    {
        Reply r = await _a.PostAsync("/api/v1/domains", new { name = "  Mail.Example.COM. " });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        Assert.Matches("^/api/v1/domains/[0-9a-f]{32}$", r.Header("Location"));
        Assert.Matches("^[0-9a-f]{32}$", r.Str("id"));
        Assert.Equal("mail.example.com", r.Str("name"));
        Assert.Equal("pending", r.Str("status"));
        Assert.False(r["sendingPaused"].GetBoolean());
        Assert.Equal(JsonValueKind.Null, r["lastCheckedAt"].ValueKind);
        Assert.Equal(JsonValueKind.Null, r["lastError"].ValueKind);
        Assert.Equal("2026-10-12T12:31:30.000Z", r.Str("nextCheckAt")); // first check after the 90 s initial interval

        JsonElement[] records = r["records"].EnumerateArray().ToArray();
        Assert.Equal(["dkim", "return_path", "spf", "dmarc", "tls_rpt"], records.Select(x => x.GetProperty("purpose").GetString()!));
        Assert.False(r["readyToSend"].GetBoolean());   // pending: sending is blocked until the required records are found
        Assert.Equal("_smtp._tls.mail.example.com", records[4].GetProperty("host").GetString());
        Assert.Equal("v=TLSRPTv1; rua=mailto:tls-rpt@mail.example.com", records[4].GetProperty("value").GetString());
        Assert.All(records, rec => Assert.False(string.IsNullOrWhiteSpace(rec.GetProperty("note").GetString())));
        JsonElement dkim = records[0];
        Assert.Equal("TXT", dkim.GetProperty("type").GetString());
        Assert.Equal("egg202610._domainkey.mail.example.com", dkim.GetProperty("host").GetString());
        Assert.StartsWith("v=DKIM1; k=rsa; p=", dkim.GetProperty("value").GetString());
        Assert.Equal(dkim.GetProperty("value").GetString(), dkim.GetProperty("expected").GetString());
        Assert.Equal(3600, dkim.GetProperty("ttl").GetInt32());
        Assert.Equal("pending", dkim.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, dkim.GetProperty("found").ValueKind);
        Assert.True(dkim.GetProperty("required").GetBoolean());
        Assert.Equal(("CNAME", "bounce.mail.example.com", "bounces.egg.test"), (records[1].GetProperty("type").GetString()!, records[1].GetProperty("host").GetString()!, records[1].GetProperty("value").GetString()!));
        Assert.Equal("v=spf1 ~all", records[2].GetProperty("value").GetString());
        Assert.Equal("_dmarc.mail.example.com", records[3].GetProperty("host").GetString());
        Assert.False(records[2].GetProperty("required").GetBoolean());
        Assert.False(records[3].GetProperty("required").GetBoolean());

        JsonElement key = r["dkim"];
        Assert.Equal("egg202610", key.GetProperty("selector").GetString());
        Assert.True(key.GetProperty("active").GetBoolean());
        Assert.EndsWith(key.GetProperty("publicKey").GetString()!, dkim.GetProperty("value").GetString());
        using RSA publicKey = RSA.Create();
        publicKey.ImportSubjectPublicKeyInfo(Convert.FromBase64String(key.GetProperty("publicKey").GetString()!), out _);
        Assert.Equal(2048, publicKey.KeySize);
    }

    [Fact]
    public async Task The_private_key_is_stored_protected_and_belongs_to_the_published_public_key()
    {
        JsonElement domain = await CreateAsync();
        Guid id = Guid.Parse(domain.GetProperty("id").GetString()!);
        Mta.Storage.DkimKeyRecord key = Assert.Single(await _f.Storage.Config.GetDkimKeysAsync(id, default));
        Assert.True(key.Active);
        Assert.Null(key.RetiredAt);
        Assert.Equal(domain.GetProperty("dkim").GetProperty("publicKey").GetString(), key.PublicKeyBase64);

        byte[] der = _f.Protector.Unprotect(key.PrivateKeyProtected, SecretPurposes.DkimKey);
        using RSA rsa = DkimKeyTools.LoadPrivateKeyDer(der);
        Assert.Equal(2048, rsa.KeySize);
        Assert.Equal(key.PublicKeyBase64, DkimKeyTools.ExportPublicKeyBase64(rsa));
        Assert.NotEqual(der, key.PrivateKeyProtected);
        Assert.ThrowsAny<CryptographicException>((Action)(() => _f.Protector.Unprotect(key.PrivateKeyProtected, SecretPurposes.WebhookSecret)));

        // The secret never appears in any response.
        Assert.DoesNotContain(Convert.ToBase64String(der), domain.GetRawText());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("localhost")]
    [InlineData("1.2.3.4")]
    [InlineData("[1.2.3.4]")]
    [InlineData("a_b.example")]
    [InlineData("-bad.example")]
    [InlineData("bad..example")]
    [InlineData("has space.example")]
    [InlineData("user@example.com")]
    public async Task Invalid_domain_names_are_validation_failed(string name)
    {
        Reply r = await _a.PostAsync("/api/v1/domains", new { name });
        r.Problem(HttpStatusCode.BadRequest, "validation_failed");
        Assert.Equal(["name"], r.ErrorFields);
    }

    [Fact]
    public async Task International_names_are_stored_as_a_labels()
    {
        Reply r = await _a.PostAsync("/api/v1/domains", new { name = "bücher.example" });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        Assert.Equal("xn--bcher-kva.example", r.Str("name"));
    }

    [Fact]
    public async Task A_domain_can_be_registered_once()
    {
        await CreateAsync("dup.example");
        Reply again = await _a.PostAsync("/api/v1/domains", new { name = "DUP.example" });
        again.Problem(HttpStatusCode.BadRequest, "validation_failed");
        ApiClient b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        (await b.PostAsync("/api/v1/domains", new { name = "dup.example" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
        (await _a.PostAsync("/api/v1/domains", new { name = "example.com" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    [Fact]
    public async Task The_number_of_domains_per_tenant_is_limited()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { ConfigureApi = o => o.MaxDomainsPerTenant = 3 });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        Assert.Equal(HttpStatusCode.Created, (await c.PostAsync("/api/v1/domains", new { name = "one.example" })).Status);
        Assert.Equal(HttpStatusCode.Created, (await c.PostAsync("/api/v1/domains", new { name = "two.example" })).Status);
        (await c.PostAsync("/api/v1/domains", new { name = "three.example" })).Problem(HttpStatusCode.BadRequest, "validation_failed");
    }

    // Read / delete / isolation

    [Fact]
    public async Task Listing_and_reading_are_limited_to_the_callers_tenant()
    {
        JsonElement mine = await CreateAsync("mine.example");
        ApiClient b = await _f.KeyClientAsync(ApiFixture.TenantBId);
        JsonElement theirs = await CreateAsync("theirs.example", b);

        Reply list = await _a.GetAsync("/api/v1/domains");
        Assert.Equal(["example.com", "mine.example"], list.Json.EnumerateArray().Select(d => d.GetProperty("name").GetString()!));

        Assert.Equal("mine.example", (await _a.GetAsync("/api/v1/domains/" + mine.GetProperty("id").GetString())).Str("name"));
        string theirId = theirs.GetProperty("id").GetString()!;
        (await _a.GetAsync("/api/v1/domains/" + theirId)).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.GetAsync("/api/v1/domains/not-an-id")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.PostAsync($"/api/v1/domains/{theirId}/verify")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.PostAsync($"/api/v1/domains/{theirId}/dkim/rotate")).Problem(HttpStatusCode.NotFound, "not_found");
        (await _a.DeleteAsync("/api/v1/domains/" + theirId)).Problem(HttpStatusCode.NotFound, "not_found");

        // The foreign domain is untouched by the attempts.
        Assert.NotNull(await _f.Storage.Config.GetDomainAsync(Guid.Parse(theirId), default));
        Assert.Single(await _f.Storage.Config.GetDkimKeysAsync(Guid.Parse(theirId), default));
    }

    [Fact]
    public async Task Deleting_a_domain_removes_it_and_its_keys()
    {
        JsonElement d = await CreateAsync("gone.example");
        Guid id = Guid.Parse(d.GetProperty("id").GetString()!);
        Assert.Equal(HttpStatusCode.NoContent, (await _a.DeleteAsync("/api/v1/domains/" + id.ToString("N"))).Status);
        (await _a.GetAsync("/api/v1/domains/" + id.ToString("N"))).Problem(HttpStatusCode.NotFound, "not_found");
        Assert.Empty(await _f.Storage.Config.GetDkimKeysAsync(id, default));
        (await _a.DeleteAsync("/api/v1/domains/" + id.ToString("N"))).Problem(HttpStatusCode.NotFound, "not_found");
    }

    [Fact]
    public async Task Domains_need_the_domains_scope()
    {
        ApiClient c = await _f.KeyClientAsync(ApiFixture.TenantAId, "read", "send");
        (await c.GetAsync("/api/v1/domains")).Problem(HttpStatusCode.Forbidden, "forbidden");
        (await c.PostAsync("/api/v1/domains", new { name = "x.example" })).Problem(HttpStatusCode.Forbidden, "forbidden");
    }

    // Verification

    [Fact]
    public async Task Verify_now_checks_dns_and_reports_each_record()
    {
        JsonElement d = await CreateAsync();
        string id = d.GetProperty("id").GetString()!;

        JsonElement first = await VerifyAsync(id);
        Assert.Equal("verifying", first.GetProperty("status").GetString());
        Assert.Equal("missing", StatusOf(first, "dkim"));
        Assert.Equal("missing", StatusOf(first, "return_path"));
        Assert.Contains("Dkim record egg202610._domainkey.new.example is missing", first.GetProperty("lastError").GetString());
        Assert.Equal("2026-10-12T12:30:00.000Z", first.GetProperty("lastCheckedAt").GetString());

        Publish(d, "dkim", "return_path");
        _f.Clock.Advance(TimeSpan.FromSeconds(31));
        JsonElement second = await VerifyAsync(id);
        Assert.Equal("verified", second.GetProperty("status").GetString());
        Assert.Equal("ok", StatusOf(second, "dkim"));
        Assert.Equal("ok", StatusOf(second, "return_path"));
        Assert.Equal("missing", StatusOf(second, "spf")); // advice only: does not block verification
        Assert.Equal("missing", StatusOf(second, "dmarc"));
        Assert.Equal(JsonValueKind.Null, second.GetProperty("lastError").ValueKind);
        Assert.True(second.GetProperty("returnPathVerified").GetBoolean());
        Assert.StartsWith("v=DKIM1", second.GetProperty("records")[0].GetProperty("found").GetString());
        Assert.Equal("2026-10-13T12:30:31.000Z", second.GetProperty("nextCheckAt").GetString()); // daily once verified
    }

    [Fact]
    public async Task A_dkim_value_that_is_not_a_key_is_invalid_with_what_was_found()
    {
        JsonElement d = await CreateAsync();
        string host = d.GetProperty("records")[0].GetProperty("host").GetString()!;
        _f.Dns.AddTxt(host, "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwrong");
        JsonElement r = await VerifyAsync(d.GetProperty("id").GetString()!);
        Assert.Equal("invalid", StatusOf(r, "dkim"));
        Assert.Contains("wrong", r.GetProperty("records")[0].GetProperty("found").GetString());
        Assert.Equal("verifying", r.GetProperty("status").GetString());
    }

    [Fact]
    public async Task Verify_now_is_limited_to_once_per_30_seconds_per_domain()
    {
        JsonElement d = await CreateAsync();
        string id = d.GetProperty("id").GetString()!;
        await VerifyAsync(id);

        _f.Clock.Advance(TimeSpan.FromSeconds(10));
        Reply limited = await _a.PostAsync($"/api/v1/domains/{id}/verify");
        limited.Problem(HttpStatusCode.TooManyRequests, "rate_limited");
        Assert.Equal("20", limited.Header("Retry-After"));

        // Another domain has its own budget.
        JsonElement other = await CreateAsync("other.example");
        await VerifyAsync(other.GetProperty("id").GetString()!);

        _f.Clock.Advance(TimeSpan.FromSeconds(20));
        Assert.Equal(HttpStatusCode.OK, (await _a.PostAsync($"/api/v1/domains/{id}/verify")).Status);
    }

    [Fact]
    public async Task The_scheduler_checks_domains_that_are_due()
    {
        JsonElement d = await CreateAsync();
        Publish(d, "dkim", "return_path");
        Assert.Equal(0, await Verification.RunDueChecksAsync(default)); // not due yet (first check after 90 s)

        _f.Clock.Advance(TimeSpan.FromSeconds(91));
        Assert.Equal(1, await Verification.RunDueChecksAsync(default));
        Reply r = await _a.GetAsync("/api/v1/domains/" + d.GetProperty("id").GetString());
        Assert.Equal("verified", r.Str("status"));
        Assert.Equal("ok", StatusOf(r.Json, "dkim")); // the per-record outcome of the scheduled check is remembered
        Assert.Equal(0, await Verification.RunDueChecksAsync(default));
    }

    [Fact]
    public async Task An_unverified_domain_is_rechecked_fast_then_slower()
    {
        JsonElement d = await CreateAsync();
        Guid id = Guid.Parse(d.GetProperty("id").GetString()!);
        _f.Clock.Advance(TimeSpan.FromSeconds(91));
        await Verification.RunDueChecksAsync(default);
        var after = (await _f.Storage.Config.GetDomainAsync(id, default))!;
        Assert.Equal(DomainStatus.Verifying, after.Status);
        Assert.Equal(_f.Clock.UtcNow.AddSeconds(90), after.NextCheckAt);

        _f.Clock.Advance(TimeSpan.FromMinutes(20));
        await Verification.RunDueChecksAsync(default);
        after = (await _f.Storage.Config.GetDomainAsync(id, default))!;
        Assert.Equal(_f.Clock.UtcNow.AddMinutes(15), after.NextCheckAt);
    }

    [Fact]
    public async Task A_verified_domain_degrades_after_two_failed_checks_and_keeps_sending()
    {
        JsonElement d = await CreateAsync();
        Publish(d, "dkim", "return_path");
        string id = d.GetProperty("id").GetString()!;
        await VerifyAsync(id);
        Assert.Equal("verified", (await _a.GetAsync("/api/v1/domains/" + id)).Str("status"));

        _f.Dns.RemoveAll(d.GetProperty("records")[0].GetProperty("host").GetString()!);
        _f.Clock.Advance(TimeSpan.FromSeconds(31));
        JsonElement one = await VerifyAsync(id);
        Assert.Equal("verified", one.GetProperty("status").GetString()); // one failure is confirmed first
        Assert.Equal("missing", StatusOf(one, "dkim"));

        _f.Clock.Advance(TimeSpan.FromMinutes(16));
        JsonElement two = await VerifyAsync(id);
        Assert.Equal("temporary_failure", two.GetProperty("status").GetString());
        Assert.False(two.GetProperty("sendingPaused").GetBoolean());
        Assert.NotEqual(JsonValueKind.Null, two.GetProperty("lastError").ValueKind);

        Reply send = await _a.PostAsync("/api/v1/messages", new { from = "x@new.example", to = new[] { "a@gmail.test" }, subject = "s", text = "t" });
        Assert.Equal(HttpStatusCode.Accepted, send.Status); // temporary failure still sends (with a banner in the dashboard)
    }

    [Fact]
    public async Task A_domain_that_stays_broken_fails_after_the_grace_period_and_pauses_sending_until_it_recovers()
    {
        JsonElement d = await CreateAsync();
        Publish(d, "dkim", "return_path");
        string id = d.GetProperty("id").GetString()!;
        await VerifyAsync(id);
        _f.Dns.RemoveAll(d.GetProperty("records")[0].GetProperty("host").GetString()!);

        for (int i = 0; i < 2; i++)
        {
            _f.Clock.Advance(TimeSpan.FromMinutes(16));
            await VerifyAsync(id);
        }

        Assert.Equal("temporary_failure", (await _a.GetAsync("/api/v1/domains/" + id)).Str("status"));
        _f.Clock.Advance(TimeSpan.FromHours(73));
        JsonElement failed = await VerifyAsync(id);
        Assert.Equal("failed", failed.GetProperty("status").GetString());
        Assert.True(failed.GetProperty("sendingPaused").GetBoolean());

        Reply send = await _a.PostAsync("/api/v1/messages", new { from = "x@new.example", to = new[] { "a@gmail.test" }, subject = "s", text = "t" });
        send.Problem(HttpStatusCode.Forbidden, "domain_not_verified");

        // The records come back: verified again and the pause is lifted.
        Publish(d, "dkim");
        _f.Clock.Advance(TimeSpan.FromSeconds(31));
        JsonElement recovered = await VerifyAsync(id);
        Assert.Equal("verified", recovered.GetProperty("status").GetString());
        Assert.False(recovered.GetProperty("sendingPaused").GetBoolean());
        Assert.Equal(HttpStatusCode.Accepted, (await _a.PostAsync("/api/v1/messages", new { from = "x@new.example", to = new[] { "a@gmail.test" }, subject = "s", text = "t" })).Status);
    }

    [Fact]
    public async Task A_dns_outage_never_changes_the_state_of_a_domain()
    {
        JsonElement d = await CreateAsync();
        Publish(d, "dkim", "return_path");
        string id = d.GetProperty("id").GetString()!;
        await VerifyAsync(id);

        _f.Dns.ServerFailure = true;
        for (int i = 0; i < 4; i++)
        {
            _f.Clock.Advance(TimeSpan.FromMinutes(6));
            JsonElement r = await VerifyAsync(id);
            Assert.Equal("verified", r.GetProperty("status").GetString());
        }

        var stored = (await _f.Storage.Config.GetDomainAsync(Guid.Parse(id), default))!;
        Assert.Equal(0, stored.ConsecutiveFailures);
        Assert.Equal(_f.Clock.UtcNow.AddMinutes(5), stored.NextCheckAt); // looks again soon
    }

    // Rotation

    [Fact]
    public async Task Rotating_publishes_the_next_selector_and_keeps_signing_with_the_current_key_until_it_is_found_in_dns()
    {
        JsonElement d = await CreateAsync();
        Publish(d, "dkim", "return_path");
        string id = d.GetProperty("id").GetString()!;
        await VerifyAsync(id);

        _f.Clock.Advance(TimeSpan.FromDays(1)); // rotations happen long after creation; keys are ordered by creation time
        Reply rotated = await _a.PostAsync($"/api/v1/domains/{id}/dkim/rotate");
        Assert.Equal(HttpStatusCode.OK, rotated.Status);
        Assert.Equal("verified", rotated.Str("status"));
        JsonElement[] dkimRecords = rotated["records"].EnumerateArray().Where(x => x.GetProperty("purpose").GetString() == "dkim").ToArray();
        Assert.Equal(["egg202610._domainkey.new.example", "egg202610-2._domainkey.new.example"], dkimRecords.Select(x => x.GetProperty("host").GetString()!));
        Assert.True(dkimRecords[0].GetProperty("required").GetBoolean());
        Assert.False(dkimRecords[1].GetProperty("required").GetBoolean()); // advice until it signs
        Assert.Equal("pending", dkimRecords[1].GetProperty("status").GetString());
        Assert.Equal("egg202610-2", rotated["dkim"].GetProperty("selector").GetString()); // the key the customer must publish now
        Assert.False(rotated["dkim"].GetProperty("active").GetBoolean());
        Assert.Equal(2, rotated["dkimKeys"].GetArrayLength());

        var keys = await _f.Storage.Config.GetDkimKeysAsync(Guid.Parse(id), default);
        Assert.Equal([true, false], keys.Select(k => k.Active));
        Assert.All(keys, k => Assert.Null(k.RetiredAt));

        // The new record is not published yet: the domain stays verified and keeps signing with the first key.
        _f.Clock.Advance(TimeSpan.FromSeconds(31));
        JsonElement still = await VerifyAsync(id);
        Assert.Equal("verified", still.GetProperty("status").GetString());
        Assert.Equal([true, false], (await _f.Storage.Config.GetDkimKeysAsync(Guid.Parse(id), default)).Select(k => k.Active));

        // Rotating again while one is pending is refused.
        (await _a.PostAsync($"/api/v1/domains/{id}/dkim/rotate")).Problem(HttpStatusCode.Conflict, "conflict");

        // Publish the new record: the next check switches signing and retires the old key.
        Publish(rotated.Json.Clone(), "dkim");
        _f.Clock.Advance(TimeSpan.FromSeconds(31));
        JsonElement switched = await VerifyAsync(id);
        Assert.Equal("egg202610-2", switched.GetProperty("dkim").GetProperty("selector").GetString());
        Assert.True(switched.GetProperty("dkim").GetProperty("active").GetBoolean());
        keys = await _f.Storage.Config.GetDkimKeysAsync(Guid.Parse(id), default);
        Assert.Equal([false, true], keys.Select(k => k.Active));
        Assert.Equal(_f.Clock.UtcNow, keys[0].RetiredAt);
        Assert.Null(keys[1].RetiredAt);

        // The retired key stays published for at least 7 days, then drops out of the list.
        _f.Clock.Advance(TimeSpan.FromDays(6));
        Assert.Equal(2, (await _a.GetAsync($"/api/v1/domains/{id}"))["records"].EnumerateArray().Count(x => x.GetProperty("purpose").GetString() == "dkim"));
        _f.Clock.Advance(TimeSpan.FromDays(2));
        Reply later = await _a.GetAsync($"/api/v1/domains/{id}");
        Assert.Equal(["egg202610-2._domainkey.new.example"], later["records"].EnumerateArray().Where(x => x.GetProperty("purpose").GetString() == "dkim").Select(x => x.GetProperty("host").GetString()!));
        Assert.Equal(2, later["dkimKeys"].GetArrayLength());

        // Selector names are never reused: the next rotation is -3.
        _f.Clock.Advance(TimeSpan.FromDays(1));
        Reply third = await _a.PostAsync($"/api/v1/domains/{id}/dkim/rotate");
        Assert.Equal("egg202610-3", third["dkim"].GetProperty("selector").GetString());
    }

    [Fact]
    public async Task A_rotated_in_key_signs_real_mail_only_after_the_switch()
    {
        JsonElement d = await CreateAsync();
        Publish(d, "dkim", "return_path");
        string id = d.GetProperty("id").GetString()!;
        await VerifyAsync(id);
        await _a.PostAsync($"/api/v1/domains/{id}/dkim/rotate");

        var keys = await _f.Storage.Config.GetDkimKeysAsync(Guid.Parse(id), default);
        // The delivery engine signs with the newest key that is Active and not retired.
        var signing = keys.Where(k => k.Active && k.RetiredAt is null).OrderByDescending(k => k.CreatedAt).Single();
        Assert.Equal("egg202610", signing.Selector);
    }

    [Fact]
    public async Task Rotation_needs_a_domain_of_the_tenant()
    {
        (await _a.PostAsync($"/api/v1/domains/{Guid.NewGuid():N}/dkim/rotate")).Problem(HttpStatusCode.NotFound, "not_found");
    }

    // SQLite

    [Fact]
    public async Task The_domain_flow_works_on_sqlite()
    {
        await using ApiFixture f = await ApiFixture.StartAsync(new ApiFixtureOptions { Sqlite = true });
        ApiClient c = await f.KeyClientAsync(ApiFixture.TenantAId);
        Reply created = await c.PostAsync("/api/v1/domains", new { name = "disk.example" });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        JsonElement d = created.Json.Clone();
        foreach (JsonElement rec in d.GetProperty("records").EnumerateArray().Where(r => r.GetProperty("purpose").GetString() is "dkim" or "return_path"))
        {
            if (rec.GetProperty("type").GetString() == "CNAME") { f.Dns.AddCname(rec.GetProperty("host").GetString()!, rec.GetProperty("value").GetString()!); }
            else { f.Dns.AddTxt(rec.GetProperty("host").GetString()!, rec.GetProperty("value").GetString()!); }
        }

        Reply verified = await c.PostAsync($"/api/v1/domains/{d.GetProperty("id").GetString()}/verify");
        Assert.Equal("verified", verified.Str("status"));
        Reply rotated = await c.PostAsync($"/api/v1/domains/{d.GetProperty("id").GetString()}/dkim/rotate");
        Assert.Equal(2, rotated["dkimKeys"].GetArrayLength());
        Assert.Equal(HttpStatusCode.NoContent, (await c.DeleteAsync($"/api/v1/domains/{d.GetProperty("id").GetString()}")).Status);
    }
}
