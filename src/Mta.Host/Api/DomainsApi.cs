using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Core;
using Mta.Host.Domains;
using Mta.Policy;
using Mta.Storage;
using StoredDkimKey = Mta.Storage.DkimKeyRecord;

namespace Mta.Host.Api;

public sealed class CreateDomainRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}

public sealed record DnsRecordResponse(string Type, string Host, string Value, int Ttl, string Purpose, string Status, string? Found, string Expected, bool Required, string? Note, bool Publishable);

/// <summary>The MTA-STS policy file EggMail serves for a domain (<see cref="Url"/> is where receivers fetch it, <see cref="Content"/> is what they get).</summary>
public sealed record MtaStsPolicyResponse(string Url, string Host, string Content);

/// <summary>Everything to publish for a domain: the records with their last check result, the same as zone-file text, and the MTA-STS policy file when it is served.</summary>
public sealed record DomainRecordsResponse(Guid Id, string Name, bool ReadyToSend, DateTimeOffset? CheckedAt, IReadOnlyList<DnsRecordResponse> Records, string ZoneFile, MtaStsPolicyResponse? MtaStsPolicy);

public sealed record DkimKeyResponse(string Selector, string PublicKey, bool Active, DateTimeOffset CreatedAt, DateTimeOffset? RetiredAt);

public sealed record DomainResponse(
    Guid Id,
    string Name,
    string Status,
    bool SendingPaused,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastCheckedAt,
    DateTimeOffset? NextCheckAt,
    string? LastError,
    bool ReturnPathVerified,
    bool ReadyToSend,
    IReadOnlyList<DnsRecordResponse> Records,
    DkimKeyResponse Dkim,
    IReadOnlyList<DkimKeyResponse> DkimKeys);

/// <summary>Domains: create (with an RSA-2048 DKIM key), records, verification, DKIM rotation. Every query is keyed by the caller's tenant.</summary>
public sealed class DomainsApi(ApiAuthenticator auth, IStorage storage, ISecretProtector protector, DomainVerificationService verification, ApiOptions options, IClock clock)
{
    public void Map(RouteGroupBuilder api)
    {
        api.GetRoute("/domains", ListAsync);
        api.PostRoute("/domains", CreateAsync);
        api.GetRoute("/domains/{id}", GetAsync);
        api.DeleteRoute("/domains/{id}", DeleteAsync);
        api.GetRoute("/domains/{id}/records", RecordsAsync);
        api.PostRoute("/domains/{id}/verify", VerifyAsync);
        api.PostRoute("/domains/{id}/dkim/rotate", RotateAsync);
        api.DeleteRoute("/domains/{id}/dkim/rotate", CancelRotationAsync);
    }

    private IConfigStore Config => storage.Config;

    private async Task<DomainRecord> FindOwnAsync(ApiCaller caller, string id, CancellationToken ct)
    {
        DomainRecord? domain = ApiJson.TryParseId(id, out Guid guid) ? await Config.GetDomainAsync(guid, ct).ConfigureAwait(false) : null;
        // A domain of another tenant is indistinguishable from one that does not exist.
        return domain is not null && domain.TenantId == caller.TenantId ? domain : throw ApiException.NotFound("Domain not found.");
    }

    private async Task<IResult> ListAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Domains).ConfigureAwait(false);
        var domains = await Config.GetDomainsAsync(caller.TenantId, context.RequestAborted).ConfigureAwait(false);
        var items = new List<DomainResponse>(domains.Count);
        foreach (DomainRecord d in domains)
        {
            items.Add(await ToResponseAsync(d, context.RequestAborted).ConfigureAwait(false));
        }

        return ApiResults.Ok(items);
    }

    private async Task<IResult> GetAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Domains).ConfigureAwait(false);
        DomainRecord domain = await FindOwnAsync(caller, id, context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(await ToResponseAsync(domain, context.RequestAborted).ConfigureAwait(false));
    }

    /// <summary>
    /// What to publish for the domain, as records with their last check result and as zone-file text; <c>?format=zone</c> answers only the zone file as
    /// <c>text/plain</c>. Nothing is looked up in DNS (use <c>POST /verify</c> for that).
    /// </summary>
    private async Task<IResult> RecordsAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Domains).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnAsync(caller, id, ct).ConfigureAwait(false);
        var keys = await Config.GetDkimKeysAsync(domain.Id, ct).ConfigureAwait(false);
        var plan = verification.PlanRecords(domain, keys, clock.UtcNow);
        string zone = ZoneFile.Render(domain.Name, plan);
        if (string.Equals(context.Request.Query["format"], "zone", StringComparison.OrdinalIgnoreCase))
        {
            return Results.Text(zone, "text/plain; charset=utf-8");
        }

        DomainCheckSnapshot? snapshot = await verification.GetSnapshotAsync(domain.Id, ct).ConfigureAwait(false);
        DomainRecordOptions recordOptions = verification.RecordOptions;
        MtaStsPolicyResponse? policy = recordOptions.MtaStsEnabled
            ? new MtaStsPolicyResponse(MtaStsPolicyDocument.UrlFor(domain.Name), MtaStsPolicyDocument.HostFor(domain.Name), MtaStsPolicyDocument.Render(recordOptions))
            : null;
        return ApiResults.Ok(new DomainRecordsResponse(
            domain.Id, domain.Name, IsReadyToSend(domain), snapshot?.CheckedAt, plan.Select(r => ToRecordResponse(domain, r, snapshot)).ToList(), zone, policy));
    }

    private async Task<IResult> CreateAsync(HttpContext context)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Domains).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        CreateDomainRequest body = await ApiJson.ReadBodyAsync<CreateDomainRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        string name = NormalizeName(body.Name);

        if ((await Config.GetDomainsAsync(caller.TenantId, ct).ConfigureAwait(false)).Count >= options.MaxDomainsPerTenant)
        {
            throw ApiException.Validation("name", $"At most {options.MaxDomainsPerTenant} domains per tenant.");
        }

        if (await Config.FindDomainByNameAsync(name, ct).ConfigureAwait(false) is not null)
        {
            throw ApiException.Validation("name", "This domain is already registered.");
        }

        RegisteredDomain registered;
        try
        {
            registered = await DomainRegistration.RegisterAsync(Config, protector, verification.Schedule, verification.RecordOptions, caller.TenantId, name, clock.UtcNow, ct).ConfigureAwait(false);
        }
        catch (StorageConflictException)
        {
            throw ApiException.Validation("name", "This domain is already registered.");
        }

        return ApiResults.Created("/api/v1/domains/" + ApiJson.Id(registered.Domain.Id), await ToResponseAsync(registered.Domain, ct).ConfigureAwait(false));
    }

    private async Task<IResult> DeleteAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Domains).ConfigureAwait(false);
        DomainRecord domain = await FindOwnAsync(caller, id, context.RequestAborted).ConfigureAwait(false);
        // Not while a check or rotation of the domain is running anywhere (it could write check results for a domain that is gone).
        await using IAsyncDisposable? held = await verification.TryLockAsync(domain.Id, context.RequestAborted).ConfigureAwait(false);
        if (held is null)
        {
            throw ApiException.Conflict("A check or rotation of this domain is running; retry in a moment.");
        }

        // Received mail belongs to the domain: deleting the domain would leave it unreachable through the API but kept (and counted) until retention. Refuse unless the caller says to purge it.
        // "Has mail" is an existence query (one row of the (domain_id, id) index), not a scan.
        bool hasMail = (await storage.Inbound.SearchAsync(new InboundMessageQuery(caller.TenantId, DomainId: domain.Id, Limit: 1), context.RequestAborted).ConfigureAwait(false)).Items.Count > 0;
        if (hasMail)
        {
            if (!string.Equals(context.Request.Query["purgeInbound"], "true", StringComparison.Ordinal))
            {
                var details = new Dictionary<string, object?> { ["reason"] = "inbound_messages_exist" };
                if (caller.HasScope(ApiScopes.InboundRead))
                {
                    // How much mail there is is itself information about the mailbox: only a key that may read the mail is told.
                    details["messages"] = (await storage.Inbound.GetUsageAsync(caller.TenantId, domain.Id, context.RequestAborted).ConfigureAwait(false)).Messages;
                }

                throw new ApiException(
                    StatusCodes.Status409Conflict, ApiCodes.Conflict,
                    $"The domain still has received messages. Delete them first, or pass purgeInbound=true to delete them with the domain (needs the '{ApiScopes.InboundWrite}' scope).",
                    extensions: details);
            }

            if (!caller.HasScope(ApiScopes.InboundWrite))
            {
                throw ApiException.Forbidden($"purgeInbound=true deletes received mail and needs the '{ApiScopes.InboundWrite}' scope.");
            }

            // Stop receiving first (the settings are what the receive path reads), then purge in batches, then delete the domain: no mail arrives while the old mail goes.
            InboundDomainSettings? settings = await storage.Inbound.GetSettingsAsync(domain.Id, context.RequestAborted).ConfigureAwait(false);
            if (settings is { Enabled: true })
            {
                await storage.Inbound.UpsertSettingsAsync(settings with { Enabled = false, UpdatedAt = clock.UtcNow }, context.RequestAborted).ConfigureAwait(false);
            }

            await storage.Inbound.DeleteMatchingAsync(new InboundMessageQuery(caller.TenantId, DomainId: domain.Id), context.RequestAborted).ConfigureAwait(false);
        }

        await Config.DeleteDomainAsync(domain.Id, context.RequestAborted).ConfigureAwait(false);
        Mta.Host.Submission.DomainChangeSignal.Bump();
        return ApiResults.NoContent();
    }

    private async Task<IResult> VerifyAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Domains).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnAsync(caller, id, ct).ConfigureAwait(false);
        if (!verification.Schedule.CanVerifyNow(domain.LastCheckedAt, clock.UtcNow, out TimeSpan retryAfter))
        {
            throw ApiException.RateLimited("Verify now is limited to once per 30 seconds per domain.", retryAfter);
        }

        await using IAsyncDisposable? held = await verification.TryLockAsync(domain.Id, ct).ConfigureAwait(false);
        if (held is null)
        {
            throw ApiException.RateLimited("A check of this domain is already running.", TimeSpan.FromSeconds(5));
        }

        DomainRecord? updated = await verification.CheckAsync(domain.Id, ct).ConfigureAwait(false) ?? throw ApiException.NotFound("Domain not found.");
        return ApiResults.Ok(await ToResponseAsync(updated, ct).ConfigureAwait(false));
    }

    private async Task<IResult> RotateAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Domains).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnAsync(caller, id, ct).ConfigureAwait(false);
        // One check or rotation at a time per domain across all replicas (two requests would otherwise both pass the "nothing pending" check while a key is generated).
        await using IAsyncDisposable? held = await verification.TryLockAsync(domain.Id, ct).ConfigureAwait(false);
        if (held is null)
        {
            throw ApiException.Conflict("A check or rotation of this domain is running; retry in a moment.");
        }

        var keys = await Config.GetDkimKeysAsync(domain.Id, ct).ConfigureAwait(false);
        if (keys.Any(k => !k.Active && k.RetiredAt is null))
        {
            throw ApiException.Conflict("A key rotation is already in progress: publish the new DNS record (signing switches to the new key once it is found) or cancel it with DELETE.");
        }

        DateTimeOffset now = clock.UtcNow;
        string selector = DomainVerificationService.NextSelector(keys, now);
        // The new key does not sign until its record is published (the verification service switches); the current key keeps signing.
        StoredDkimKey key = await DomainVerificationService.CreateKeyAsync(domain.Id, selector, protector, now, active: false).ConfigureAwait(false);
        await Config.AddDkimKeyAsync(key, ct).ConfigureAwait(false);

        // Look for the new record soon rather than at the (daily) cadence of a verified domain. The row is read again so a check that finished meanwhile is not overwritten.
        DomainRecord fresh = await Config.GetDomainAsync(domain.Id, ct).ConfigureAwait(false) ?? throw ApiException.NotFound("Domain not found.");
        DateTimeOffset soon = verification.Schedule.FirstCheckAt(now);
        if (fresh.NextCheckAt is null || fresh.NextCheckAt > soon)
        {
            fresh = fresh with { NextCheckAt = soon };
            await Config.UpsertDomainAsync(fresh, ct).ConfigureAwait(false);
            Mta.Host.Submission.DomainChangeSignal.Bump();
        }

        return ApiResults.Ok(await ToResponseAsync(fresh, ct).ConfigureAwait(false));
    }

    /// <summary>Cancels a rotation that has not switched yet: the new key is deleted (its selector stays used, names are never reused).</summary>
    private async Task<IResult> CancelRotationAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Domains).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnAsync(caller, id, ct).ConfigureAwait(false);
        var pending = (await Config.GetDkimKeysAsync(domain.Id, ct).ConfigureAwait(false)).Where(k => !k.Active && k.RetiredAt is null).ToList();
        if (pending.Count == 0)
        {
            throw ApiException.NotFound("No key rotation is pending.");
        }

        foreach (StoredDkimKey key in pending)
        {
            await Config.DeletePendingDkimKeyAsync(domain.Id, key.Id, ct).ConfigureAwait(false);
        }

        return ApiResults.Ok(await ToResponseAsync(domain, ct).ConfigureAwait(false));
    }

    // Response building

    private async Task<DomainResponse> ToResponseAsync(DomainRecord domain, CancellationToken ct)
    {
        var keys = await Config.GetDkimKeysAsync(domain.Id, ct).ConfigureAwait(false);
        DateTimeOffset now = clock.UtcNow;
        var plan = verification.PlanRecords(domain, keys, now);
        DomainCheckSnapshot? snapshot = await verification.GetSnapshotAsync(domain.Id, ct).ConfigureAwait(false);
        var records = plan.Select(r => ToRecordResponse(domain, r, snapshot)).ToList();

        var ordered = keys.OrderBy(k => k.CreatedAt).ThenBy(k => k.Id).ToList();
        StoredDkimKey? newest = ordered.LastOrDefault();
        DkimKeyResponse dkim = newest is null
            ? new DkimKeyResponse("", "", false, domain.CreatedAt, null)
            : KeyOf(newest);
        return new DomainResponse(
            domain.Id, domain.Name, ApiMap.DomainStatus(domain.Status), domain.SendingPaused, domain.CreatedAt, domain.LastCheckedAt, domain.NextCheckAt, domain.LastError,
            domain.ReturnPathVerified, IsReadyToSend(domain), records, dkim, ordered.Select(KeyOf).ToList());
    }

    private static DkimKeyResponse KeyOf(StoredDkimKey k) => new(k.Selector, k.PublicKeyBase64, k.Active, k.CreatedAt, k.RetiredAt);

    private static DnsRecordResponse ToRecordResponse(DomainRecord domain, ExpectedDomainRecord record, DomainCheckSnapshot? snapshot)
    {
        string status;
        string? found = null;
        if (snapshot is not null && snapshot.Records.TryGetValue(DomainCheckSnapshot.KeyOf(record.Type, record.Host), out RecordCheckSnapshot? seen))
        {
            status = DomainVerificationService.StatusWord(seen.Status);
            found = seen.Found;
        }
        else
        {
            // Nothing is known about this record yet (never checked, or last checked before check results were persisted): a verified domain implies its required records.
            status = record.Required && domain.Status == DomainStatus.Verified ? "ok" : "pending";
        }

        return new DnsRecordResponse(record.Type, record.Host, record.Value, record.Ttl, DomainRecordPurposes.ApiWord(record.Purpose), status, found, record.Value, record.Required, record.Note, ZoneFile.BelongsInZone(record, domain.Name));
    }

    /// <summary>Whether mail can be sent from the domain now: verified, or in the grace period of a temporary failure, and not paused (design §8).</summary>
    public static bool IsReadyToSend(DomainRecord domain) => domain.Status is DomainStatus.Verified or DomainStatus.TemporaryFailure && !domain.SendingPaused;

    /// <summary>Lower-cases and validates a domain name; returns the A-label form.</summary>
    public static string NormalizeName(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            throw ApiException.Validation("name", "A domain name is required.");
        }

        return DomainNames.TryNormalize(input, out string name) ? name : throw ApiException.Validation("name", "Enter a valid domain name such as mail.example.com.");
    }
}
