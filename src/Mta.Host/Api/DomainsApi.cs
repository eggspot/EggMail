using System.Net;
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

public sealed record DnsRecordResponse(string Type, string Host, string Value, int Ttl, string Purpose, string Status, string? Found, string Expected, bool Required);

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
        api.PostRoute("/domains/{id}/verify", VerifyAsync);
        api.PostRoute("/domains/{id}/dkim/rotate", RotateAsync);
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

        DateTimeOffset now = clock.UtcNow;
        var domain = new DomainRecord(
            Ids.New(now),
            caller.TenantId,
            name,
            DomainStatus.Pending,
            string.IsNullOrWhiteSpace(verification.RecordOptions.BounceDomain) ? null : DomainRecordPlanner.ReturnPathHost(name, verification.RecordOptions),
            ReturnPathVerified: false,
            now,
            LastCheckedAt: null,
            NextCheckAt: verification.Schedule.FirstCheckAt(now),
            ConsecutiveFailures: 0,
            TemporaryFailureSince: null,
            SendingPaused: false,
            LastError: null);
        StoredDkimKey key = await DomainVerificationService.CreateKeyAsync(domain.Id, DomainVerificationService.NextSelector([], now), protector, now, active: true).ConfigureAwait(false);

        // The key goes in first: a domain without a key would verify without DKIM if the process died in between. An orphan key is harmless.
        await Config.AddDkimKeyAsync(key, ct).ConfigureAwait(false);
        try
        {
            await Config.UpsertDomainAsync(domain, ct).ConfigureAwait(false);
        }
        catch (StorageConflictException)
        {
            await Config.DeleteDomainAsync(domain.Id, CancellationToken.None).ConfigureAwait(false); // removes the orphan key
            throw ApiException.Validation("name", "This domain is already registered.");
        }

        return ApiResults.Created("/api/v1/domains/" + ApiJson.Id(domain.Id), await ToResponseAsync(domain, ct).ConfigureAwait(false));
    }

    private async Task<IResult> DeleteAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Domains).ConfigureAwait(false);
        DomainRecord domain = await FindOwnAsync(caller, id, context.RequestAborted).ConfigureAwait(false);
        await Config.DeleteDomainAsync(domain.Id, context.RequestAborted).ConfigureAwait(false);
        verification.Forget(domain.Id);
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

        if (!verification.TryEnter(domain.Id))
        {
            throw ApiException.RateLimited("A check of this domain is already running.", TimeSpan.FromSeconds(5));
        }

        try
        {
            DomainRecord? updated = await verification.CheckAsync(domain.Id, ct).ConfigureAwait(false) ?? throw ApiException.NotFound("Domain not found.");
            return ApiResults.Ok(await ToResponseAsync(updated, ct).ConfigureAwait(false));
        }
        finally
        {
            verification.Leave(domain.Id);
        }
    }

    private async Task<IResult> RotateAsync(HttpContext context, string id)
    {
        ApiCaller caller = await auth.RequireTenantAsync(context, ApiScopes.Domains).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        DomainRecord domain = await FindOwnAsync(caller, id, ct).ConfigureAwait(false);
        var keys = await Config.GetDkimKeysAsync(domain.Id, ct).ConfigureAwait(false);
        if (keys.Any(k => !k.Active && k.RetiredAt is null))
        {
            throw ApiException.Conflict("A key rotation is already in progress: publish the new DNS record; signing switches to the new key once it is found.");
        }

        DateTimeOffset now = clock.UtcNow;
        string selector = DomainVerificationService.NextSelector(keys, now);
        // The new key does not sign until its record is published (the verification service switches); the current key keeps signing.
        StoredDkimKey key = await DomainVerificationService.CreateKeyAsync(domain.Id, selector, protector, now, active: false).ConfigureAwait(false);
        await Config.AddDkimKeyAsync(key, ct).ConfigureAwait(false);
        // Look for the new record soon rather than at the (daily) cadence of a verified domain.
        DateTimeOffset soon = verification.Schedule.FirstCheckAt(now);
        if (domain.NextCheckAt is null || domain.NextCheckAt > soon)
        {
            domain = domain with { NextCheckAt = soon };
            await Config.UpsertDomainAsync(domain, ct).ConfigureAwait(false);
        }

        return ApiResults.Ok(await ToResponseAsync(domain, ct).ConfigureAwait(false));
    }

    // Response building

    private async Task<DomainResponse> ToResponseAsync(DomainRecord domain, CancellationToken ct)
    {
        var keys = await Config.GetDkimKeysAsync(domain.Id, ct).ConfigureAwait(false);
        DateTimeOffset now = clock.UtcNow;
        var plan = verification.PlanRecords(domain, keys, now);
        DomainCheckSnapshot? snapshot = verification.GetSnapshot(domain.Id);
        var records = plan.Select(r => ToRecordResponse(domain, r, snapshot)).ToList();

        var ordered = keys.OrderBy(k => k.CreatedAt).ThenBy(k => k.Id).ToList();
        StoredDkimKey? newest = ordered.LastOrDefault();
        DkimKeyResponse dkim = newest is null
            ? new DkimKeyResponse("", "", false, domain.CreatedAt, null)
            : KeyOf(newest);
        return new DomainResponse(
            domain.Id, domain.Name, ApiMap.DomainStatus(domain.Status), domain.SendingPaused, domain.CreatedAt, domain.LastCheckedAt, domain.NextCheckAt, domain.LastError,
            domain.ReturnPathVerified, records, dkim, ordered.Select(KeyOf).ToList());
    }

    private static DkimKeyResponse KeyOf(StoredDkimKey k) => new(k.Selector, k.PublicKeyBase64, k.Active, k.CreatedAt, k.RetiredAt);

    private static DnsRecordResponse ToRecordResponse(DomainRecord domain, ExpectedDomainRecord record, DomainCheckSnapshot? snapshot)
    {
        string status;
        string? found = null;
        if (snapshot is not null && snapshot.Records.TryGetValue(DomainCheckSnapshot.KeyOf(record.Type, record.Host), out RecordCheckSnapshot? seen))
        {
            status = seen.Status switch
            {
                DomainRecordStatus.Ok => "ok",
                DomainRecordStatus.Missing => "missing",
                DomainRecordStatus.Invalid => "invalid",
                _ => "pending",
            };
            found = seen.Found;
        }
        else
        {
            // Nothing is known about this record yet (restart, other replica, or not checked): a verified domain implies its required records.
            status = record.Required && domain.Status == DomainStatus.Verified ? "ok" : "pending";
        }

        string purpose = record.Purpose switch
        {
            DomainRecordPurpose.Dkim => "dkim",
            DomainRecordPurpose.ReturnPath => "return_path",
            DomainRecordPurpose.Spf => "spf",
            _ => "dmarc",
        };
        return new DnsRecordResponse(record.Type, record.Host, record.Value, record.Ttl, purpose, status, found, record.Value, record.Required);
    }

    /// <summary>Lower-cases and validates a domain name; returns the A-label form.</summary>
    public static string NormalizeName(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            throw ApiException.Validation("name", "A domain name is required.");
        }

        string trimmed = input.Trim().TrimEnd('.');
        if (trimmed.Length > 253 || !EmailAddress.TryParse("postmaster@" + trimmed, allowUtf8: true, out EmailAddress parsed)
            || parsed.IsAddressLiteral || !parsed.Domain.Contains('.') || parsed.Domain.Contains('_') || IPAddress.TryParse(parsed.Domain, out _))
        {
            throw ApiException.Validation("name", "Enter a valid domain name such as mail.example.com.");
        }

        return parsed.Domain;
    }
}
