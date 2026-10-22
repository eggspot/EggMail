using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Mta.Core;
using Mta.Host.Tls;
using Mta.Storage;

namespace Mta.Host.Api;

public sealed class CreateTenantRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}

public sealed class UpdateTenantRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary><c>active</c> or <c>suspended</c>.</summary>
    [JsonPropertyName("status")]
    public string? Status { get; set; }
}

public sealed record TenantResponse(Guid Id, string Name, string Slug, string Status, DateTimeOffset CreatedAt, bool StoreAttachments);

public sealed class UploadCertificateRequest
{
    [JsonPropertyName("certificatePem")]
    public string? CertificatePem { get; set; }

    [JsonPropertyName("privateKeyPem")]
    public string? PrivateKeyPem { get; set; }

    [JsonPropertyName("pfxBase64")]
    public byte[]? PfxBase64 { get; set; }

    [JsonPropertyName("pfxPassword")]
    public string? PfxPassword { get; set; }
}

public sealed class RequestAcmeCertificateRequest
{
    [JsonPropertyName("domains")]
    public List<string>? Domains { get; set; }
}

public sealed record CertificateResponse(
    Guid Id,
    string Name,
    string Subject,
    string Issuer,
    IReadOnlyList<string> San,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string Source,
    bool Active,
    string Thumbprint);

public sealed record AcmeRequestResponse(string Status, string Message);

public sealed record AcmeRenewalResponse(string CertificateName, string Status, DateTimeOffset? LastAttemptAt, DateTimeOffset? NextAttemptAt, int Failures, string? LastError);

public sealed record AdminQueueStatus(long Depth, long Deferred, DateTimeOffset? OldestDueAt);

public sealed record AdminStorageStatus(bool Healthy, string? Detail, IReadOnlyList<CapabilityWarning> Warnings);

public sealed record AdminCertificateStatus(string Subject, DateTimeOffset NotAfter, string Source);

public sealed record AdminPressureStatus(long WriterQueueDepth, long WriterQueueOverThresholdSeconds, double CommitP99Ms, bool Advisory,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? QueueDepthThreshold,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? QueueThresholdSeconds,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] double? CommitP99ThresholdMs);

public sealed record AdminSwitchStatus(string State);

public sealed record AdminStatusResponse(
    string Version,
    string Backend,
    string HistoryMode,
    long UptimeSeconds,
    AdminQueueStatus Queue,
    AdminStorageStatus Storage,
    IReadOnlyList<AdminCertificateStatus> Certificates,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] AdminPressureStatus? Pressure,
    AdminSwitchStatus Switch);

public sealed record MaintenanceStartResponse(string Status);

public sealed record MaintenanceStateResponse(bool Running, DateTimeOffset? StartedAt, DateTimeOffset? FinishedAt, string? Error, IReadOnlyList<MaintenanceReportResponse> Reports);

public sealed record MaintenanceReportResponse(string Job, long DurationMs, long RowsAffected, string? Detail);

/// <summary>The admin surface (role <c>admin</c>): tenants, status, global settings, certificates, maintenance and the backend switch.</summary>
public sealed partial class AdminApi(
    ApiAuthenticator auth,
    IStorage storage,
    ApiOptions options,
    IClock clock,
    ISecretProtector protector,
    SettingsService settings,
    CapabilitiesService capabilities,
    IStorageSwitchService switchService,
    IAcmeCertificateRequester acme,
    MaintenanceRunner maintenance,
    ApiRuntimeInfo runtime,
    IStoragePressureSource? pressure = null)
{
    private IConfigStore Config => storage.Config;

    public void Map(RouteGroupBuilder api)
    {
        var admin = api.MapGroup("/admin");
        admin.GetRoute("/tenants", ListTenantsAsync);
        admin.PostRoute("/tenants", CreateTenantAsync);
        admin.PatchRoute("/tenants/{id}", UpdateTenantAsync);
        admin.GetRoute("/status", StatusAsync);
        admin.GetRoute("/settings", async (HttpContext c) => { await auth.RequireAdminAsync(c).ConfigureAwait(false); return ApiResults.Ok(await settings.ListGlobalAsync(c.RequestAborted).ConfigureAwait(false)); });
        admin.PutRoute("/settings", PutSettingsAsync);
        admin.GetRoute("/certificates", ListCertificatesAsync);
        admin.PostRoute("/certificates", UploadCertificateAsync);
        admin.PostRoute("/certificates/acme", RequestAcmeAsync);
        admin.GetRoute("/certificates/acme", AcmeStatusAsync);
        admin.PostRoute("/maintenance/run", RunMaintenanceAsync);
        admin.GetRoute("/maintenance", MaintenanceStateAsync);

        var sw = admin.MapGroup("/storage/switch");
        sw.PostRoute("/preflight", SwitchPreflightAsync);
        sw.PostRoute("/start", SwitchStartAsync);
        sw.GetRoute("", SwitchStatusAsync);
        sw.PostRoute("/confirm", (HttpContext c) => SwitchStepAsync(c, switchService.ConfirmAsync));
        sw.PostRoute("/activate", (HttpContext c) => SwitchStepAsync(c, switchService.ActivateAsync));
        sw.PostRoute("/rollback", (HttpContext c) => SwitchStepAsync(c, switchService.RollbackAsync));
        sw.PostRoute("/finalize", (HttpContext c) => SwitchStepAsync(c, switchService.FinalizeAsync));
    }

    // Tenants

    private static TenantResponse ToResponse(Tenant t) => new(t.Id, t.Name, t.Slug, t.Enabled ? "active" : "suspended", t.CreatedAt, t.StoreAttachments);

    private async Task<IResult> ListTenantsAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        return ApiResults.Ok((await Config.GetTenantsAsync(context.RequestAborted).ConfigureAwait(false)).Select(ToResponse).ToList());
    }

    private async Task<IResult> CreateTenantAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        CreateTenantRequest body = await ApiJson.ReadBodyAsync<CreateTenantRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        string name = ValidTenantName(body.Name);
        var tenants = await Config.GetTenantsAsync(ct).ConfigureAwait(false);
        if (tenants.Any(t => string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase)))
        {
            throw ApiException.Validation("name", "A tenant with this name already exists.");
        }

        var slugs = tenants.Select(t => t.Slug).ToHashSet(StringComparer.Ordinal);
        string slug = Slugify(name);
        for (int i = 2; slugs.Contains(slug); i++)
        {
            slug = $"{Slugify(name)}-{i}";
        }

        var tenant = new Tenant(Ids.New(clock.UtcNow), name, slug, true, clock.UtcNow, false);
        try
        {
            await Config.UpsertTenantAsync(tenant, ct).ConfigureAwait(false);
        }
        catch (StorageConflictException)
        {
            throw ApiException.Validation("name", "A tenant with this name already exists.");
        }

        return ApiResults.Created("/api/v1/admin/tenants/" + ApiJson.Id(tenant.Id), ToResponse(tenant));
    }

    private async Task<IResult> UpdateTenantAsync(HttpContext context, string id)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        Tenant? tenant = ApiJson.TryParseId(id, out Guid guid) ? await Config.GetTenantAsync(guid, ct).ConfigureAwait(false) : null;
        if (tenant is null)
        {
            throw ApiException.NotFound("Tenant not found.");
        }

        UpdateTenantRequest body = await ApiJson.ReadBodyAsync<UpdateTenantRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        string? name = null;
        if (body.Name is not null)
        {
            try
            {
                name = ValidTenantName(body.Name);
                if ((await Config.GetTenantsAsync(ct).ConfigureAwait(false)).Any(t => t.Id != tenant.Id && string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase)))
                {
                    errors.Add("name", "A tenant with this name already exists.");
                }
            }
            catch (ApiException ex)
            {
                errors.Add("name", ex.Errors?[0].Message ?? ex.Detail);
            }
        }

        if (body.Status is not null && body.Status is not ("active" or "suspended"))
        {
            errors.Add("status", "Must be \"active\" or \"suspended\".");
        }

        errors.ThrowIfAny();
        Tenant updated = tenant with { Name = name ?? tenant.Name, Enabled = body.Status is null ? tenant.Enabled : body.Status == "active" };
        await Config.UpsertTenantAsync(updated, ct).ConfigureAwait(false);
        return ApiResults.Ok(ToResponse(updated));
    }

    private static string ValidTenantName(string? name)
    {
        string trimmed = name?.Trim() ?? "";
        if (trimmed.Length is 0 or > 80 || ApiText.HasUnsafeCharacter(trimmed))
        {
            throw ApiException.Validation("name", "A name of 1 to 80 characters is required.");
        }

        return trimmed;
    }

    private static string Slugify(string name)
    {
        string slug = NonSlug().Replace(name.ToLowerInvariant(), "-").Trim('-');
        if (slug.Length > 40)
        {
            slug = slug[..40].Trim('-');
        }

        return slug.Length == 0 ? "tenant" : slug;
    }

    [GeneratedRegex("[^a-z0-9]+")]
    private static partial Regex NonSlug();

    // Status

    private async Task<IResult> StatusAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        QueueStats queue = await storage.Deliveries.GetQueueStatsAsync(ct).ConfigureAwait(false);
        Mta.Observability.HealthReport health = await capabilities.GetHealthAsync(ct).ConfigureAwait(false);
        var certificates = await Config.GetCertificatesAsync(ct).ConfigureAwait(false);
        SwitchStatusReport sw = await switchService.GetStatusAsync(ct).ConfigureAwait(false);
        StoragePressure? p = pressure?.Get();
        string detail = health.Details.TryGetValue("storage.backend", out string? backend)
            ? (health.Ready ? $"{backend} storage is ready." : $"{backend} storage is not ready.")
            : health.Ready ? "Storage is ready." : "Storage is not ready.";
        return ApiResults.Ok(new AdminStatusResponse(
            capabilities.Version,
            ApiMap.Backend(storage.Backend),
            ApiMap.HistoryMode(storage.HistoryMode),
            (long)(clock.UtcNow - runtime.StartedAt).TotalSeconds,
            new AdminQueueStatus(queue.Queued + queue.Leased + queue.Deferred, queue.Deferred, queue.OldestDueAt),
            new AdminStorageStatus(health.Ready, detail, health.Warnings.Select(w => new CapabilityWarning(w.Code, w.Message)).ToList()),
            certificates.Where(c => c.Active).Select(c => new AdminCertificateStatus(SubjectOf(c), c.NotAfter, SourceName(c.Source))).ToList(),
            p is null ? null : new AdminPressureStatus(p.WriterQueueDepth, p.WriterQueueOverThresholdSeconds, p.CommitP99Ms, p.Advisory, p.QueueDepthThreshold, p.QueueThresholdSeconds, p.CommitP99ThresholdMs),
            new AdminSwitchStatus(sw.State)));
    }

    private async Task<IResult> PutSettingsAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        SettingsUpdateRequest body = await ApiJson.ReadBodyAsync<SettingsUpdateRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        if (body.Values is null)
        {
            throw ApiException.Validation("values", "An object of setting values is required.");
        }

        return ApiResults.Ok(await settings.UpdateGlobalAsync(body.Values, context.RequestAborted).ConfigureAwait(false));
    }

    // Certificates

    private static string SourceName(string source) => source switch
    {
        "selfsigned" => "self_signed",
        "upload" => "upload",
        _ => "acme",
    };

    private static string SubjectOf(CertificateRecord record) => Parse(record)?.Subject ?? record.Name;

    private static X509Certificate2? Parse(CertificateRecord record)
    {
        try
        {
            var collection = new X509Certificate2Collection();
            collection.ImportFromPem(record.ChainPem);
            return collection.Count > 0 ? collection[0] : null;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static CertificateResponse ToResponse(CertificateRecord c)
    {
        X509Certificate2? leaf = Parse(c);
        return new CertificateResponse(c.Id, c.Name, leaf?.Subject ?? c.Name, leaf?.Issuer ?? "", c.Subjects, c.NotBefore, c.NotAfter, SourceName(c.Source), c.Active, c.Thumbprint);
    }

    private async Task<IResult> ListCertificatesAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        return ApiResults.Ok((await Config.GetCertificatesAsync(context.RequestAborted).ConfigureAwait(false)).Select(ToResponse).ToList());
    }

    private async Task<IResult> UploadCertificateAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        CancellationToken ct = context.RequestAborted;
        UploadCertificateRequest body = await ApiJson.ReadBodyAsync<UploadCertificateRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        bool hasPem = !string.IsNullOrWhiteSpace(body.CertificatePem);
        bool hasPfx = body.PfxBase64 is { Length: > 0 };
        if (hasPem == hasPfx)
        {
            throw ApiException.Validation("certificatePem", "Give either a PEM certificate with its private key, or a PFX file.");
        }

        if ((body.CertificatePem?.Length ?? 0) > 256 * 1024 || (body.PrivateKeyPem?.Length ?? 0) > 64 * 1024 || (body.PfxBase64?.Length ?? 0) > 256 * 1024)
        {
            throw new ApiException(StatusCodes.Status413PayloadTooLarge, ApiCodes.PayloadTooLarge, "The certificate material is too large.");
        }

        X509Certificate2Collection chain = [];
        X509Certificate2? leafWithKey = null;
        try
        {
            if (hasPem)
            {
                if (string.IsNullOrWhiteSpace(body.PrivateKeyPem))
                {
                    throw ApiException.Validation("privateKeyPem", "A PEM private key is required.");
                }

                try
                {
                    chain.ImportFromPem(body.CertificatePem);
                }
                catch (Exception ex) when (ex is CryptographicException or ArgumentException)
                {
                    throw ApiException.Validation("certificatePem", "The text is not a PEM certificate chain.");
                }

                if (chain.Count == 0)
                {
                    throw ApiException.Validation("certificatePem", "No PEM certificate found.");
                }

                try
                {
                    leafWithKey = X509Certificate2.CreateFromPem(chain[0].ExportCertificatePem(), body.PrivateKeyPem);
                }
                catch (Exception ex) when (ex is CryptographicException or ArgumentException)
                {
                    throw ApiException.Validation("privateKeyPem", "The private key is not valid, is encrypted, or does not belong to the first certificate.");
                }
            }
            else
            {
                try
                {
                    X509Certificate2Collection loaded = X509CertificateLoader.LoadPkcs12Collection(body.PfxBase64!, body.PfxPassword, X509KeyStorageFlags.Exportable);
                    X509Certificate2? withKey = loaded.OfType<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey);
                    if (withKey is null)
                    {
                        throw ApiException.Validation("pfxBase64", "The PFX file holds no private key.");
                    }

                    leafWithKey = withKey;
                    chain.Add(withKey);
                    foreach (X509Certificate2 other in loaded.OfType<X509Certificate2>().Where(c => !ReferenceEquals(c, withKey)))
                    {
                        chain.Add(other);
                    }
                }
                catch (CryptographicException)
                {
                    throw ApiException.Validation("pfxBase64", "The PFX file cannot be read (wrong password or not a PFX).");
                }
            }

            DateTimeOffset now = clock.UtcNow;
            if (leafWithKey.NotAfter.ToUniversalTime() <= now.UtcDateTime)
            {
                throw ApiException.Validation("certificatePem", "The certificate has expired.");
            }

            if (leafWithKey.NotBefore.ToUniversalTime() > now.UtcDateTime.AddDays(1))
            {
                throw ApiException.Validation("certificatePem", "The certificate is not valid yet.");
            }

            byte[] pkcs8 = ExportPrivateKey(leafWithKey);
            try
            {
                var subjects = CertificateMaterial.SubjectsOf(leafWithKey);
                if (subjects.Count == 0)
                {
                    throw ApiException.Validation("certificatePem", "The certificate names no host.");
                }

                string chainPem = string.Concat(chain.OfType<X509Certificate2>().Select(c => c.ExportCertificatePem() + "\n"));
                var record = new CertificateRecord(
                    Ids.New(now), "upload:" + leafWithKey.Thumbprint.ToLowerInvariant(), subjects, leafWithKey.NotBefore.ToUniversalTime(), leafWithKey.NotAfter.ToUniversalTime(),
                    chainPem, protector.Protect(pkcs8, SecretPurposes.TlsPrivateKey), "upload", leafWithKey.Thumbprint, Active: true, Version: 0, CreatedAt: now);
                if ((await Config.GetCertificatesAsync(ct).ConfigureAwait(false)).Any(c => c.Name == record.Name))
                {
                    throw ApiException.Conflict("This certificate was uploaded before.");
                }

                await Config.UpsertCertificateAsync(record, ct).ConfigureAwait(false);

                // The first-run self-signed certificate is a placeholder: once a real certificate is uploaded it must not win the selection.
                foreach (CertificateRecord placeholder in (await Config.GetCertificatesAsync(ct).ConfigureAwait(false)).Where(c => c.Active && c.Source == "selfsigned"))
                {
                    await Config.UpsertCertificateAsync(placeholder with { Active = false }, ct).ConfigureAwait(false);
                }

                CertificateRecord stored = (await Config.GetCertificatesAsync(ct).ConfigureAwait(false)).First(c => c.Id == record.Id);
                return ApiResults.Created("/api/v1/admin/certificates/" + ApiJson.Id(record.Id), ToResponse(stored));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pkcs8);
            }
        }
        finally
        {
            leafWithKey?.Dispose();
            foreach (X509Certificate2 c in chain)
            {
                c.Dispose();
            }
        }
    }

    private static byte[] ExportPrivateKey(X509Certificate2 certificate)
    {
        using RSA? rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
        {
            return rsa.ExportPkcs8PrivateKey();
        }

        using ECDsa? ec = certificate.GetECDsaPrivateKey();
        if (ec is not null)
        {
            return ec.ExportPkcs8PrivateKey();
        }

        throw ApiException.Validation("privateKeyPem", "Only RSA and ECDSA keys are supported.");
    }

    private async Task<IResult> RequestAcmeAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        RequestAcmeCertificateRequest body = await ApiJson.ReadBodyAsync<RequestAcmeCertificateRequest>(context, options.MaxBodyBytes).ConfigureAwait(false);
        var errors = new ValidationErrors();
        var domains = (body.Domains ?? []).Select(d => d?.Trim().ToLowerInvariant() ?? "").Distinct().ToList();
        if (domains.Count is 0 or > 10)
        {
            errors.Add("domains", "Give 1 to 10 domain names.");
        }
        else
        {
            foreach (string d in domains)
            {
                string host = d.StartsWith("*.", StringComparison.Ordinal) ? d[2..] : d;
                if (!EmailAddress.IsValidHostName(host) || !host.Contains('.') || host.Contains('_') || System.Net.IPAddress.TryParse(host, out _))
                {
                    errors.Add("domains", $"\"{d}\" is not a valid host name.");
                }
            }
        }

        errors.ThrowIfAny();
        return acme.Start(domains) switch
        {
            AcmeStartResult.Started => ApiResults.Accepted(new AcmeRequestResponse("pending", $"Certificate requested for {string.Join(", ", domains)} (HTTP-01 or DNS-01, as configured). The result is recorded under GET /api/v1/admin/certificates/acme.")),
            AcmeStartResult.AlreadyRunning => throw ApiException.Conflict("A certificate order is already running."),
            _ => throw ApiException.NotReady("ACME is not configured on this server (Acme:Enabled, a DNS provider and an email address)."),
        };
    }

    private async Task<IResult> AcmeStatusAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        var renewals = await Config.GetAcmeRenewalsAsync(context.RequestAborted).ConfigureAwait(false);
        return ApiResults.Ok(renewals.Select(r => new AcmeRenewalResponse(r.CertificateName, r.Status, r.LastAttemptAt, r.NextAttemptAt, r.Failures, r.LastError)).ToList());
    }

    // Maintenance

    private async Task<IResult> RunMaintenanceAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        return ApiResults.Accepted(new MaintenanceStartResponse(maintenance.TryStart() == MaintenanceStartResult.Started ? "started" : "running"));
    }

    private async Task<IResult> MaintenanceStateAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        MaintenanceRunState s = maintenance.State;
        return ApiResults.Ok(new MaintenanceStateResponse(s.Running, s.StartedAt, s.FinishedAt, s.Error,
            s.Reports.Select(r => new MaintenanceReportResponse(r.Job, (long)r.Duration.TotalMilliseconds, r.RowsAffected, r.Detail)).ToList()));
    }

    // Storage switch (thin layer over IStorageSwitchService)

    private void ValidateSwitch(SwitchRequestModel body, bool forStart)
    {
        var errors = new ValidationErrors();
        string current = ApiMap.Backend(storage.Backend);
        if (body.To is not ("postgres" or "sqlite"))
        {
            errors.Add("to", "Must be \"postgres\" or \"sqlite\".");
        }
        else if (body.To == current)
        {
            errors.Add("to", $"The server already uses {current}.");
        }

        if (body.Mode is not ("drain" or "quiesce"))
        {
            errors.Add("mode", "Must be \"drain\" or \"quiesce\".");
        }

        if (body.Include is null || body.Include.Any(i => i is not ("queue" or "history")))
        {
            errors.Add("include", "Must be a list of \"queue\" and/or \"history\".");
        }
        else if (body.Mode == "drain" && body.Include.Contains("queue"))
        {
            errors.Add("include", "Queued mail only moves with mode \"quiesce\"; a drain empties the queue first.");
        }

        if (body.Target is null)
        {
            errors.Add("target", "Required.");
        }
        else if (body.To == "postgres" && string.IsNullOrWhiteSpace(body.Target.ConnectionName) && (string.IsNullOrWhiteSpace(body.Target.Host) || string.IsNullOrWhiteSpace(body.Target.Database)))
        {
            errors.Add("target", "Give a connection name, or host and database.");
        }
        else if (body.To == "sqlite" && string.IsNullOrWhiteSpace(body.Target.Path))
        {
            errors.Add("target.path", "Required.");
        }

        if (forStart && body is SwitchStartModel start)
        {
            if (start.ExportPassphrase is null || start.ExportPassphrase.Length < 12)
            {
                errors.Add("exportPassphrase", "At least 12 characters.");
            }

            if (start.Confirmation != $"switch to {body.To}")
            {
                errors.Add("confirmation", $"Type \"switch to {body.To}\" to confirm.");
            }
        }

        errors.ThrowIfAny();
    }

    private async Task<IResult> SwitchPreflightAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        SwitchRequestModel body = await ApiJson.ReadBodyAsync<SwitchRequestModel>(context, options.MaxBodyBytes).ConfigureAwait(false);
        ValidateSwitch(body, forStart: false);
        return await Engine(async () => ApiResults.Ok(await switchService.PreflightAsync(body, context.RequestAborted).ConfigureAwait(false))).ConfigureAwait(false);
    }

    private async Task<IResult> SwitchStartAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        SwitchStartModel body = await ApiJson.ReadBodyAsync<SwitchStartModel>(context, options.MaxBodyBytes).ConfigureAwait(false);
        ValidateSwitch(body, forStart: true);
        return await Engine(async () => ApiResults.Accepted(await switchService.StartAsync(body, context.RequestAborted).ConfigureAwait(false))).ConfigureAwait(false);
    }

    private async Task<IResult> SwitchStatusAsync(HttpContext context)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        return await Engine(async () => ApiResults.Ok(await switchService.GetStatusAsync(context.RequestAborted).ConfigureAwait(false))).ConfigureAwait(false);
    }

    private async Task<IResult> SwitchStepAsync(HttpContext context, Func<CancellationToken, ValueTask<SwitchStatusReport>> step)
    {
        await auth.RequireAdminAsync(context).ConfigureAwait(false);
        return await Engine(async () => ApiResults.Ok(await step(context.RequestAborted).ConfigureAwait(false))).ConfigureAwait(false);
    }

    private static async Task<IResult> Engine(Func<Task<IResult>> call)
    {
        try
        {
            return await call().ConfigureAwait(false);
        }
        catch (StorageSwitchException ex)
        {
            throw ex.Kind switch
            {
                StorageSwitchError.NotReady => ApiException.NotReady(ex.Message),
                StorageSwitchError.InvalidState => ApiException.Conflict(ex.Message),
                _ => ApiException.Validation(ex.Field ?? "$", ex.Message),
            };
        }
    }
}
