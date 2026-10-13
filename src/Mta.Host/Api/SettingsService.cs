using System.Text.Json;
using System.Text.Json.Serialization;
using Mta.Core;
using Mta.Storage;
using Mta.Webhooks;

namespace Mta.Host.Api;

public enum SettingKind : byte
{
    String,
    Number,
    Boolean,
    Enum,
}

/// <summary>One setting of the catalog: how it is typed, validated and whether it can be changed through the API.</summary>
public sealed record SettingDefinition(
    string Key,
    SettingKind Kind,
    string Description,
    IReadOnlyList<string>? Options = null,
    long Min = 0,
    long Max = long.MaxValue,
    string? ConfigKey = null,
    bool DeploymentOnly = false,
    bool AdminOnly = false,
    bool RequiresRestart = false);

public sealed record SettingItemResponse(
    string Key,
    JsonElement Value,
    string Type,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<string>? Options,
    string Description,
    bool Locked,
    bool RequiresRestart);

public sealed record SettingsResponse(IReadOnlyList<SettingItemResponse> Items);

public sealed class SettingsUpdateRequest
{
    [JsonPropertyName("values")]
    public Dictionary<string, JsonElement>? Values { get; set; }
}

/// <summary>
/// The settings catalog behind <c>/settings</c> (per tenant) and <c>/admin/settings</c> (global). A setting is <c>locked</c> when the deployment
/// configuration fixes it (<see cref="ApiOptions.LockedKeys"/>), when it can only be set at deployment time, or (tenant scope) when only admins
/// may change it. Global values are stored in the config store (decision N, layer 4) and are read at startup by the composition root unless a
/// setting says otherwise; <see cref="SettingDefinition.RequiresRestart"/> marks those.
/// </summary>
public sealed class SettingsService
{
    public const string StoreAttachmentsKey = "Content:StoreAttachments";
    public const string WebhookAllowlistKey = "Webhooks:AllowedNetworks";

    private static readonly IReadOnlyList<SettingDefinition> TenantCatalog =
    [
        new(StoreAttachmentsKey, SettingKind.Boolean, "Keep the raw message with its attachments after delivery so the message can be resent. Off by default; stored attachments use disk space. Needs the operator's Content:AllowAttachmentStorage switch."),
        new(WebhookAllowlistKey, SettingKind.String, "Comma separated networks (CIDR) your webhooks may call although they are internal addresses (SSRF allowlist). Only an administrator can change this.", AdminOnly: true),
        new("Smtp:MaxRecipients", SettingKind.Number, "Maximum recipients per message (fixed by the operator).", DeploymentOnly: true),
    ];

    private readonly IStorage _storage;
    private readonly StorageOptions _storageOptions;
    private readonly ApiOptions _options;
    private readonly IClock _clock;
    private readonly IReadOnlyList<SettingDefinition> _globalCatalog;

    public SettingsService(IStorage storage, StorageOptions storageOptions, ApiOptions options, IClock clock)
    {
        _storage = storage;
        _storageOptions = storageOptions;
        _options = options;
        _clock = clock;
        _globalCatalog =
        [
            new("History:Mode", SettingKind.Enum, "How much per-message history is recorded.", ["StatsOnly", "Full"], RequiresRestart: true),
            new("Retention:MetadataDays", SettingKind.Number, "Days to keep message events. 0 keeps them forever.", RequiresRestart: true),
            new("Webhooks:OutboxRetentionDays", SettingKind.Number, "Days to keep finished webhook deliveries. 0 keeps them forever.", RequiresRestart: true),
            new("Webhooks:AttemptLogDays", SettingKind.Number, "Days to keep the webhook attempt log. 0 keeps it forever.", RequiresRestart: true),
            new("Stats:HourlyRetentionDays", SettingKind.Number, "Days to keep hourly statistics. 0 keeps them forever.", RequiresRestart: true),
            new("Stats:DailyRetentionDays", SettingKind.Number, "Days to keep daily statistics. 0 keeps them forever.", RequiresRestart: true),
            new("Content:RetentionDays", SettingKind.Number, "Days message content is kept (6 to 30; there is no unlimited value).", Min: 6, Max: 30, RequiresRestart: true),
            new("Content:StoreAttachments", SettingKind.Boolean, "Default for storing attachments of sent messages (a tenant or a send can override it).", RequiresRestart: true),
            new("Content:AllowAttachmentStorage", SettingKind.Boolean, "Master switch: without it no attachment is ever stored.", RequiresRestart: true),
            new("Queue:MaxLifetimeDays", SettingKind.Number, "Days a message may stay queued before it expires.", Min: 1, Max: 30, ConfigKey: "Queue:MaxLifetime", RequiresRestart: true),
            new("Smtp:MaxMessageSize", SettingKind.Number, "Maximum message size in bytes (fixed by the deployment).", DeploymentOnly: true),
            new("Smtp:MaxRecipients", SettingKind.Number, "Maximum recipients per message (fixed by the deployment).", DeploymentOnly: true),
            new("Sqlite:SyncMode", SettingKind.Enum, "SQLite synchronous mode of the data files (fixed by the deployment).", ["Off", "Normal", "Full"], DeploymentOnly: true),
        ];
    }

    private IConfigStore Config => _storage.Config;

    private bool IsLockedByDeployment(SettingDefinition d) => d.DeploymentOnly || _options.LockedKeys.Contains(d.ConfigKey ?? d.Key);

    // Tenant scope

    public async ValueTask<SettingsResponse> ListTenantAsync(Tenant tenant, bool callerIsAdmin, CancellationToken ct)
    {
        var stored = (await Config.GetSettingsAsync(tenant.Id, ct).ConfigureAwait(false)).ToDictionary(s => s.Key, StringComparer.Ordinal);
        var items = new List<SettingItemResponse>();
        foreach (SettingDefinition d in TenantCatalog)
        {
            JsonElement value = d.Key switch
            {
                StoreAttachmentsKey => Element(tenant.StoreAttachments),
                "Smtp:MaxRecipients" => Element((long)_options.MaxRecipients),
                _ => stored.TryGetValue(d.Key, out SettingRecord? s) ? Parse(s.ValueJson) : Element(""),
            };
            bool locked = IsLockedByDeployment(d) || (d.AdminOnly && !callerIsAdmin) || (d.Key == StoreAttachmentsKey && !_storageOptions.Content.AllowAttachmentStorage);
            items.Add(ToItem(d, value, locked));
        }

        return new SettingsResponse(items);
    }

    public async ValueTask<SettingsResponse> UpdateTenantAsync(Tenant tenant, bool callerIsAdmin, Dictionary<string, JsonElement> values, CancellationToken ct)
    {
        var errors = new ValidationErrors();
        var validated = new List<(SettingDefinition Def, JsonElement Value)>();
        foreach (var (key, value) in values)
        {
            SettingDefinition? d = TenantCatalog.FirstOrDefault(x => x.Key == key);
            if (d is null)
            {
                errors.Add(key, "Unknown setting.");
            }
            else if (IsLockedByDeployment(d) || (d.AdminOnly && !callerIsAdmin) || (d.Key == StoreAttachmentsKey && !_storageOptions.Content.AllowAttachmentStorage))
            {
                errors.Add(key, d.AdminOnly && !callerIsAdmin ? "Only an administrator can change this setting." : "This setting is locked by the deployment configuration.");
            }
            else if (Check(d, value, out string? problem))
            {
                validated.Add((d, value));
            }
            else
            {
                errors.Add(key, problem!);
            }
        }

        errors.ThrowIfAny();
        Tenant updated = tenant;
        foreach (var (d, value) in validated)
        {
            if (d.Key == StoreAttachmentsKey)
            {
                updated = updated with { StoreAttachments = value.GetBoolean() };
            }
            else
            {
                await Config.SetSettingAsync(new SettingRecord(d.Key, tenant.Id, value.GetRawText(), _clock.UtcNow), ct).ConfigureAwait(false);
            }
        }

        if (updated != tenant)
        {
            await Config.UpsertTenantAsync(updated, ct).ConfigureAwait(false);
        }

        if (validated.Any(v => v.Def.Key == WebhookAllowlistKey))
        {
            await GetWebhookAllowlistAsync(tenant.Id, ct).ConfigureAwait(false); // refresh the cached view the dispatcher reads
        }

        return await ListTenantAsync(updated, callerIsAdmin, ct).ConfigureAwait(false);
    }

    /// <summary>The tenant's SSRF allowlist for webhook endpoints (empty when none).</summary>
    public async ValueTask<IReadOnlyList<IpNetwork>> GetWebhookAllowlistAsync(Guid tenantId, CancellationToken ct)
    {
        var stored = (await Config.GetSettingsAsync(tenantId, ct).ConfigureAwait(false)).FirstOrDefault(s => s.Key == WebhookAllowlistKey);
        IReadOnlyList<IpNetwork> networks;
        if (stored is null)
        {
            networks = [];
        }
        else
        {
            JsonElement value = Parse(stored.ValueJson);
            networks = ParseNetworks(value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "", out _);
        }

        _allowlists[tenantId] = (_clock.Timestamp, networks);
        return networks;
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, (long At, IReadOnlyList<IpNetwork> Networks)> _allowlists = new();

    /// <summary>
    /// Synchronous, cached view of <see cref="GetWebhookAllowlistAsync"/> for <c>WebhookDispatcher.AllowlistProvider</c>, which cannot await. An unknown or stale
    /// tenant returns the last known list (empty at first) and refreshes in the background; a delivery that is refused meanwhile is simply retried.
    /// </summary>
    public IReadOnlyList<IpNetwork> GetWebhookAllowlistSnapshot(Guid tenantId)
    {
        long ttl = 30 * System.Diagnostics.Stopwatch.Frequency;
        if (_allowlists.TryGetValue(tenantId, out var entry))
        {
            if (_clock.Timestamp - entry.At > ttl)
            {
                _ = RefreshAllowlistAsync(tenantId);
            }

            return entry.Networks;
        }

        _allowlists[tenantId] = (_clock.Timestamp, []);
        _ = RefreshAllowlistAsync(tenantId);
        return [];
    }

    private async Task RefreshAllowlistAsync(Guid tenantId)
    {
        try
        {
            await GetWebhookAllowlistAsync(tenantId, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Keep the previous list; the next call tries again.
        }
    }

    private static IReadOnlyList<IpNetwork> ParseNetworks(string text, out string? error)
    {
        error = null;
        var networks = new List<IpNetwork>();
        foreach (string part in text.Split([',', ';', ' ', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                networks.Add(IpNetwork.Parse(part));
            }
            catch (Exception ex) when (ex is FormatException or ArgumentException or OverflowException)
            {
                error = $"'{part}' is not a network in CIDR form (for example 10.0.0.0/8).";
                return [];
            }
        }

        return networks;
    }

    // Global scope

    public async ValueTask<SettingsResponse> ListGlobalAsync(CancellationToken ct)
    {
        var stored = (await Config.GetSettingsAsync(null, ct).ConfigureAwait(false)).ToDictionary(s => s.Key, StringComparer.Ordinal);
        var items = new List<SettingItemResponse>();
        foreach (SettingDefinition d in _globalCatalog)
        {
            bool locked = IsLockedByDeployment(d);
            JsonElement value = !locked && stored.TryGetValue(d.Key, out SettingRecord? s) ? Parse(s.ValueJson) : EffectiveDefault(d);
            items.Add(ToItem(d, value, locked));
        }

        return new SettingsResponse(items);
    }

    public async ValueTask<SettingsResponse> UpdateGlobalAsync(Dictionary<string, JsonElement> values, CancellationToken ct)
    {
        var errors = new ValidationErrors();
        var validated = new List<(SettingDefinition Def, JsonElement Value)>();
        foreach (var (key, value) in values)
        {
            SettingDefinition? d = _globalCatalog.FirstOrDefault(x => x.Key == key);
            if (d is null)
            {
                errors.Add(key, "Unknown setting.");
            }
            else if (IsLockedByDeployment(d))
            {
                errors.Add(key, "This setting is locked by the deployment configuration.");
            }
            else if (Check(d, value, out string? problem))
            {
                validated.Add((d, value));
            }
            else
            {
                errors.Add(key, problem!);
            }
        }

        errors.ThrowIfAny();
        foreach (var (d, value) in validated)
        {
            await Config.SetSettingAsync(new SettingRecord(d.Key, null, value.GetRawText(), _clock.UtcNow), ct).ConfigureAwait(false);
        }

        return await ListGlobalAsync(ct).ConfigureAwait(false);
    }

    private JsonElement EffectiveDefault(SettingDefinition d)
    {
        StorageOptions s = _storageOptions;
        return d.Key switch
        {
            "History:Mode" => Element(s.History.Mode.ToString()),
            "Retention:MetadataDays" => Element((long)s.Retention.MetadataDays),
            "Webhooks:OutboxRetentionDays" => Element((long)s.Retention.WebhookOutboxDays),
            "Webhooks:AttemptLogDays" => Element((long)s.Retention.WebhookAttemptLogDays),
            "Stats:HourlyRetentionDays" => Element((long)s.Retention.StatsHourlyDays),
            "Stats:DailyRetentionDays" => Element((long)s.Retention.StatsDailyDays),
            "Content:RetentionDays" => Element((long)s.Content.RetentionDays),
            "Content:StoreAttachments" => Element(s.Content.StoreAttachments),
            "Content:AllowAttachmentStorage" => Element(s.Content.AllowAttachmentStorage),
            "Queue:MaxLifetimeDays" => Element((long)s.Queue.MaxLifetime.TotalDays),
            "Smtp:MaxMessageSize" => Element(_options.MaxMessageBytes),
            "Smtp:MaxRecipients" => Element((long)_options.MaxRecipients),
            "Sqlite:SyncMode" => Element(s.Sqlite.SyncMode.ToString()),
            _ => Element(""),
        };
    }

    // Validation and JSON helpers

    private static bool Check(SettingDefinition d, JsonElement value, out string? problem)
    {
        problem = null;
        switch (d.Kind)
        {
            case SettingKind.Boolean:
                if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                {
                    problem = "Must be true or false.";
                }

                break;
            case SettingKind.Number:
                if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out long n) || n < d.Min || n > d.Max)
                {
                    problem = d.Max == long.MaxValue ? $"Enter a whole number, {d.Min} or greater." : $"Enter a whole number from {d.Min} to {d.Max}.";
                }

                break;
            case SettingKind.Enum:
                if (value.ValueKind != JsonValueKind.String || d.Options is null || !d.Options.Contains(value.GetString()!, StringComparer.Ordinal))
                {
                    problem = "Must be one of: " + string.Join(", ", d.Options ?? []) + ".";
                }

                break;
            default:
                if (value.ValueKind != JsonValueKind.String || value.GetString()!.Length > 1000)
                {
                    problem = "Must be a text of at most 1000 characters.";
                }
                else if (d.Key == WebhookAllowlistKey)
                {
                    ParseNetworks(value.GetString()!, out problem);
                }

                break;
        }

        return problem is null;
    }

    private static SettingItemResponse ToItem(SettingDefinition d, JsonElement value, bool locked) => new(
        d.Key,
        value,
        d.Kind switch { SettingKind.Number => "number", SettingKind.Boolean => "boolean", SettingKind.Enum => "enum", _ => "string" },
        d.Options,
        d.Description,
        locked,
        d.RequiresRestart);

    private static JsonElement Parse(string json)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            return doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            return Element("");
        }
    }

    private static JsonElement Element(string value) => JsonSerializer.SerializeToElement(value);

    private static JsonElement Element(long value) => JsonSerializer.SerializeToElement(value);

    private static JsonElement Element(bool value) => JsonSerializer.SerializeToElement(value);
}
