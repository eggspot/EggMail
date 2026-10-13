using System.Text.Json;
using Mta.Storage;

namespace Mta.Host.Submission;

/// <summary>
/// Whether a message's raw form (with its attachments) is kept after delivery, by the precedence of design section 5: the per-send API flag,
/// then the tenant's setting, then the global default <c>Content:StoreAttachments</c>, all behind the operator's master switch
/// <c>Content:AllowAttachmentStorage</c> (applied by <see cref="SubmissionService"/>). SMTP submissions have no per-send flag and use the tenant's setting.
/// <para>The tenant's setting has three states: set to true, set to false, and not set (inherit the global default). "Set" is the tenant-scoped settings row
/// <c>Content:StoreAttachments</c>. A tenant that only has the older <see cref="Tenant.StoreAttachments"/> column set to true (before the row existed) counts as set to
/// true; false in the column means nothing was ever chosen. A tenant that chose false therefore overrides a global true.</para>
/// </summary>
public static class AttachmentStoragePolicy
{
    public const string StoreAttachmentsKey = "Content:StoreAttachments";

    /// <summary>The tenant's own choice, or null when it never chose (inherit the global default).</summary>
    public static bool? TenantSetting(Tenant tenant, IEnumerable<SettingRecord> tenantSettings)
    {
        SettingRecord? row = tenantSettings.FirstOrDefault(s => s.TenantId == tenant.Id && string.Equals(s.Key, StoreAttachmentsKey, StringComparison.Ordinal));
        if (row is not null && TryBoolean(row.ValueJson, out bool chosen))
        {
            return chosen;
        }

        return tenant.StoreAttachments ? true : null;
    }

    public static async ValueTask<bool?> GetTenantSettingAsync(IConfigStore config, Tenant tenant, CancellationToken ct) =>
        TenantSetting(tenant, await config.GetSettingsAsync(tenant.Id, ct).ConfigureAwait(false));

    /// <summary>The value before the master switch: <paramref name="perSendFlag"/>, else the tenant's setting, else <paramref name="globalDefault"/>.</summary>
    public static async ValueTask<bool> ResolveAsync(IConfigStore config, Tenant tenant, bool? perSendFlag, bool globalDefault, CancellationToken ct) =>
        perSendFlag ?? await GetTenantSettingAsync(config, tenant, ct).ConfigureAwait(false) ?? globalDefault;

    private static bool TryBoolean(string json, out bool value)
    {
        value = false;
        try
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                value = doc.RootElement.GetBoolean();
                return true;
            }
        }
        catch (JsonException)
        {
        }

        return false;
    }
}
