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

    private static long _version;

    /// <summary>Changes whenever this process changes a tenant's choice, so the submission cache does not serve the old one (another replica's change shows within the cache time).</summary>
    public static long Version => Interlocked.Read(ref _version);

    public static void Bump() => Interlocked.Increment(ref _version);

    /// <summary>The tenant's own choice from the tenant-scoped settings row, or null when the row is absent.</summary>
    public static bool? RowSetting(Guid tenantId, IEnumerable<SettingRecord> tenantSettings)
    {
        SettingRecord? row = tenantSettings.FirstOrDefault(s => s.TenantId == tenantId && string.Equals(s.Key, StoreAttachmentsKey, StringComparison.Ordinal));
        return row is not null && TryBoolean(row.ValueJson, out bool chosen) ? chosen : null;
    }

    /// <summary>The row if there is one; else the older column counts as a choice only when it is true.</summary>
    public static bool? Combine(Tenant tenant, bool? rowSetting) => rowSetting ?? (tenant.StoreAttachments ? true : null);

    /// <summary>The tenant's own choice, or null when it never chose (inherit the global default).</summary>
    public static bool? TenantSetting(Tenant tenant, IEnumerable<SettingRecord> tenantSettings) => Combine(tenant, RowSetting(tenant.Id, tenantSettings));

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
