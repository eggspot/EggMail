using System.Text.Json;
using System.Text.RegularExpressions;
using Mta.Storage;

namespace Mta.Host.Configuration;

/// <summary>
/// The global settings kept in the configuration store (edited through <c>/admin/settings</c>) as a configuration layer. A stored value
/// is the lowest layer: command line, environment, mounted files and the bootstrap file all win over it, and those keys are shown as
/// locked in the dashboard. Only rows that look like configuration keys (<c>Section:Name</c>) are used; the store also holds internal
/// rows (Data Protection key ring, VERP keys) that must never become configuration.
/// </summary>
public static partial class StoredSettings
{
    [GeneratedRegex(@"^[A-Za-z][A-Za-z0-9]*(:[A-Za-z][A-Za-z0-9]*)+$")]
    private static partial Regex ConfigKey();

    public static async Task<IReadOnlyList<KeyValuePair<string, string?>>> LoadAsync(IConfigStore config, CancellationToken ct)
    {
        var rows = await config.GetSettingsAsync(null, ct).ConfigureAwait(false);
        var result = new List<KeyValuePair<string, string?>>();
        foreach (var row in rows.Where(r => r.TenantId is null && ConfigKey().IsMatch(r.Key)))
        {
            if (TryScalar(row.ValueJson, out string? value))
            {
                result.Add(new KeyValuePair<string, string?>(row.Key, value));
            }
        }

        return result;
    }

    internal static bool TryScalar(string json, out string? value)
    {
        value = null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            switch (doc.RootElement.ValueKind)
            {
                case JsonValueKind.String:
                    value = doc.RootElement.GetString();
                    return true;
                case JsonValueKind.Number:
                    value = doc.RootElement.GetRawText();
                    return true;
                case JsonValueKind.True:
                    value = "true";
                    return true;
                case JsonValueKind.False:
                    value = "false";
                    return true;
                default:
                    return false;
            }
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
