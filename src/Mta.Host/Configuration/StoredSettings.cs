using System.Text.Json;
using System.Text.RegularExpressions;
using Mta.Storage;

namespace Mta.Host.Configuration;

/// <summary>
/// The global settings kept in the configuration store (edited through <c>/admin/settings</c>) as a configuration layer. A stored value
/// is the lowest layer: command line, environment, mounted files and the bootstrap file all win over it, and those keys are shown as
/// locked in the dashboard. Only rows that look like configuration keys (<c>Section:Name</c>) are used; the store also holds internal
/// rows (Data Protection key ring, the marker left where the VERP keys were) that must never become configuration.
/// </summary>
public static partial class StoredSettings
{
    [GeneratedRegex(@"^[A-Za-z][A-Za-z0-9]*(:[A-Za-z][A-Za-z0-9]*)+$")]
    private static partial Regex ConfigKey();

    private const string MaxLifetimeDaysKey = "Queue:MaxLifetimeDays";

    public static async Task<IReadOnlyList<KeyValuePair<string, string?>>> LoadAsync(IConfigStore config, CancellationToken ct)
    {
        var rows = await config.GetSettingsAsync(null, ct).ConfigureAwait(false);
        var result = new List<KeyValuePair<string, string?>>();
        foreach (var row in rows.Where(r => r.TenantId is null && ConfigKey().IsMatch(r.Key)))
        {
            if (!TryScalar(row.ValueJson, out string? value))
            {
                continue;
            }

            // The API edits the queue lifetime in whole days (Queue:MaxLifetimeDays); the configuration key is a time span (Queue:MaxLifetime).
            // Without this translation the stored value would be ignored at the next start.
            if (string.Equals(row.Key, MaxLifetimeDaysKey, StringComparison.OrdinalIgnoreCase))
            {
                if (long.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long days) && days is > 0 and < 3650)
                {
                    result.Add(new KeyValuePair<string, string?>("Queue:MaxLifetime", TimeSpan.FromDays(days).ToString("c", System.Globalization.CultureInfo.InvariantCulture)));
                }

                continue;
            }

            result.Add(new KeyValuePair<string, string?>(row.Key, value));
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
