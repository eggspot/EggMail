using Microsoft.Extensions.Configuration;
using Mta.Storage;

namespace Mta.Host.Switching;

/// <summary>
/// The configuration of the switch target. It starts from the source's own configuration (so history mode, retention, content
/// and the secrets settings are the same unless said otherwise) and applies every key under <c>SwitchTarget:</c> on top, for
/// example <c>SwitchTarget:Sqlite:DataDirectory</c> or <c>SwitchTarget:Storage:Postgres:RuntimeConnectionString</c>. The target
/// backend is the <c>--to</c> value.
/// </summary>
public static class SwitchTargetConfiguration
{
    public const string Prefix = "SwitchTarget:";

    /// <summary>Parses <c>postgres</c> or <c>sqlite</c> (any case).</summary>
    public static bool TryParseBackend(string? text, out StorageBackend backend)
    {
        backend = StorageBackend.Sqlite;
        if (string.Equals(text, "postgres", StringComparison.OrdinalIgnoreCase) || string.Equals(text, "postgresql", StringComparison.OrdinalIgnoreCase))
        {
            backend = StorageBackend.Postgres;
            return true;
        }

        return string.Equals(text, "sqlite", StringComparison.OrdinalIgnoreCase);
    }

    public static IConfiguration Build(IConfiguration main, StorageBackend backend, string? targetDirectory = null)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, string?> kv in main.AsEnumerable())
        {
            if (kv.Value is not null && !kv.Key.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            {
                values[kv.Key] = kv.Value;
            }
        }

        foreach (KeyValuePair<string, string?> kv in main.AsEnumerable())
        {
            if (kv.Value is not null && kv.Key.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            {
                values[kv.Key[Prefix.Length..]] = kv.Value;
            }
        }

        values["Storage:Backend"] = backend.ToString();
        if (targetDirectory is not null)
        {
            values["Sqlite:DataDirectory"] = targetDirectory;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }
}
