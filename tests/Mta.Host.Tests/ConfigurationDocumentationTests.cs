using System.Reflection;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using Mta.Host.Configuration;

namespace Mta.Host.Tests;

/// <summary>
/// docs/operations.md and the code agree on the configuration keys: every key the loader reads is documented with its full name, and every
/// key the guide names is one the code reads. A new setting without documentation, or a documented setting nothing reads, fails here.
/// </summary>
public partial class ConfigurationDocumentationTests
{
    /// <summary>Keys that are documented as a family because their names are chosen by the operator (their prefix is read as a whole).</summary>
    private static readonly string[] DocumentedFamilies = ["SwitchTarget:", "SwitchSource:"];

    [GeneratedRegex(@"`([A-Z][A-Za-z0-9]*(?::[A-Za-z0-9<>*-]+)*)`")]
    private static partial Regex KeySpan();

    internal static SortedSet<string> KeysReadByCodeForTests() => KeysReadByCode();

    internal static string DocumentationPath()
    {
        for (string? dir = AppContext.BaseDirectory; dir is not null; dir = Path.GetDirectoryName(dir))
        {
            string candidate = Path.Combine(dir, "docs", "operations.md");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException("docs/operations.md was not found above " + AppContext.BaseDirectory);
    }

    /// <summary>The key-looking names in code spans of the guide (a key has a section, or is <c>Hostname</c>).</summary>
    private static HashSet<string> DocumentedKeys()
    {
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in KeySpan().Matches(File.ReadAllText(DocumentationPath())))
        {
            string key = m.Groups[1].Value;
            if (key.Contains(':', StringComparison.Ordinal) || key == "Hostname")
            {
                keys.Add(key);
            }
        }

        return keys;
    }

    /// <summary>Keys bound by section classes (reflection) plus the keys the hand-written storage binding asks the configuration for (recorded).</summary>
    private static SortedSet<string> KeysReadByCode()
    {
        var keys = new SortedSet<string>(StringComparer.OrdinalIgnoreCase) { "Hostname" };
        foreach (PropertyInfo section in typeof(MtaConfig).GetProperties().Where(p => p.Name is not ("Hostname" or "Storage")))
        {
            AddSection(keys, section.Name, section.PropertyType);
        }

        var recorder = new RecordingConfiguration();
        ConfigLoader.Load(recorder);
        foreach (string key in recorder.Keys.Where(k => k.Contains(':', StringComparison.Ordinal)))
        {
            keys.Add(key);
        }

        return keys;
    }

    private static void AddSection(SortedSet<string> keys, string prefix, Type type)
    {
        foreach (PropertyInfo p in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            string key = prefix + ":" + p.Name;
            Type t = p.PropertyType;
            if (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(Dictionary<,>))
            {
                AddSection(keys, key + ":<name>", t.GetGenericArguments()[1]);
            }
            else if (IsSection(t))
            {
                AddSection(keys, key, t);
            }
            else
            {
                keys.Add(key);
            }
        }
    }

    private static bool IsSection(Type t) => t.IsClass && t != typeof(string) && !t.IsGenericType && !t.IsArray && t.Namespace?.StartsWith("Mta.", StringComparison.Ordinal) == true;

    [Fact]
    public void Every_key_the_code_reads_is_documented_in_the_operations_guide()
    {
        HashSet<string> documented = DocumentedKeys();
        string[] missing = KeysReadByCode().Where(k => !documented.Contains(k)).ToArray();
        Assert.True(missing.Length == 0, "docs/operations.md does not document these configuration keys (use the full key in a code span):\n  " + string.Join("\n  ", missing));
    }

    [Fact]
    public void Every_key_the_operations_guide_names_is_read_by_the_code()
    {
        SortedSet<string> read = KeysReadByCode();
        string[] unknown = DocumentedKeys()
            .Where(k => !read.Contains(k)
                && !DocumentedFamilies.Any(f => k.StartsWith(f, StringComparison.OrdinalIgnoreCase))
                && !Mta.Host.Api.SettingsService.TenantSettingKeys.Contains(k, StringComparer.OrdinalIgnoreCase))   // per-tenant settings: stored per tenant, not deployment configuration
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        Assert.True(unknown.Length == 0, "docs/operations.md names configuration keys nothing reads (fix the name or remove the row):\n  " + string.Join("\n  ", unknown));
    }

    [Fact]
    public void The_key_catalog_sees_nested_sections_listeners_and_storage_keys()
    {
        SortedSet<string> keys = KeysReadByCode();
        Assert.Contains("Delivery:Throttle:MaxConnections", keys);
        Assert.Contains("Smtp:Listeners:<name>:Port", keys);
        Assert.Contains("Storage:Postgres:RuntimeConnectionString", keys);
        Assert.Contains("Mail:Database:Migrate", keys);
        Assert.Contains("Webhooks:Timeout", keys);
        Assert.Contains("Tls:CertificatePath", keys);
        Assert.Contains("Api:SessionLifetime", keys);
    }

    /// <summary>An empty configuration that remembers every key it was asked for (indexer and <c>GetSection</c>, which is what <c>GetValue</c> uses).</summary>
    private sealed class RecordingConfiguration : IConfiguration
    {
        private readonly IConfigurationRoot _inner = new ConfigurationBuilder().Build();
        private readonly List<string> _keys = [];

        public IReadOnlyList<string> Keys => _keys;

        public string? this[string key]
        {
            get
            {
                _keys.Add(key);
                return _inner[key];
            }
            set => _inner[key] = value;
        }

        public IConfigurationSection GetSection(string key)
        {
            _keys.Add(key);
            return _inner.GetSection(key);
        }

        public IEnumerable<IConfigurationSection> GetChildren() => _inner.GetChildren();

        public IChangeToken GetReloadToken() => _inner.GetReloadToken();
    }
}
