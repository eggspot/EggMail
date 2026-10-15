using Mta.Host.Configuration;

namespace Mta.Host.Tests;

[CollectionDefinition("Process environment variables", DisableParallelization = true)]
public sealed class ProcessEnvironmentCollection;

/// <summary>
/// The precedence of the simple variables against the real process environment (long-form variables, and the HOSTNAME variable that Docker and Kubernetes set
/// in every container). These tests change process-wide environment variables, so they run alone (no other test class runs at the same time) and put every
/// variable back.
/// </summary>
[Collection("Process environment variables")]
public sealed class EnvironmentPrecedenceTests : IDisposable
{
    private readonly Dictionary<string, string?> _saved = [];

    private void Set(string name, string? value)
    {
        if (!_saved.ContainsKey(name))
        {
            _saved[name] = Environment.GetEnvironmentVariable(name);
        }

        Environment.SetEnvironmentVariable(name, value);
    }

    public void Dispose()
    {
        foreach (var (name, value) in _saved)
        {
            Environment.SetEnvironmentVariable(name, value);
        }
    }

    private static MtaConfig Load(Func<string, string?> aliases)
    {
        string directory = Path.Combine(Path.GetTempPath(), "eggmail-precedence-" + Guid.NewGuid().ToString("N"));   // nothing there: no files
        return ConfigLoader.Load(ConfigLoader.Build([], dataDirectoryHint: directory, appSettingsPath: Path.Combine(directory, "appsettings.json"), environment: aliases)).Config;
    }

    [Fact]
    public void EGGMAIL_HOSTNAME_beats_the_HOSTNAME_variable_of_the_container_runtime()
    {
        Set("HOSTNAME", "3f2a1b9c0d11");   // the container id, which is what the configuration sees as the key "Hostname"

        Assert.Equal("3f2a1b9c0d11", Load(_ => null).Hostname);   // without the alias the runtime's value is the host name (the log then says nobody chose it)
        Assert.Equal("mail.example.com", Load(name => name == "EGGMAIL_HOSTNAME" ? "mail.example.com" : null).Hostname);
    }

    [Fact]
    public void A_long_form_environment_variable_beats_the_simple_one_for_every_other_key()
    {
        Set("Acme__Email", "long-form@example.com");

        MtaConfig c = Load(name => name switch { "EGGMAIL_HOSTNAME" => "mail.example.com", "EGGMAIL_ACME_EMAIL" => "alias@example.com", "CLOUDFLARE_API_TOKEN" => "x", _ => null });

        Assert.Equal("long-form@example.com", c.Acme.Email);
        Assert.Equal("mail.example.com", c.Hostname);
    }

    [Fact]
    public void A_long_form_list_in_the_environment_replaces_the_alias_list()
    {
        Set("Acme__Domains__0", "long-form.example.com");

        MtaConfig c = Load(name => name switch { "EGGMAIL_HOSTNAME" => "mail.example.com", "EGGMAIL_ACME_EMAIL" => "alias@example.com", "CLOUDFLARE_API_TOKEN" => "x", _ => null });

        Assert.Equal(["long-form.example.com"], c.Acme.Domains);
    }
}
