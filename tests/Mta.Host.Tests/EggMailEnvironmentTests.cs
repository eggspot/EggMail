using Microsoft.Extensions.Configuration;
using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Tests;

/// <summary>
/// The simple EGGMAIL_* environment variables: what each one stands for, what is refused (with a message that names the variable), and that the long-form
/// configuration always wins over them.
/// </summary>
public class EggMailEnvironmentTests
{
    private static EnvironmentAliasResult Translate(params (string Name, string Value)[] variables)
    {
        var map = variables.ToDictionary(v => v.Name, v => v.Value);
        return EggMailEnvironment.Translate(name => map.GetValueOrDefault(name));
    }

    private static Dictionary<string, string?> Values(EnvironmentAliasResult result) =>
        result.Values.ToDictionary(v => v.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);

    private static LoadedConfig Load(string[] args, params (string Name, string Value)[] variables)
    {
        var map = variables.ToDictionary(v => v.Name, v => v.Value);
        string directory = Path.Combine(Path.GetTempPath(), "eggmail-alias-" + Guid.NewGuid().ToString("N"));   // nothing there: no appsettings.json or bootstrap file
        return ConfigLoader.Load(ConfigLoader.Build(args, dataDirectoryHint: directory, appSettingsPath: Path.Combine(directory, "appsettings.json"), environment: name => map.GetValueOrDefault(name)));
    }

    [Fact]
    public void No_variables_change_nothing()
    {
        EnvironmentAliasResult result = Translate();

        Assert.Empty(result.Values);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void The_host_name_is_normalized_and_sets_Hostname()
    {
        EnvironmentAliasResult result = Translate(("EGGMAIL_HOSTNAME", "  Mail.Example.COM. "));

        Assert.Empty(result.Errors);
        Assert.Equal("mail.example.com", Values(result)["Hostname"]);
    }

    [Theory]
    [InlineData("https://mail.example.com")]
    [InlineData("mail.example.com:587")]
    [InlineData("203.0.113.5")]
    [InlineData("mail example.com")]
    [InlineData("bob@example.com")]
    [InlineData("-bad.example.com")]
    public void A_host_name_that_cannot_be_one_is_refused_by_name(string value)
    {
        EnvironmentAliasResult result = Translate(("EGGMAIL_HOSTNAME", value));

        string error = Assert.Single(result.Errors);
        Assert.Contains("EGGMAIL_HOSTNAME", error, StringComparison.Ordinal);
        Assert.DoesNotContain(result.Values, v => v.Key == "Hostname");
    }

    [Fact]
    public void Host_name_and_acme_email_together_turn_acme_on_for_that_name()
    {
        EnvironmentAliasResult result = Translate(("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_EMAIL", "ops@example.com"));

        Assert.Empty(result.Errors);
        Dictionary<string, string?> values = Values(result);
        Assert.Equal("true", values["Acme:Enabled"]);
        Assert.Equal("ops@example.com", values["Acme:Email"]);
        Assert.Equal("mail.example.com", values["Acme:Domains:0"]);
        Assert.DoesNotContain("Acme:DirectoryUrl", values.Keys);   // the production CA is the default of the key
    }

    [Fact]
    public void The_host_name_alone_does_not_turn_acme_on()
    {
        Dictionary<string, string?> values = Values(Translate(("EGGMAIL_HOSTNAME", "mail.example.com")));

        Assert.DoesNotContain("Acme:Enabled", values.Keys);
    }

    [Fact]
    public void An_acme_email_without_a_host_name_is_refused_and_says_what_to_set()
    {
        string error = Assert.Single(Translate(("EGGMAIL_ACME_EMAIL", "ops@example.com")).Errors);

        Assert.Contains("EGGMAIL_ACME_EMAIL needs EGGMAIL_HOSTNAME", error, StringComparison.Ordinal);
    }

    [Fact]
    public void A_host_name_without_a_dot_cannot_get_a_certificate()
    {
        string error = Assert.Single(Translate(("EGGMAIL_HOSTNAME", "mail"), ("EGGMAIL_ACME_EMAIL", "ops@example.com")).Errors);

        Assert.Contains("no dot", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("not-an-email")]
    [InlineData("a@b@example.com")]
    [InlineData("ops@localhost")]
    public void An_acme_email_that_is_not_an_address_is_refused(string email)
    {
        string error = Assert.Single(Translate(("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_EMAIL", email)).Errors);

        Assert.Contains("EGGMAIL_ACME_EMAIL", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Staging_selects_the_lets_encrypt_staging_directory_and_a_directory_selects_any_ca()
    {
        var staging = Values(Translate(("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_EMAIL", "ops@example.com"), ("EGGMAIL_ACME_STAGING", "true")));
        var other = Values(Translate(("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_EMAIL", "ops@example.com"), ("EGGMAIL_ACME_DIRECTORY", "https://ca.internal/dir")));
        var off = Values(Translate(("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_EMAIL", "ops@example.com"), ("EGGMAIL_ACME_STAGING", "false")));

        Assert.Equal("https://acme-staging-v02.api.letsencrypt.org/directory", staging["Acme:DirectoryUrl"]);
        Assert.Equal("https://ca.internal/dir", other["Acme:DirectoryUrl"]);
        Assert.DoesNotContain("Acme:DirectoryUrl", off.Keys);
    }

    [Fact]
    public void Two_cas_a_bad_directory_a_bad_boolean_and_a_ca_without_acme_are_refused()
    {
        Assert.Contains("two different CAs", Assert.Single(Translate(("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_EMAIL", "ops@example.com"), ("EGGMAIL_ACME_STAGING", "true"), ("EGGMAIL_ACME_DIRECTORY", "https://ca/dir")).Errors), StringComparison.Ordinal);
        Assert.Contains("EGGMAIL_ACME_DIRECTORY", Assert.Single(Translate(("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_EMAIL", "ops@example.com"), ("EGGMAIL_ACME_DIRECTORY", "ca.internal/dir")).Errors), StringComparison.Ordinal);
        Assert.Contains("EGGMAIL_ACME_STAGING", Assert.Single(Translate(("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_EMAIL", "ops@example.com"), ("EGGMAIL_ACME_STAGING", "yes")).Errors), StringComparison.Ordinal);
        Assert.Contains("ACME stays off", Assert.Single(Translate(("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_STAGING", "true")).Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void A_cloudflare_token_selects_the_dns_challenge_in_the_value_or_file_form()
    {
        var token = Values(Translate(("CLOUDFLARE_API_TOKEN", "cf-token")));
        var file = Values(Translate(("CLOUDFLARE_API_TOKEN_FILE", "/run/secrets/cf")));

        Assert.Equal("cf-token", token["Acme:CloudflareApiToken"]);
        Assert.Equal("Dns01", token["Acme:Challenge"]);
        Assert.Equal("/run/secrets/cf", file["Acme:CloudflareApiTokenFile"]);
        Assert.Equal("Dns01", file["Acme:Challenge"]);
        Assert.Single(Translate(("CLOUDFLARE_API_TOKEN", "a"), ("CLOUDFLARE_API_TOKEN_FILE", "/b")).Errors);
    }

    [Fact]
    public void The_administrator_user_and_password_forms()
    {
        var plain = Values(Translate(("EGGMAIL_ADMIN_USER", "owner"), ("EGGMAIL_ADMIN_PASSWORD", "correct horse battery")));
        var file = Values(Translate(("EGGMAIL_ADMIN_PASSWORD_FILE", "/run/secrets/pw")));

        Assert.Equal("owner", plain["Dashboard:BootstrapAdminUser"]);
        Assert.Equal("correct horse battery", plain["Dashboard:BootstrapAdminPassword"]);
        Assert.Equal("/run/secrets/pw", file["Dashboard:BootstrapAdminPasswordFile"]);
        Assert.Contains("both set", Assert.Single(Translate(("EGGMAIL_ADMIN_PASSWORD", "correct horse battery"), ("EGGMAIL_ADMIN_PASSWORD_FILE", "/x")).Errors), StringComparison.Ordinal);
        Assert.Contains("at least 10", Assert.Single(Translate(("EGGMAIL_ADMIN_PASSWORD", "short")).Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void A_password_keeps_its_spaces()
    {
        Assert.Equal(" leading and trailing ", Values(Translate(("EGGMAIL_ADMIN_PASSWORD", " leading and trailing ")))["Dashboard:BootstrapAdminPassword"]);
    }

    [Fact]
    public void Domains_become_the_bootstrap_list_lower_cased_and_without_duplicates()
    {
        var values = Values(Translate(("EGGMAIL_DOMAINS", "Example.com, example.org;example.com")));

        Assert.Equal("example.com", values["Domains:Bootstrap:0"]);
        Assert.Equal("example.org", values["Domains:Bootstrap:1"]);
        Assert.DoesNotContain("Domains:Bootstrap:2", values.Keys);
        Assert.Contains("EGGMAIL_DOMAINS", Assert.Single(Translate(("EGGMAIL_DOMAINS", "https://example.com")).Errors), StringComparison.Ordinal);
        Assert.Contains("EGGMAIL_DOMAINS", Assert.Single(Translate(("EGGMAIL_DOMAINS", "me@example.com")).Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void A_database_variable_switches_to_postgres_with_the_runtime_connection_string()
    {
        var values = Values(Translate(("EGGMAIL_DATABASE", "Host=db;Database=eggmail;Username=eggmail;Password=pw")));

        Assert.Equal("Postgres", values["Storage:Backend"]);
        Assert.Contains("Host=db", values["Storage:Postgres:RuntimeConnectionString"], StringComparison.Ordinal);
        Assert.DoesNotContain("Storage:Postgres:OwnerConnectionString", values.Keys);
    }

    [Fact]
    public void A_postgres_url_is_converted_with_percent_encoding_and_sslmode()
    {
        var values = Values(Translate(("EGGMAIL_DATABASE", "postgres://egg%40mail:p%2Fw%3A1@db.example.com:6432/mail?sslmode=require")));

        var builder = new Npgsql.NpgsqlConnectionStringBuilder(values["Storage:Postgres:RuntimeConnectionString"]);
        Assert.Equal("db.example.com", builder.Host);
        Assert.Equal(6432, builder.Port);
        Assert.Equal("egg@mail", builder.Username);
        Assert.Equal("p/w:1", builder.Password);
        Assert.Equal("mail", builder.Database);
        Assert.Equal(Npgsql.SslMode.Require, builder.SslMode);
    }

    [Theory]
    [InlineData("postgres://db.example.com/mail")]                          // no user
    [InlineData("Host=db;Database=eggmail")]                                // no user
    [InlineData("Database=eggmail;Username=u")]                             // no host
    [InlineData("this is not a connection string")]
    [InlineData("postgres://u:p@db/mail?application_name=x")]               // a parameter the URL form does not carry
    [InlineData("postgres://u:p@db/mail?sslmode=sometimes")]
    public void An_unusable_database_value_is_refused_by_name(string value)
    {
        string error = Assert.Single(Translate(("EGGMAIL_DATABASE", value)).Errors);

        Assert.StartsWith("EGGMAIL_DATABASE:", error, StringComparison.Ordinal);
    }

    [Fact]
    public void A_relay_is_a_host_and_port_with_an_optional_login()
    {
        var plain = Values(Translate(("EGGMAIL_RELAY", "smtp.relay.example:587")));
        var login = Values(Translate(("EGGMAIL_RELAY", "smtp.relay.example:465"), ("EGGMAIL_RELAY_USER", "u"), ("EGGMAIL_RELAY_PASSWORD_FILE", "/run/secrets/relay")));

        Assert.Equal("smtp.relay.example:587", plain["Delivery:Relay:Address"]);
        Assert.Equal("u", login["Delivery:Relay:User"]);
        Assert.Equal("/run/secrets/relay", login["Delivery:Relay:PasswordFile"]);
    }

    [Theory]
    [InlineData("smtp.relay.example")]               // no port
    [InlineData("smtp.relay.example:0")]
    [InlineData("smtp.relay.example:70000")]
    [InlineData("203.0.113.5:587")]                  // an address, not a name
    [InlineData("smtp://smtp.relay.example:587")]
    public void A_relay_that_is_not_host_and_port_is_refused(string value)
    {
        string error = Assert.Single(Translate(("EGGMAIL_RELAY", value)).Errors);

        Assert.StartsWith("EGGMAIL_RELAY:", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Relay_login_variables_need_each_other_and_the_relay()
    {
        Assert.Contains("without EGGMAIL_RELAY", Assert.Single(Translate(("EGGMAIL_RELAY_USER", "u")).Errors), StringComparison.Ordinal);
        Assert.Contains("needs EGGMAIL_RELAY_USER", Assert.Single(Translate(("EGGMAIL_RELAY", "h.example:587"), ("EGGMAIL_RELAY_PASSWORD", "p")).Errors), StringComparison.Ordinal);
        Assert.Contains("needs EGGMAIL_RELAY_PASSWORD", Assert.Single(Translate(("EGGMAIL_RELAY", "h.example:587"), ("EGGMAIL_RELAY_USER", "u")).Errors), StringComparison.Ordinal);
        Assert.Contains("both set", Assert.Single(Translate(("EGGMAIL_RELAY", "h.example:587"), ("EGGMAIL_RELAY_USER", "u"), ("EGGMAIL_RELAY_PASSWORD", "p"), ("EGGMAIL_RELAY_PASSWORD_FILE", "/f")).Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void Blank_variables_count_as_unset()
    {
        EnvironmentAliasResult result = Translate(("EGGMAIL_HOSTNAME", ""), ("EGGMAIL_ACME_EMAIL", "  "), ("EGGMAIL_DATABASE", ""), ("EGGMAIL_RELAY", " "));

        Assert.Empty(result.Values);
        Assert.Empty(result.Errors);
    }

    // The layering

    [Fact]
    public void The_variables_reach_the_typed_configuration()
    {
        LoadedConfig loaded = Load([],
            ("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_EMAIL", "ops@example.com"), ("CLOUDFLARE_API_TOKEN", "cf"), ("EGGMAIL_ADMIN_USER", "owner"),
            ("EGGMAIL_DATABASE", "Host=db;Database=eggmail;Username=eggmail;Password=pw"), ("EGGMAIL_RELAY", "smtp.relay.example:587"));

        Assert.True(loaded.IsValid, string.Join("; ", loaded.Errors));
        MtaConfig c = loaded.Config;
        Assert.Equal("mail.example.com", c.Hostname);
        Assert.True(c.Acme.Enabled);
        Assert.Equal("ops@example.com", c.Acme.Email);
        Assert.Equal(["mail.example.com"], c.Acme.Domains);
        Assert.Equal("cf", c.Acme.CloudflareApiToken);
        Assert.Equal("owner", c.Dashboard.BootstrapAdminUser);
        Assert.Equal(StorageBackend.Postgres, c.Storage.Backend);
        Assert.Equal("Host=db;Database=eggmail;Username=eggmail;Password=pw", c.Storage.Postgres.RuntimeConnectionString);
        Assert.Equal("smtp.relay.example:587", c.Delivery.Relay.Address);
        Assert.Contains("Hostname", loaded.LockedKeys);   // the deployment set it, so the dashboard shows it as set from outside
    }

    [Fact]
    public void The_long_form_configuration_wins_over_the_simple_variables()
    {
        LoadedConfig fromCommandLine = Load(["--Hostname=other.example.com", "--Storage:Backend=Sqlite"],
            ("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_DATABASE", "Host=db;Database=eggmail;Username=eggmail"));

        Assert.Equal("other.example.com", fromCommandLine.Config.Hostname);
        Assert.Equal(StorageBackend.Sqlite, fromCommandLine.Config.Storage.Backend);
    }

    [Fact]
    public void The_simple_variables_sit_above_the_files_and_below_the_long_form_environment_and_the_command_line()
    {
        // The long-form environment variables come from the real process environment, which a test must not change; the order of the layers is what decides.
        string directory = Path.Combine(Path.GetTempPath(), "eggmail-alias-" + Guid.NewGuid().ToString("N"));
        IConfigurationRoot root = ConfigLoader.Build([], dataDirectoryHint: directory, appSettingsPath: Path.Combine(directory, "appsettings.json"), environment: _ => null);

        List<Type> order = root.Providers.Select(p => p.GetType()).ToList();
        int simple = order.IndexOf(typeof(EggMailEnvironmentProvider));
        int environment = order.IndexOf(typeof(Microsoft.Extensions.Configuration.EnvironmentVariables.EnvironmentVariablesConfigurationProvider));
        int commandLine = order.IndexOf(typeof(Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider));
        Assert.True(simple >= 0 && simple < environment && environment < commandLine, string.Join(", ", order.Select(t => t.Name)));
    }

    [Fact]
    public void A_problem_in_a_variable_makes_the_configuration_invalid()
    {
        LoadedConfig loaded = Load([], ("EGGMAIL_ACME_EMAIL", "ops@example.com"));

        Assert.False(loaded.IsValid);
        Assert.Contains(loaded.Errors, e => e.Contains("EGGMAIL_ACME_EMAIL needs EGGMAIL_HOSTNAME", StringComparison.Ordinal));
    }

    [Fact]
    public void The_variables_are_identical_in_the_code_and_the_operations_guide()
    {
        string guide = File.ReadAllText(ConfigurationDocumentationTests.DocumentationPath());
        foreach (EnvironmentAlias alias in EggMailEnvironment.Aliases)
        {
            Assert.True(guide.Contains($"| `{alias.Name}` |", StringComparison.Ordinal), $"docs/operations.md has no table row for {alias.Name}");
        }

        // Every variable the table in the guide lists is one the code reads (a row for a variable nothing reads is a lie).
        var listed = System.Text.RegularExpressions.Regex.Matches(guide, @"^\| `((?:EGGMAIL_|CLOUDFLARE_)[A-Z_]+)` \|", System.Text.RegularExpressions.RegexOptions.Multiline).Select(m => m.Groups[1].Value);
        Assert.All(listed, name => Assert.Contains(EggMailEnvironment.Aliases, a => a.Name == name));
    }

    /// <summary>EGGMAIL_ names in the documents and deployment files that are not configuration aliases (compose substitution variables, scripts, tests).</summary>
    private static readonly string[] NotAliases = ["EGGMAIL_IMAGE", "EGGMAIL_DB_PASSWORD", "EGGMAIL_BUNDLE_PASSPHRASE"];

    [Fact]
    public void The_documents_and_compose_files_use_only_variables_that_exist()
    {
        // A typo such as EGGMAIL_HOST in the quick start would be copied by every reader, and nothing else would notice.
        string root = Path.GetDirectoryName(Path.GetDirectoryName(ConfigurationDocumentationTests.DocumentationPath()))!;
        string[] files = ["README.md", "docs/operations.md", "docs/release.md", "deploy/compose/compose.yaml", "deploy/compose/compose.postgres.yaml", "deploy/compose/.env.example"];
        string[] known = [.. EggMailEnvironment.Aliases.Select(a => a.Name), .. NotAliases];
        foreach (string file in files)
        {
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(File.ReadAllText(Path.Combine(root, file)), @"\b(?:EGGMAIL|CLOUDFLARE)_[A-Z0-9_]+"))
            {
                Assert.True(known.Contains(m.Value), $"{file} mentions {m.Value}, which is not a variable the server reads");
            }
        }
    }

    [Fact]
    public void Every_key_an_alias_stands_for_is_a_key_the_code_reads()
    {
        SortedSet<string> read = ConfigurationDocumentationTests.KeysReadByCodeForTests();
        foreach (string key in EggMailEnvironment.Aliases.SelectMany(a => a.Keys).Distinct())
        {
            if (ConfigurationDocumentationTests.KeysFromOtherChanges.Contains(key, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            Assert.True(read.Contains(key), $"an environment variable maps to {key}, which nothing reads");
        }
    }
}
