using Microsoft.Extensions.Configuration;
using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Tests;

/// <summary>
/// The simple EGGMAIL_* environment variables: what each one stands for, what is refused (with a message that names the variable), and that the long-form
/// configuration always wins over them.
/// </summary>
public class EnvironmentAliasesTests
{
    private static EnvironmentAliasResult Translate(params (string Name, string Value)[] variables)
    {
        var map = variables.ToDictionary(v => v.Name, v => v.Value);
        return EnvironmentAliases.Translate(name => map.GetValueOrDefault(name));
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
    public void The_documented_recipe_host_name_and_acme_email_alone_is_valid_and_uses_http_01_and_a_cloudflare_token_selects_dns_01()
    {
        LoadedConfig http = Load([], ("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_EMAIL", "ops@example.com"));
        Assert.True(http.IsValid, string.Join("; ", http.Errors));
        Assert.True(http.Config.Acme.Enabled);
        Assert.False(http.Config.Acme.UsesDns01());                       // no Cloudflare token: the built-in HTTP-01 listener answers the CA
        Assert.Equal(["mail.example.com"], http.Config.Acme.Domains);
        Assert.Equal("ops@example.com", http.Config.Acme.Email);

        LoadedConfig dns = Load([], ("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_EMAIL", "ops@example.com"), ("CLOUDFLARE_API_TOKEN", "cf"));
        Assert.True(dns.IsValid, string.Join("; ", dns.Errors));
        Assert.True(dns.Config.Acme.UsesDns01());

        LoadedConfig staging = Load([], ("EGGMAIL_HOSTNAME", "mail.example.com"), ("EGGMAIL_ACME_EMAIL", "ops@example.com"), ("EGGMAIL_ACME_STAGING", "true"));
        Assert.True(staging.IsValid, string.Join("; ", staging.Errors));
        Assert.Equal(AcmeSection.LetsEncryptStagingDirectoryUrl, staging.Config.Acme.EffectiveDirectoryUrl());
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
    }

    [Fact]
    public void A_ca_choice_without_acme_is_refused_unless_acme_is_switched_on_some_other_way()
    {
        // Whether ACME is on is decided by the whole configuration, not by the aliases alone.
        LoadedConfig alone = Load([], ("EGGMAIL_ACME_STAGING", "true"));
        Assert.False(alone.IsValid);
        Assert.Contains(alone.Errors, e => e.Contains("ACME stays off", StringComparison.Ordinal));

        LoadedConfig enabledElsewhere = Load(["--Acme:Enabled=true", "--Acme:CloudflareApiToken=x"], ("EGGMAIL_ACME_STAGING", "true"));
        Assert.DoesNotContain(enabledElsewhere.Errors, e => e.Contains("ACME stays off", StringComparison.Ordinal));
        Assert.Equal(EnvironmentAliases.AcmeStagingDirectory, enabledElsewhere.Config.Acme.DirectoryUrl);
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
    public void The_administrator_user_and_password_forms_are_only_mapped_and_trimmed()
    {
        var plain = Values(Translate(("EGGMAIL_ADMIN_USER", "owner"), ("EGGMAIL_ADMIN_PASSWORD", "  correct horse battery\n")));
        var file = Values(Translate(("EGGMAIL_ADMIN_PASSWORD_FILE", "/run/secrets/pw")));

        Assert.Equal("owner", plain["Dashboard:BootstrapAdminUser"]);
        Assert.Equal("correct horse battery", plain["Dashboard:BootstrapAdminPassword"]);   // trimmed, like the contents of the password file
        Assert.Equal("/run/secrets/pw", file["Dashboard:BootstrapAdminPasswordFile"]);
    }

    [Fact]
    public void A_weak_or_doubled_administrator_password_does_not_block_commands_that_never_create_the_administrator()
    {
        // `mta --healthcheck` and `mta admin create` read the same environment as the server: whether the password is usable matters only when the first
        // administrator is created (FirstAdministrator), so the alias layer and the configuration are valid here.
        LoadedConfig loaded = Load([], ("EGGMAIL_ADMIN_PASSWORD", "short"), ("EGGMAIL_ADMIN_PASSWORD_FILE", "/x"), ("EGGMAIL_ADMIN_USER", "a b\tc"));

        Assert.True(loaded.IsValid, string.Join("; ", loaded.Errors));
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

    [Theory]
    [InlineData("EGGMAIL_RELAY", "relayuser:SECRETPW@smtp.relay.example:587")]
    [InlineData("EGGMAIL_RELAY", "smtp://relayuser:SECRETPW@smtp.relay.example:587")]
    [InlineData("EGGMAIL_RELAY", "SECRETPW")]
    [InlineData("EGGMAIL_DATABASE", "SECRETPW")]
    [InlineData("EGGMAIL_DATABASE", "Host=db;Password=SECRETPW;Bogus=1")]
    [InlineData("EGGMAIL_DATABASE", "Host=db;Password=SECRETPW;Port=notanumber;Username=u")]
    [InlineData("EGGMAIL_DATABASE", "Host=db;Password=SECRETPW")]
    [InlineData("EGGMAIL_DATABASE", "Password=SECRETPW;Username=u")]
    [InlineData("EGGMAIL_DATABASE", "postgres://u:SECRETPW@/db")]
    [InlineData("EGGMAIL_DATABASE", "postgres://u:SECRETPW@db/x?sslmode=SECRETPW")]
    [InlineData("EGGMAIL_DATABASE", "postgres://u:SECRETPW@db/x?target_session_attrs=SECRETPW")]
    [InlineData("EGGMAIL_DATABASE", "postgres://u:SECRETPW@[::bad")]
    [InlineData("EGGMAIL_DATABASE", "Host=db;Password=SECRETPW;Username=u;Ssl Mode=SECRETPW")]
    [InlineData("EGGMAIL_HOSTNAME", "https://user:SECRETPW@mail.example.com")]
    [InlineData("EGGMAIL_ACME_EMAIL", "SECRETPW")]
    [InlineData("EGGMAIL_ACME_DIRECTORY", "ca.example/SECRETPW")]
    [InlineData("EGGMAIL_DOMAINS", "https://user:SECRETPW@example.com")]
    public void An_error_names_the_variable_and_never_repeats_the_value(string variable, string value)
    {
        // The value of these variables can carry a password (a login in a relay address, a connection string); a log line or a terminal must never show it.
        var variables = new List<(string, string)> { (variable, value) };
        if (variable == "EGGMAIL_ACME_EMAIL" || variable == "EGGMAIL_ACME_DIRECTORY")
        {
            variables.Add(("EGGMAIL_HOSTNAME", "mail.example.com"));
        }

        LoadedConfig loaded = Load([], [.. variables]);

        Assert.False(loaded.IsValid, $"{variable}={value} was accepted");
        Assert.All(loaded.Errors, e => Assert.DoesNotContain("SECRETPW", e, StringComparison.Ordinal));
        Assert.Contains(loaded.Errors, e => e.Contains(variable, StringComparison.Ordinal));
    }

    [Fact]
    public void A_relay_login_in_the_address_is_explained_without_being_shown()
    {
        string error = Assert.Single(Translate(("EGGMAIL_RELAY", "relayuser:SECRETPW@smtp.relay.example:587")).Errors);

        Assert.Contains("EGGMAIL_RELAY_USER", error, StringComparison.Ordinal);
        Assert.DoesNotContain("SECRETPW", error, StringComparison.Ordinal);
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
    public void The_simple_variables_sit_above_the_files_and_below_the_long_form_environment_and_the_command_line_except_the_host_name()
    {
        // The long-form environment variables come from the real process environment, which a test must not change; the order of the layers is what decides.
        string directory = Path.Combine(Path.GetTempPath(), "eggmail-alias-" + Guid.NewGuid().ToString("N"));
        IConfigurationRoot root = ConfigLoader.Build([], dataDirectoryHint: directory, appSettingsPath: Path.Combine(directory, "appsettings.json"),
            environment: name => name == "EGGMAIL_HOSTNAME" ? "mail.example.com" : name == "EGGMAIL_ADMIN_USER" ? "owner" : null);

        List<IConfigurationProvider> providers = root.Providers.ToList();
        int below = providers.FindIndex(p => p is EnvironmentAliasesProvider);
        int environment = providers.FindIndex(p => p is Microsoft.Extensions.Configuration.EnvironmentVariables.EnvironmentVariablesConfigurationProvider);
        int above = providers.FindLastIndex(p => p is EnvironmentAliasesProvider);
        int commandLine = providers.FindIndex(p => p is Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider);
        Assert.True(below >= 0 && below < environment && environment < above && above < commandLine, string.Join(", ", providers.Select(p => p.GetType().Name)));

        // Only the host name is above the environment: Docker and Kubernetes set HOSTNAME (the container id) in every container, and configuration keys are
        // case-insensitive, so that variable would otherwise silently beat EGGMAIL_HOSTNAME.
        Assert.True(providers[above].TryGet("Hostname", out string? hostname));
        Assert.Equal("mail.example.com", hostname);
        Assert.False(providers[below].TryGet("Hostname", out _));
        Assert.True(providers[below].TryGet("Dashboard:BootstrapAdminUser", out _));
        Assert.False(providers[above].TryGet("Dashboard:BootstrapAdminUser", out _));
    }

    private static string TemporaryDirectory()
    {
        string directory = Path.Combine(Path.GetTempPath(), "eggmail-alias-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    [Fact]
    public void The_simple_variables_win_over_appsettings_and_the_bootstrap_file_and_lose_to_the_command_line()
    {
        string directory = TemporaryDirectory();
        try
        {
            string appSettings = Path.Combine(directory, "appsettings.json");
            File.WriteAllText(appSettings, """{ "Hostname": "from-appsettings.example.com", "Acme": { "Email": "settings@example.com" }, "Delivery": { "Relay": { "Address": "settings.relay.example:587" } } }""");
            File.WriteAllText(Path.Combine(directory, ConfigLoader.BootstrapFileName), """{ "Storage": { "Backend": "Sqlite" }, "Delivery": { "Relay": { "Address": "bootstrap.relay.example:587" } } }""");
            Func<string, string?> env = name => name switch
            {
                "EGGMAIL_HOSTNAME" => "alias.example.com", "EGGMAIL_ACME_EMAIL" => "alias@example.com", "EGGMAIL_RELAY" => "alias.relay.example:587",
                "EGGMAIL_DATABASE" => "Host=db;Database=eggmail;Username=eggmail", _ => null,
            };

            MtaConfig plain = ConfigLoader.Load(ConfigLoader.Build([], dataDirectoryHint: directory, appSettingsPath: appSettings, environment: env)).Config;
            Assert.Equal("alias.example.com", plain.Hostname);
            Assert.Equal("alias@example.com", plain.Acme.Email);
            Assert.Equal("alias.relay.example:587", plain.Delivery.Relay.Address);
            Assert.Equal(StorageBackend.Postgres, plain.Storage.Backend);   // the bootstrap file says Sqlite; the environment alias is above it

            MtaConfig overridden = ConfigLoader.Load(ConfigLoader.Build(["--Hostname=cli.example.com", "--Acme:Email=cli@example.com", "--Storage:Backend=Sqlite"], dataDirectoryHint: directory, appSettingsPath: appSettings, environment: env)).Config;
            Assert.Equal("cli.example.com", overridden.Hostname);
            Assert.Equal("cli@example.com", overridden.Acme.Email);
            Assert.Equal(StorageBackend.Sqlite, overridden.Storage.Backend);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);   // created by this test
        }
    }

    [Fact]
    public void The_stored_settings_layer_is_below_the_simple_variables()
    {
        var stored = new[] { new KeyValuePair<string, string?>("Acme:Email", "stored@example.com"), new KeyValuePair<string, string?>("Sending:GlobalPerHour", "10") };
        string directory = Path.Combine(Path.GetTempPath(), "eggmail-alias-" + Guid.NewGuid().ToString("N"));

        MtaConfig c = ConfigLoader.Load(ConfigLoader.Build([], dataDirectoryHint: directory, appSettingsPath: Path.Combine(directory, "appsettings.json"), storedSettings: stored,
            environment: name => name switch { "EGGMAIL_HOSTNAME" => "mail.example.com", "EGGMAIL_ACME_EMAIL" => "alias@example.com", _ => null })).Config;

        Assert.Equal("alias@example.com", c.Acme.Email);
        Assert.Equal(10, c.Sending.GlobalPerHour);
    }

    [Fact]
    public void A_list_from_a_variable_replaces_the_list_of_a_lower_layer_instead_of_merging_by_index()
    {
        string directory = TemporaryDirectory();
        try
        {
            string appSettings = Path.Combine(directory, "appsettings.json");
            File.WriteAllText(appSettings, """{ "Acme": { "Domains": ["old-one.example.com", "old-two.example.com"] }, "Api": { "MetricsAllowedNetworks": ["10.0.0.0/8", "192.168.0.0/16"] } }""");

            MtaConfig c = ConfigLoader.Load(ConfigLoader.Build(["--Api:MetricsAllowedNetworks:0=172.16.0.0/12"], dataDirectoryHint: directory, appSettingsPath: appSettings,
                environment: name => name switch { "EGGMAIL_HOSTNAME" => "mail.example.com", "EGGMAIL_ACME_EMAIL" => "ops@example.com", "CLOUDFLARE_API_TOKEN" => "x", _ => null })).Config;

            Assert.Equal(["mail.example.com"], c.Acme.Domains);                        // not [mail.example.com, old-two.example.com]
            Assert.Equal(["172.16.0.0/12"], c.Api.MetricsAllowedNetworks);             // the command line owns this list too
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void EGGMAIL_DOMAINS_replaces_the_bootstrap_domains_of_a_lower_layer_and_a_long_form_list_replaces_the_alias_list()
    {
        string directory = TemporaryDirectory();
        try
        {
            string appSettings = Path.Combine(directory, "appsettings.json");
            File.WriteAllText(appSettings, """{ "Domains": { "Bootstrap": ["old-one.example", "old-two.example"], "MtaStsMx": ["mx1.example.com", "mx2.example.com"] } }""");
            Func<string, string?> env = name => name == "EGGMAIL_DOMAINS" ? "new.example" : null;

            MtaConfig fromAlias = ConfigLoader.Load(ConfigLoader.Build([], dataDirectoryHint: directory, appSettingsPath: appSettings, environment: env)).Config;
            Assert.Equal(["new.example"], fromAlias.Domains.Bootstrap);                       // not [new.example, old-two.example]
            Assert.Equal(["mx1.example.com", "mx2.example.com"], fromAlias.Domains.MtaStsMx);   // a list nobody else mentions is untouched

            MtaConfig fromCommandLine = ConfigLoader.Load(ConfigLoader.Build(["--Domains:Bootstrap:0=cli.example", "--Domains:MtaStsMx:0=mx.cli.example"], dataDirectoryHint: directory, appSettingsPath: appSettings, environment: env)).Config;
            Assert.Equal(["cli.example"], fromCommandLine.Domains.Bootstrap);                 // the command line owns the list
            Assert.Equal(["mx.cli.example"], fromCommandLine.Domains.MtaStsMx);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void A_list_in_the_same_layer_keeps_all_its_entries_and_a_separated_value_is_split()
    {
        string directory = TemporaryDirectory();
        try
        {
            string appSettings = Path.Combine(directory, "appsettings.json");
            File.WriteAllText(appSettings, """{ "Acme": { "Domains": ["a.example.com", "b.example.com"] } }""");

            Assert.Equal(["a.example.com", "b.example.com"], ConfigLoader.Load(ConfigLoader.Build([], dataDirectoryHint: directory, appSettingsPath: appSettings, environment: _ => null)).Config.Acme.Domains);
            Assert.Equal(["x.example.com", "y.example.com"], ConfigLoader.Load(ConfigLoader.Build(["--Acme:Domains=x.example.com, y.example.com"], dataDirectoryHint: directory, appSettingsPath: appSettings, environment: _ => null)).Config.Acme.Domains);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
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
        foreach (EnvironmentAlias alias in EnvironmentAliases.Aliases)
        {
            Assert.True(guide.Contains($"| `{alias.Name}` |", StringComparison.Ordinal), $"docs/operations.md has no table row for {alias.Name}");
        }

        // Every variable the table in the guide lists is one the code reads (a row for a variable nothing reads is a lie).
        var listed = System.Text.RegularExpressions.Regex.Matches(guide, @"^\| `((?:EGGMAIL_|CLOUDFLARE_)[A-Z_]+)` \|", System.Text.RegularExpressions.RegexOptions.Multiline).Select(m => m.Groups[1].Value);
        Assert.All(listed, name => Assert.Contains(EnvironmentAliases.Aliases, a => a.Name == name));
    }

    /// <summary>EGGMAIL_ names in the documents and deployment files that are not configuration aliases (compose substitution variables, scripts, tests).</summary>
    private static readonly string[] NotAliases = ["EGGMAIL_IMAGE", "EGGMAIL_DB_PASSWORD", "EGGMAIL_BUNDLE_PASSPHRASE"];

    [Fact]
    public void The_documents_and_compose_files_use_only_variables_that_exist()
    {
        // A typo such as EGGMAIL_HOST in the quick start would be copied by every reader, and nothing else would notice.
        string root = Path.GetDirectoryName(Path.GetDirectoryName(ConfigurationDocumentationTests.DocumentationPath()))!;
        string[] files = ["README.md", "docs/operations.md", "docs/release.md", "deploy/compose/compose.yaml", "deploy/compose/compose.postgres.yaml", "deploy/compose/.env.example"];
        string[] known = [.. EnvironmentAliases.Aliases.Select(a => a.Name), .. NotAliases];
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
        foreach (string key in EnvironmentAliases.Aliases.SelectMany(a => a.Keys).Distinct())
        {
            Assert.True(read.Contains(key), $"an environment variable maps to {key}, which nothing reads");
        }
    }
}
