using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using Npgsql;

namespace Mta.Host.Configuration;

/// <summary>One simple environment variable of the quick start and the configuration keys it stands for.</summary>
public sealed record EnvironmentAlias(string Name, string Meaning, IReadOnlyList<string> Keys);

/// <summary>The outcome of reading the simple environment variables: the configuration values they stand for and the problems found.</summary>
public sealed record EnvironmentAliasResult(IReadOnlyList<KeyValuePair<string, string?>> Values, IReadOnlyList<string> Errors);

/// <summary>
/// The small set of simple environment variables that start EggMail with very little configuration (<c>EGGMAIL_HOSTNAME</c>, <c>EGGMAIL_ADMIN_PASSWORD</c>, ...).
/// They are documented aliases for configuration keys, not a second configuration system: <see cref="Translate"/> turns them into the keys the loader
/// already reads, and <see cref="ConfigLoader.Build"/> adds those values just above the files and just below the long-form environment variables
/// (<c>Hostname</c>, <c>Acme__Email</c>, ...) and the command line, so anything set the long way always wins. A combination that cannot work is an
/// error that names the variable and says what to set instead (the server then refuses to start rather than start in a state nobody asked for).
/// </summary>
public static partial class EnvironmentAliases
{
    /// <summary>The variables, documented in docs/operations.md ("The simple environment variables"); a test keeps that table and this list identical.</summary>
    public static IReadOnlyList<EnvironmentAlias> Aliases { get; } =
    [
        new("EGGMAIL_HOSTNAME", "Name of this server in SMTP greetings (HELO/EHLO) and message ids, in the first-run certificate and the ACME certificate (the dashboard serves the same certificate)", ["Hostname", "Acme:Domains"]),
        new("EGGMAIL_ACME_EMAIL", "Contact for the ACME account; with EGGMAIL_HOSTNAME it turns ACME on", ["Acme:Enabled", "Acme:Email", "Acme:Domains"]),
        new("EGGMAIL_ACME_STAGING", "true: order from the Let's Encrypt staging CA (certificates are not trusted by clients); use while testing", ["Acme:Directory"]),
        new("EGGMAIL_ACME_DIRECTORY", "ACME directory URL (or a name such as ZeroSsl) of any other CA", ["Acme:Directory"]),
        new("CLOUDFLARE_API_TOKEN", "Cloudflare API token with DNS edit rights; selects the DNS-01 challenge (wildcard names, no inbound port 80)", ["Acme:CloudflareApiToken", "Acme:Challenge"]),
        new("CLOUDFLARE_API_TOKEN_FILE", "The same token read from a file (a mounted secret)", ["Acme:CloudflareApiTokenFile", "Acme:Challenge"]),
        new("EGGMAIL_ADMIN_USER", "User name of the first dashboard administrator (default admin)", ["Dashboard:BootstrapAdminUser"]),
        new("EGGMAIL_ADMIN_PASSWORD", "Password of the first dashboard administrator; without it (and without the file form) the server generates one and prints it once", ["Dashboard:BootstrapAdminPassword"]),
        new("EGGMAIL_ADMIN_PASSWORD_FILE", "The same password read from a file (a mounted secret); preferred to the plain form", ["Dashboard:BootstrapAdminPasswordFile"]),
        new("EGGMAIL_DOMAINS", "Sending domains to register at start, separated by commas", ["Domains:Bootstrap"]),
        new("EGGMAIL_DATABASE", "PostgreSQL connection string (Npgsql form or a postgres:// URL): one variable switches from SQLite to PostgreSQL", ["Storage:Backend", "Storage:Postgres:RuntimeConnectionString"]),
        new("EGGMAIL_RELAY", "host:port of a smarthost used when direct delivery fails (optional)", ["Delivery:Relay:Address"]),
        new("EGGMAIL_RELAY_USER", "Login on that relay", ["Delivery:Relay:User"]),
        new("EGGMAIL_RELAY_PASSWORD", "Password on that relay", ["Delivery:Relay:Password"]),
        new("EGGMAIL_RELAY_PASSWORD_FILE", "The same password read from a file (a mounted secret)", ["Delivery:Relay:PasswordFile"]),
    ];

    /// <summary>Reads the variables through <paramref name="get"/> (the process environment in production) and returns the configuration they stand for.</summary>
    public static EnvironmentAliasResult Translate(Func<string, string?> get)
    {
        var values = new List<KeyValuePair<string, string?>>();
        var errors = new List<string>();
        string? Read(string name) => get(name) is { } v && !string.IsNullOrWhiteSpace(v) ? v.Trim() : null;
        void Set(string key, string? value) => values.Add(new KeyValuePair<string, string?>(key, value));

        string? hostname = Read("EGGMAIL_HOSTNAME");
        string? acmeEmail = Read("EGGMAIL_ACME_EMAIL");
        string? staging = Read("EGGMAIL_ACME_STAGING");
        string? directory = Read("EGGMAIL_ACME_DIRECTORY");
        string? cloudflareToken = Read("CLOUDFLARE_API_TOKEN");
        string? cloudflareTokenFile = Read("CLOUDFLARE_API_TOKEN_FILE");

        if (hostname is not null)
        {
            if (NormalizeHostname(hostname) is { } normalized)
            {
                hostname = normalized;
                Set("Hostname", hostname);
            }
            else
            {
                errors.Add("EGGMAIL_HOSTNAME is not a host name. Use the DNS name of this server, for example mail.example.com (no http://, no port, no IP address).");
                hostname = null;
            }
        }

        if (acmeEmail is not null)
        {
            if (!IsEmailAddress(acmeEmail))
            {
                errors.Add("EGGMAIL_ACME_EMAIL is not an email address. Use the contact address for the certificate account, for example admin@example.com.");
            }
            else if (Read("EGGMAIL_HOSTNAME") is null)
            {
                errors.Add("EGGMAIL_ACME_EMAIL needs EGGMAIL_HOSTNAME: the certificate is ordered for that name. Set both (EGGMAIL_HOSTNAME=mail.example.com), or remove EGGMAIL_ACME_EMAIL to keep the self-signed certificate.");
            }
            else if (hostname is not null)
            {
                if (!hostname.Contains('.', StringComparison.Ordinal))
                {
                    errors.Add("EGGMAIL_HOSTNAME has no dot: a certificate authority only issues for a fully qualified name such as mail.example.com.");
                }
                else
                {
                    Set("Acme:Enabled", "true");
                    Set("Acme:Email", acmeEmail);
                    Set("Acme:Domains:0", hostname);
                }
            }
        }

        bool useStaging = false;
        if (staging is not null && !bool.TryParse(staging, out useStaging))
        {
            errors.Add("EGGMAIL_ACME_STAGING must be true or false.");
        }

        if (useStaging && directory is not null)
        {
            errors.Add("EGGMAIL_ACME_STAGING=true and EGGMAIL_ACME_DIRECTORY name two different CAs. Set only one of them.");
        }
        else if (useStaging)
        {
            Set("Acme:Directory", "LetsEncryptStaging");   // the key that wins over Acme:DirectoryUrl: a mounted file that sets either cannot override the alias silently
        }
        else if (directory is not null)
        {
            if (AcmeSection.ResolveDirectory(directory) is null)
            {
                errors.Add("EGGMAIL_ACME_DIRECTORY is neither an http(s) URL nor a known CA name (LetsEncrypt, LetsEncryptStaging, ZeroSsl). Use the directory URL of your CA, for example https://acme-v02.api.letsencrypt.org/directory.");
            }
            else
            {
                Set("Acme:Directory", directory);
            }
        }

        if (cloudflareToken is not null && cloudflareTokenFile is not null)
        {
            errors.Add("CLOUDFLARE_API_TOKEN and CLOUDFLARE_API_TOKEN_FILE are both set. Set only one.");
        }
        else if (cloudflareToken is not null || cloudflareTokenFile is not null)
        {
            Set(cloudflareToken is not null ? "Acme:CloudflareApiToken" : "Acme:CloudflareApiTokenFile", cloudflareToken ?? cloudflareTokenFile);
            Set("Acme:Challenge", "Dns01");
        }

        // The administrator variables are only mapped. Whether the user name and the password are usable matters when the first administrator is created
        // (FirstAdministrator), not for `--healthcheck` or `mta admin create`, which read the same environment.
        if (Read("EGGMAIL_ADMIN_USER") is { } adminUser)
        {
            Set("Dashboard:BootstrapAdminUser", adminUser);
        }

        if (Read("EGGMAIL_ADMIN_PASSWORD") is { } adminPassword)   // trimmed like the contents of the password file
        {
            Set("Dashboard:BootstrapAdminPassword", adminPassword);
        }

        if (Read("EGGMAIL_ADMIN_PASSWORD_FILE") is { } adminPasswordFile)
        {
            Set("Dashboard:BootstrapAdminPasswordFile", adminPasswordFile);
        }

        if (Read("EGGMAIL_DOMAINS") is { } domains)
        {
            string[] names = domains.Split([',', ';', ' ', '\t', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(d => d.TrimEnd('.').ToLowerInvariant()).Distinct().ToArray();
            int bad = Array.FindIndex(names, d => d.Contains("://", StringComparison.Ordinal) || d.Contains('@') || d.Contains('/') || d.Contains(':') || !d.Contains('.', StringComparison.Ordinal));
            if (names.Length == 0 || bad >= 0)
            {
                errors.Add("EGGMAIL_DOMAINS must list sending domains such as example.com, separated by commas (not addresses or URLs)" + (bad < 0 ? "." : $"; check entry {bad + 1}."));
            }
            else
            {
                for (int i = 0; i < names.Length; i++)
                {
                    Set($"Domains:Bootstrap:{i.ToString(CultureInfo.InvariantCulture)}", names[i]);
                }
            }
        }

        if (Read("EGGMAIL_DATABASE") is { } database)
        {
            if (NormalizeDatabase(database, out string connection) is { } problem)
            {
                errors.Add("EGGMAIL_DATABASE: " + problem);
            }
            else
            {
                Set("Storage:Backend", "Postgres");
                Set("Storage:Postgres:RuntimeConnectionString", connection);
            }
        }

        string? relay = Read("EGGMAIL_RELAY");
        string? relayUser = Read("EGGMAIL_RELAY_USER");
        string? relayPassword = Read("EGGMAIL_RELAY_PASSWORD");
        string? relayPasswordFile = Read("EGGMAIL_RELAY_PASSWORD_FILE");
        if (relay is null)
        {
            if (relayUser is not null || relayPassword is not null || relayPasswordFile is not null)
            {
                errors.Add("EGGMAIL_RELAY_USER / EGGMAIL_RELAY_PASSWORD(_FILE) are set without EGGMAIL_RELAY. Set EGGMAIL_RELAY=host:port, or remove the login variables.");
            }
        }
        else
        {
            if (RelayProblem(relay) is { } problem)
            {
                errors.Add("EGGMAIL_RELAY: " + problem);
            }
            else
            {
                Set("Delivery:Relay:Address", relay);
            }

            if (relayPassword is not null && relayPasswordFile is not null)
            {
                errors.Add("EGGMAIL_RELAY_PASSWORD and EGGMAIL_RELAY_PASSWORD_FILE are both set. Set only one.");
            }
            else if ((relayPassword is not null || relayPasswordFile is not null) && relayUser is null)
            {
                errors.Add("EGGMAIL_RELAY_PASSWORD(_FILE) needs EGGMAIL_RELAY_USER (the login the password belongs to).");
            }
            else if (relayUser is not null && relayPassword is null && relayPasswordFile is null)
            {
                errors.Add("EGGMAIL_RELAY_USER needs EGGMAIL_RELAY_PASSWORD or EGGMAIL_RELAY_PASSWORD_FILE.");
            }
            else if (relayUser is not null)
            {
                Set("Delivery:Relay:User", relayUser);
                Set(relayPassword is not null ? "Delivery:Relay:Password" : "Delivery:Relay:PasswordFile", relayPassword ?? relayPasswordFile);
            }
        }

        return new EnvironmentAliasResult(values, errors);
    }

    /// <summary>The variables of the process environment.</summary>
    public static EnvironmentAliasResult TranslateProcessEnvironment() => Translate(Environment.GetEnvironmentVariable);

    /// <summary>Lower case, no trailing dot, letters/digits/dash/underscore labels (an internationalized name is converted to its ASCII form); null when it cannot be a host name.</summary>
    public static string? NormalizeHostname(string value)
    {
        string name = value.Trim().TrimEnd('.').ToLowerInvariant();
        if (name.Length == 0 || name.Any(char.IsWhiteSpace) || name.Contains("://", StringComparison.Ordinal) || name.Contains('/') || name.Contains(':') || name.Contains('@'))
        {
            return null;
        }

        if (name.Any(c => c > 127))
        {
            try
            {
                name = new IdnMapping().GetAscii(name);
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        // An address is not a name: "1.2.3.4" would be a greeting nobody can match to a PTR record.
        if (IPAddress.TryParse(name, out _) || name.Length > 253 || !HostnamePattern().IsMatch(name))
        {
            return null;
        }

        return name;
    }

    [GeneratedRegex("^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")]
    private static partial Regex HostnamePattern();

    private static bool IsEmailAddress(string value)
    {
        int at = value.IndexOf('@', StringComparison.Ordinal);
        return at > 0 && at == value.LastIndexOf('@') && at < value.Length - 1 && !value.Any(char.IsWhiteSpace) && value[(at + 1)..].Contains('.', StringComparison.Ordinal);
    }

    /// <summary>Why a value is not <c>host:port</c> of a relay, or null. The text never repeats the value: it may carry a login (<c>user:password@host:587</c>).</summary>
    public static string? RelayProblem(string value)
    {
        int colon = value.LastIndexOf(':');
        if (colon <= 0 || colon == value.Length - 1 || !int.TryParse(value[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out int port) || port is < 1 or > 65535)
        {
            return "not host:port. Use for example smtp.relay.example:587 (the login goes in EGGMAIL_RELAY_USER and EGGMAIL_RELAY_PASSWORD_FILE, not in this value).";
        }

        string host = value[..colon];
        if (NormalizeHostname(host) is not { } name || name.Split('.')[^1].All(char.IsAsciiDigit))
        {
            return "the host is not a host name. Use a name such as smtp.relay.example, not an IP address or a URL (a login goes in EGGMAIL_RELAY_USER and EGGMAIL_RELAY_PASSWORD_FILE): the name is looked up in DNS and its certificate is checked.";
        }

        return null;
    }

    /// <summary>
    /// Accepts an Npgsql connection string or a <c>postgres://user:password@host:port/database?sslmode=require</c> URL and returns the Npgsql form in
    /// <paramref name="connectionString"/>. Returns the problem (and an empty string) when it cannot work. A problem text never repeats the value or the
    /// parser's own message (both can contain the password): it says which part is wrong.
    /// </summary>
    public static string? NormalizeDatabase(string value, out string connectionString)
    {
        const string Form = " Use Host=db.example.com;Database=eggmail;Username=eggmail;Password=... or postgres://user:password@db.example.com/eggmail (percent-encode special characters in the password of a URL).";
        connectionString = "";
        try
        {
            NpgsqlConnectionStringBuilder builder;
            if (value.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase) || value.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase))
            {
                if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri) || string.IsNullOrEmpty(uri.Host))
                {
                    return "the URL is not valid." + Form;
                }

                builder = new NpgsqlConnectionStringBuilder { Host = uri.Host.Trim('[', ']'), Port = uri.Port > 0 ? uri.Port : 5432 };
                if (uri.UserInfo.Length > 0)
                {
                    int colon = uri.UserInfo.IndexOf(':', StringComparison.Ordinal);
                    builder.Username = Uri.UnescapeDataString(colon < 0 ? uri.UserInfo : uri.UserInfo[..colon]);
                    if (colon >= 0)
                    {
                        builder.Password = Uri.UnescapeDataString(uri.UserInfo[(colon + 1)..]);
                    }
                }

                string database = Uri.UnescapeDataString(uri.AbsolutePath.Trim('/'));
                if (database.Length > 0)
                {
                    builder.Database = database;
                }

                foreach (string pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    int eq = pair.IndexOf('=', StringComparison.Ordinal);
                    string key = Uri.UnescapeDataString(eq < 0 ? pair : pair[..eq]);
                    string val = eq < 0 ? "" : Uri.UnescapeDataString(pair[(eq + 1)..]);
                    if (!key.Equals("sslmode", StringComparison.OrdinalIgnoreCase))
                    {
                        return "the URL has a parameter other than sslmode, which a URL cannot carry. Use the Npgsql form (Host=...;Database=...;Username=...;Password=...) for other options.";
                    }

                    SslMode? mode = val.ToLowerInvariant() switch
                    {
                        "disable" => SslMode.Disable,
                        "prefer" => SslMode.Prefer,
                        "require" => SslMode.Require,
                        "verify-ca" => SslMode.VerifyCA,
                        "verify-full" => SslMode.VerifyFull,
                        _ => null,
                    };
                    if (mode is null)
                    {
                        return "sslmode is not one of disable, prefer, require, verify-ca, verify-full.";
                    }

                    builder.SslMode = mode.Value;
                }
            }
            else
            {
                builder = new NpgsqlConnectionStringBuilder(value);
            }

            if (string.IsNullOrWhiteSpace(builder.Host))
            {
                return "no host." + Form;
            }

            if (string.IsNullOrWhiteSpace(builder.Username))
            {
                return "no user. Add Username=... (or user:password@ in the URL).";
            }

            connectionString = builder.ConnectionString;
            return null;
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or UriFormatException or InvalidOperationException)
        {
            return "not a valid PostgreSQL connection string." + Form;
        }
    }
}

/// <summary>Configuration source of the simple environment variables; a distinct provider type so the backend switch can tell where a value came from.</summary>
public sealed class EnvironmentAliasesSource(EnvironmentAliasResult result) : IConfigurationSource
{
    public IConfigurationProvider Build(IConfigurationBuilder builder) => new EnvironmentAliasesProvider(new MemoryConfigurationSource { InitialData = result.Values }, result.Errors);
}

/// <summary>Provider of <see cref="EnvironmentAliasesSource"/>; carries the problems found while reading the variables so <see cref="ConfigLoader.Load"/> can report them.</summary>
public sealed class EnvironmentAliasesProvider(MemoryConfigurationSource source, IReadOnlyList<string> errors) : MemoryConfigurationProvider(source)
{
    public IReadOnlyList<string> Errors { get; } = errors;
}
