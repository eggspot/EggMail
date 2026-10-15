using Mta.Core;
using Mta.Host.Configuration;

namespace Mta.Host.Hosting;

/// <summary>Checks made before the storage opens, and the advice a start with little configuration logs, so the most common first-run mistakes end in one sentence that says what to do.</summary>
public static class StartupChecks
{
    /// <summary>
    /// Creates the SQLite data directory when it is missing and proves the process can write in it. Returns the problem to show, or null.
    /// The usual cause in a container is a bind-mounted host directory owned by root: the image runs as uid 1654, a named volume is prepared for it.
    /// </summary>
    public static string? DataDirectoryProblem(string directory)
    {
        string probe = Path.Combine(directory, ".eggmail-write-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllBytes(probe, [0]);
            File.Delete(probe);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"The data directory '{directory}' cannot be written by this process ({ex.Message}). " +
                "In Docker use a named volume (-v eggmail-data:/data), which is prepared for the container user; for a bind mount make the host directory writable by uid 1654 (chown 1654:1654 <directory>). " +
                "Elsewhere set Sqlite:DataDirectory to a directory the server may write.";
        }
    }

    /// <summary>
    /// Does anything name this server? "Not configured" is not "the key is absent": Docker and Kubernetes set the HOSTNAME variable (the container id or pod name), which is
    /// the key <c>Hostname</c> to the case-insensitive configuration, so the host name equal to the machine name or to HOSTNAME means nobody chose it.
    /// </summary>
    public static bool HostnameConfigured(MtaConfig config, Func<string, string?> environment) =>
        environment("EGGMAIL_HOSTNAME") is not null || environment("Hostname") is not null
        || !(string.Equals(config.Hostname, Environment.MachineName, StringComparison.OrdinalIgnoreCase)
            || string.Equals(config.Hostname, environment("HOSTNAME"), StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// <c>EGGMAIL_HOSTNAME</c> wins over a different <c>Hostname</c> from a file or the long-form environment (it has to, see <see cref="ConfigLoader.Build"/>); say so, so that
    /// nobody wonders why the file's value is ignored. Returns the sentence, or null when nothing is overridden. Only the command line is above the alias.
    /// </summary>
    public static string? HostnameOverrideNote(MtaConfig config, Microsoft.Extensions.Configuration.IConfiguration? source, Func<string, string?> environment)
    {
        if (environment("EGGMAIL_HOSTNAME") is null)
        {
            return null;
        }

        var others = new List<string?> { environment("Hostname") };
        if (source is Microsoft.Extensions.Configuration.IConfigurationRoot root)
        {
            foreach (Microsoft.Extensions.Configuration.IConfigurationProvider provider in root.Providers)
            {
                if (provider is not (EnvironmentAliasesProvider or Microsoft.Extensions.Configuration.EnvironmentVariables.EnvironmentVariablesConfigurationProvider or Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider)
                    && provider.TryGet("Hostname", out string? value))
                {
                    others.Add(value);
                }
            }
        }

        string? different = others.FirstOrDefault(o => !string.IsNullOrWhiteSpace(o) && !string.Equals(o.Trim().TrimEnd('.'), config.Hostname, StringComparison.OrdinalIgnoreCase));
        return different is null
            ? null
            : $"EGGMAIL_HOSTNAME ('{config.Hostname}') overrides the different Hostname ('{different}') set in a file or the environment. Remove one of them; only the command line (--Hostname=) is above EGGMAIL_HOSTNAME.";
    }

    /// <summary>What is wrong with a name used in HELO/EHLO and in certificates, as sentences; empty when it is fine. Receiving servers score these down or refuse them.</summary>
    public static IReadOnlyList<string> HeloNameWarnings(string name)
    {
        var warnings = new List<string>();
        if (name.Contains('_', StringComparison.Ordinal))
        {
            warnings.Add($"The host name '{name}' contains an underscore, which is not valid in a host name: many receiving servers reject or score down a HELO name like that.");
        }

        if (!name.Contains('.', StringComparison.Ordinal))
        {
            warnings.Add($"The host name '{name}' is a single label, not a fully qualified name: receiving servers expect a name such as mail.example.com that resolves in DNS and matches the reverse DNS (PTR) of this server's IP address.");
        }

        return warnings;
    }

    /// <summary>
    /// With the PostgreSQL backend selected but SQLite files from an earlier run in the data directory (and no bootstrap file, which a deliberate switch writes), the data in
    /// those files is not used. Returns the warning, or null.
    /// </summary>
    public static string? AbandonedSqliteDataWarning(MtaConfig config)
    {
        string directory = config.Storage.Sqlite.DataDirectory;
        if (config.Storage.Backend != Mta.Storage.StorageBackend.Postgres || !File.Exists(Path.Combine(directory, "config.db")) || File.Exists(Path.Combine(directory, ConfigLoader.BootstrapFileName)))
        {
            return null;
        }

        return $"PostgreSQL is selected (EGGMAIL_DATABASE / Storage:Backend) but '{directory}' holds the SQLite files of an earlier run: the tenants, domains, keys and queued mail in them are NOT used by this start and this server begins empty. " +
            "To move them, stop this server, start the previous SQLite configuration and use the dashboard's Storage switch, or `mta migrate-storage --to postgres` (docs/operations.md). To start fresh on purpose, ignore this warning.";
    }

    /// <summary>The advice that applies to a start with little configuration: written to the log, never fatal.</summary>
    public static void LogAdvice(MtaConfig config, IMtaLog log, Func<string, string?>? environment = null, Microsoft.Extensions.Configuration.IConfiguration? source = null)
    {
        environment ??= Environment.GetEnvironmentVariable;
        if (HostnameOverrideNote(config, source, environment) is { } overrideNote)
        {
            log.Write(MtaLogLevel.Warning, "startup", overrideNote);
        }

        if (!HostnameConfigured(config, environment))
        {
            log.Write(MtaLogLevel.Warning, "startup",
                $"No host name is configured: using the machine name '{config.Hostname}' in SMTP greetings and certificates. Set EGGMAIL_HOSTNAME to the DNS name of this server (for example mail.example.com), which also has to match the reverse DNS (PTR) of its public IP address, or receiving servers will score your mail down.");
        }
        else
        {
            foreach (string warning in HeloNameWarnings(config.Delivery.HeloName ?? config.Hostname))
            {
                log.Write(MtaLogLevel.Warning, "startup", warning);
            }
        }

        if (AbandonedSqliteDataWarning(config) is { } abandoned)
        {
            log.Write(MtaLogLevel.Warning, "startup", abandoned);
        }

        if (!config.Acme.Enabled && config.Tls.CertificatePath is null)
        {
            log.Write(MtaLogLevel.Information, "startup", "No ACME configured: the certificate stays self-signed until you set EGGMAIL_HOSTNAME and EGGMAIL_ACME_EMAIL or upload one in the dashboard.");
        }
    }
}
