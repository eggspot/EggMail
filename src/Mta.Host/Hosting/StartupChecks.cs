using Mta.Core;
using Mta.Host.Configuration;

namespace Mta.Host.Hosting;

/// <summary>Checks made before the storage opens, so the most common first-run mistakes end in one sentence that says what to do instead of a stack trace.</summary>
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

    /// <summary>The advice that applies to a start with little configuration: written to the log, never fatal.</summary>
    public static void LogAdvice(MtaConfig config, LoadedConfig loaded, IMtaLog log)
    {
        if (!loaded.LockedKeys.Contains("Hostname"))
        {
            log.Write(MtaLogLevel.Warning, "startup",
                $"No host name is configured: using the machine name '{config.Hostname}' in SMTP greetings and certificates. Set EGGMAIL_HOSTNAME to the DNS name of this server (for example mail.example.com), which also has to match the reverse DNS (PTR) of its public IP address, or receiving servers will score your mail down.");
        }

        if (!config.Acme.Enabled && config.Tls.CertificatePath is null)
        {
            log.Write(MtaLogLevel.Information, "startup", "No ACME configured: the certificate stays self-signed until you set EGGMAIL_HOSTNAME and EGGMAIL_ACME_EMAIL or upload one in the dashboard.");
        }
    }
}
