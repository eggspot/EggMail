using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;

namespace Mta.Dns;

/// <summary>The resolver settings read from the operating system.</summary>
/// <param name="Servers">The nameservers, in order, on port 53.</param>
/// <param name="Timeout">The per-attempt timeout from <c>options timeout:N</c>, clamped to 1..30 s, or null if not configured.</param>
/// <param name="Attempts">The attempt count from <c>options attempts:N</c>, clamped to 1..5, or null if not configured.</param>
/// <param name="Source">Where the servers came from: a file path, "network-interfaces", or "fallback".</param>
public sealed record SystemDnsConfig(IReadOnlyList<IPEndPoint> Servers, TimeSpan? Timeout, int? Attempts, string Source);

/// <summary>Reads the machine's DNS client configuration: resolv.conf on Linux and macOS, network interface DNS addresses as a best-effort elsewhere.</summary>
public static class SystemDnsConfiguration
{
    public const string DefaultResolvConfPath = "/etc/resolv.conf";

    private const int DnsPort = 53;

    /// <summary>
    /// Parses resolv.conf text. Honors <c>nameserver</c> lines and <c>options timeout:N attempts:N</c>; everything
    /// else (<c>search</c>, <c>domain</c>, <c>ndots</c>, <c>sortlist</c>, ...) is ignored, because a mail server
    /// resolves fully qualified names only. Comment lines start with '#' or ';'. Unparsable lines are skipped.
    /// The result may have no servers.
    /// </summary>
    public static SystemDnsConfig ParseResolvConf(string text, string source = "resolv.conf")
    {
        ArgumentNullException.ThrowIfNull(text);
        var servers = new List<IPEndPoint>();
        TimeSpan? timeout = null;
        int? attempts = null;

        foreach (var rawLine in text.Split('\n'))
        {
            string line = rawLine;
            int comment = line.AsSpan().IndexOfAny('#', ';');
            if (comment >= 0)
            {
                line = line[..comment];
            }

            var tokens = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 2)
            {
                continue;
            }

            if (tokens[0] == "nameserver")
            {
                if (IPAddress.TryParse(tokens[1], out var address) && !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any))
                {
                    AddServer(servers, address);
                }

                continue;
            }

            if (tokens[0] == "options")
            {
                for (int i = 1; i < tokens.Length; i++)
                {
                    if (TryOption(tokens[i], "timeout:", out int seconds))
                    {
                        timeout = TimeSpan.FromSeconds(Math.Clamp(seconds, 1, 30));
                    }
                    else if (TryOption(tokens[i], "attempts:", out int count))
                    {
                        attempts = Math.Clamp(count, 1, 5);
                    }
                }
            }
        }

        return new SystemDnsConfig(servers, timeout, attempts, source);
    }

    /// <summary>Reads and parses a resolv.conf file. Returns null if the file is missing or unreadable.</summary>
    public static SystemDnsConfig? ReadResolvConf(string path = DefaultResolvConfPath)
    {
        try
        {
            return File.Exists(path) ? ParseResolvConf(File.ReadAllText(path), path) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Finds the resolvers to use: resolv.conf first; if it names none (or does not exist, as on Windows), the DNS
    /// addresses of the operational network interfaces; if still none, 127.0.0.1 (a local resolver such as Unbound)
    /// and, only when <paramref name="allowPublicFallback"/> is true, then 1.1.1.1 and 8.8.8.8.
    /// <paramref name="useNetworkInterfaces"/> can switch the interface step off (used by tests).
    /// </summary>
    public static SystemDnsConfig Discover(bool allowPublicFallback = false, string resolvConfPath = DefaultResolvConfPath, bool useNetworkInterfaces = true)
    {
        var fromFile = ReadResolvConf(resolvConfPath);
        if (fromFile is { Servers.Count: > 0 })
        {
            return fromFile;
        }

        var fromInterfaces = useNetworkInterfaces ? ReadNetworkInterfaces() : [];
        if (fromInterfaces.Count > 0)
        {
            return new SystemDnsConfig(fromInterfaces, fromFile?.Timeout, fromFile?.Attempts, "network-interfaces");
        }

        var fallback = new List<IPEndPoint> { new(IPAddress.Loopback, DnsPort) };
        if (allowPublicFallback)
        {
            fallback.Add(new IPEndPoint(IPAddress.Parse("1.1.1.1"), DnsPort));
            fallback.Add(new IPEndPoint(IPAddress.Parse("8.8.8.8"), DnsPort));
        }

        return new SystemDnsConfig(fallback, fromFile?.Timeout, fromFile?.Attempts, "fallback");
    }

    private static List<IPEndPoint> ReadNetworkInterfaces()
    {
        var servers = new List<IPEndPoint>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up
                    || nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                foreach (var address in nic.GetIPProperties().DnsAddresses)
                {
                    // fec0:0:0:ffff::1-3 are the long-deprecated site-local placeholders Windows lists for unconfigured IPv6.
                    if (address.IsIPv6SiteLocal || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
                    {
                        continue;
                    }

                    AddServer(servers, address);
                }
            }
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException or InvalidOperationException)
        {
            // Best effort only.
        }

        return servers;
    }

    private static void AddServer(List<IPEndPoint> servers, IPAddress address)
    {
        var endpoint = new IPEndPoint(address, DnsPort);
        if (!servers.Contains(endpoint))
        {
            servers.Add(endpoint);
        }
    }

    private static bool TryOption(string token, string prefix, out int value)
    {
        value = 0;
        return token.StartsWith(prefix, StringComparison.Ordinal)
            && int.TryParse(token.AsSpan(prefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }
}
