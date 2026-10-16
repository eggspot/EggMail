using System.Net;
using System.Net.Sockets;

namespace Mta.RemoteMta.Tests.Harness;

/// <summary>A fact that is reported as skipped, with the reason, where the IPv6 loopback address cannot be used (some containers have no IPv6).</summary>
public sealed class Ipv6FactAttribute : FactAttribute
{
    public override string Skip
    {
        get => base.Skip ?? (Available(out string? reason) ? null! : reason!);
        set => base.Skip = value;
    }

    private static bool Available(out string? reason)
    {
        if (!Socket.OSSupportsIPv6)
        {
            reason = "this machine has no IPv6";
            return false;
        }

        try
        {
            using var probe = new TcpListener(IPAddress.IPv6Loopback, 0);
            probe.Start();
            reason = null;
            return true;
        }
        catch (SocketException ex)
        {
            reason = "the IPv6 loopback address cannot be used here: " + ex.SocketErrorCode;
            return false;
        }
    }
}
