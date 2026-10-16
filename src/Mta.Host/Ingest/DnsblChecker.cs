using System.Net;
using System.Net.Sockets;
using System.Text;
using Mta.Dns;

namespace Mta.Host.Ingest;

/// <summary>
/// The optional reputation hook (design section 11.5): looks the connecting address up in the configured DNS blocklists. Off when no zone is configured. A hit is an answer in <c>127.0.0.0/8</c>
/// that is not in <c>127.255.255.0/24</c>, the range the common lists use for "your resolver is blocked or over quota" (that is an error: never a hit). A failure or a timeout is an error and never
/// blocks. <b>Every query tells the list operator which addresses connect to this server</b>; EggMail ships no list and endorses none.
/// </summary>
public sealed class DnsblChecker
{
    public const int MaxZones = 8;

    private readonly IDnsResolver _dns;
    private readonly string[] _zones;
    private readonly TimeSpan _timeout;

    public DnsblChecker(IDnsResolver dns, IEnumerable<string> zones, TimeSpan timeout)
    {
        _dns = dns;
        _zones = zones.Select(z => z.Trim().Trim('.').ToLowerInvariant()).Where(z => z.Length > 0).Distinct().Take(MaxZones).ToArray();
        _timeout = timeout;
    }

    public bool Enabled => _zones.Length > 0;

    /// <summary>The zone that lists <paramref name="client"/> (the first in configured order), or null.</summary>
    public async ValueTask<string?> FindListingAsync(IPAddress client, CancellationToken cancellationToken)
    {
        if (!Enabled)
        {
            return null;
        }

        string reversed = ReversedAddress(NetworkKey.Normalize(client));
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        Task<bool?>[] lookups = _zones.Select(zone => LookupAsync(reversed + "." + zone, timeout.Token)).ToArray();
        try
        {
            await Task.WhenAll(lookups).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }

        string? listed = null;
        for (int i = 0; i < lookups.Length; i++)
        {
            bool? hit = lookups[i].IsCompletedSuccessfully ? lookups[i].Result : null;
            string result = hit switch { true => "hit", false => "miss", _ => "error" };
            InboundMetrics.Dnsbl.Add(1, new KeyValuePair<string, object?>("result", result));
            if (hit == true)
            {
                listed ??= _zones[i];
            }
        }

        return listed;
    }

    // true: listed; false: not listed; null: could not be told (a failure, a timeout, a "your resolver is blocked" answer).
    private async Task<bool?> LookupAsync(string name, CancellationToken ct)
    {
        try
        {
            DnsResponse response = await _dns.QueryAsync(name, DnsRecordType.A, ct).ConfigureAwait(false);
            if (response.Rcode == DnsRcode.NameError)
            {
                return false;
            }

            if (response.Rcode != DnsRcode.NoError)
            {
                return null;
            }

            bool listed = false, any = false;
            foreach (ARecord answer in response.Get<ARecord>())
            {
                any = true;
                byte[] b = answer.Address.GetAddressBytes();
                if (b[0] != 127 || (b[1] == 255 && b[2] == 255))
                {
                    return null;   // outside 127/8, or the 127.255.255.x range: an error answer
                }

                listed = true;
            }

            return any ? listed : false;
        }
        catch (Exception ex) when (ex is DnsException or OperationCanceledException or SocketException or IOException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>The address the way a list wants it in a query name: IPv4 as the reversed octets, IPv6 as the 32 nibbles of the full address reversed, lower-case hex, dot-separated, no zero compression.</summary>
    public static string ReversedAddress(IPAddress address)
    {
        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out int written);
        var sb = new StringBuilder(written == 4 ? 15 : 63);
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            for (int i = 3; i >= 0; i--)
            {
                sb.Append(bytes[i]);
                if (i > 0)
                {
                    sb.Append('.');
                }
            }

            return sb.ToString();
        }

        const string hex = "0123456789abcdef";
        for (int i = 15; i >= 0; i--)
        {
            sb.Append(hex[bytes[i] & 0xF]).Append('.').Append(hex[bytes[i] >> 4]);
            if (i > 0)
            {
                sb.Append('.');
            }
        }

        return sb.ToString();
    }
}
