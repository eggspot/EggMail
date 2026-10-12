using System.Net;
using Mta.Dns;

namespace Mta.Auth.Tests;

/// <summary>Builds a <see cref="StaticDnsResolver"/> from one line per record: <c>name TYPE value</c>.</summary>
internal static class TestZone
{
    public static string Z(params string[] lines) => string.Join('\n', lines);

    public static StaticDnsResolver Build(string zone)
    {
        var resolver = new StaticDnsResolver();
        foreach (string raw in zone.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            string line = raw.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            string[] head = line.Split(' ', 3);
            string name = head[0];
            string type = head[1].ToUpperInvariant();
            string value = head.Length > 2 ? head[2] : string.Empty;
            switch (type)
            {
                case "TXT":
                    resolver.AddTxt(name, value);
                    break;
                case "A":
                    resolver.AddA(name, value);
                    break;
                case "AAAA":
                    resolver.AddAaaa(name, value);
                    break;
                case "MX":
                    {
                        string[] mx = value.Split(' ');
                        resolver.AddMx(name, ushort.Parse(mx[0]), mx[1]);
                        break;
                    }

                case "PTR":
                    resolver.Add(new PtrRecord(name.ToLowerInvariant(), 300, value));
                    break;
                case "CNAME":
                    resolver.Add(new CnameRecord(name.ToLowerInvariant(), 300, value));
                    break;
                case "EXISTS":
                    // The name exists but has no data of the queried types (NODATA instead of NXDOMAIN).
                    resolver.Add(new UnknownRecord(name.ToLowerInvariant(), 99, 300, []));
                    break;
                case "SERVFAIL":
                    resolver.Fail(name, Enum.Parse<DnsRecordType>(value, true), DnsRcode.ServerFailure);
                    break;
                case "REFUSED":
                    resolver.Fail(name, Enum.Parse<DnsRecordType>(value, true), DnsRcode.Refused);
                    break;
                default:
                    throw new ArgumentException("Unknown zone record type " + type);
            }
        }

        return resolver;
    }

    public static IPAddress Ip(string text) => IPAddress.Parse(text);
}
