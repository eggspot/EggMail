using Mta.Core;
using System.Net;
using System.Net.Sockets;

namespace Mta.Dns;

/// <summary>The outcome of resolving the mail hosts for a domain.</summary>
public enum MxResolutionStatus
{
    /// <summary>At least one mail exchanger with at least one usable address was found.</summary>
    Ok,

    /// <summary>RFC 7505 null MX: the domain explicitly does not accept mail. Do not retry; the failure is permanent.</summary>
    NullMx,

    /// <summary>The domain exists but has no mail host: no MX records and no address records (or none of the MX hosts resolve to an address). Permanent.</summary>
    NoMailHost,

    /// <summary>A DNS lookup failed temporarily (timeout, SERVFAIL, malformed answer, no usable address after a temporary error). Retry later.</summary>
    TempFail,

    /// <summary>The domain does not exist (NXDOMAIN) or is not a valid DNS name. Permanent.</summary>
    NonExistentDomain,
}

/// <summary>Which address families to return and in which order.</summary>
public enum MxAddressPreference
{
    /// <summary>IPv4 addresses first, then IPv6 (default: conservative for sender reputation and SPF).</summary>
    Ipv4First,

    /// <summary>IPv6 addresses first, then IPv4.</summary>
    Ipv6First,

    /// <summary>Only IPv4 addresses.</summary>
    Ipv4Only,

    /// <summary>Only IPv6 addresses.</summary>
    Ipv6Only,
}

/// <summary>A mail exchanger: host name, MX preference (lower is tried first) and its addresses in connection order.</summary>
public sealed record MailExchanger(string Host, ushort Preference, IReadOnlyList<IPAddress> Addresses)
{
    /// <summary>True if the host name is an alias (CNAME). RFC 2181 §10.3 forbids this for MX targets, but it is common and tolerated.</summary>
    public bool ResolvedViaCname { get; init; }
}

/// <summary>The result of <see cref="MxResolver.ResolveAsync"/>.</summary>
public sealed record MxResolution(MxResolutionStatus Status, IReadOnlyList<MailExchanger> Exchangers)
{
    /// <summary>True when the domain had no MX record and its own A/AAAA addresses were used (RFC 5321 §5.1 implicit MX).</summary>
    public bool UsedImplicitMx { get; init; }

    /// <summary>A short human-readable reason for any status other than <see cref="MxResolutionStatus.Ok"/> (suitable for a DSN diagnostic).</summary>
    public string? Detail { get; init; }

    public bool IsOk => Status == MxResolutionStatus.Ok;

    /// <summary>
    /// The AD bit of the MX answer (only ever true when the resolver is configured to trust it, for example a local
    /// validating Unbound). DANE (RFC 7672) requires a secure MX RRset before TLSA records may be used.
    /// </summary>
    public bool MxAuthenticated { get; init; }
}

/// <summary>The result of <see cref="MxResolver.ResolveHostAsync"/>.</summary>
public sealed record HostAddresses(MxResolutionStatus Status, IReadOnlyList<IPAddress> Addresses)
{
    public bool ResolvedViaCname { get; init; }
}

/// <summary>Settings for <see cref="MxResolver"/>.</summary>
public sealed record MxResolverOptions
{
    /// <summary>At most this many MX records (after sorting by preference) are considered. Bounds the lookups a hostile zone can cause. Default 10.</summary>
    public int MaxMxHosts { get; init; } = 10;

    /// <summary>At most this many addresses are kept per mail host. Default 8.</summary>
    public int MaxAddressesPerHost { get; init; } = 8;

    public MxAddressPreference AddressPreference { get; init; } = MxAddressPreference.Ipv4First;

    /// <summary>Accept an MX host that is a CNAME alias (flagged via <see cref="MailExchanger.ResolvedViaCname"/>). Default true.</summary>
    public bool AllowCnameExchanger { get; init; } = true;

    /// <summary>
    /// Drop addresses that can never be a mail server on the public internet and would aim the SMTP client at
    /// the sender's own machine or a network-internal service: unspecified (0.0.0.0, ::), loopback, multicast, and
    /// IPv4 addresses from 224.0.0.0 up (multicast, reserved, broadcast). For the hosts a <em>recipient domain</em> names (its MX records, or its own address
    /// when it has none) the addresses of internal networks are dropped as well: private (10/8, 172.16/12, 192.168/16, fc00::/7), link-local (including the
    /// cloud metadata address 169.254.169.254), carrier-grade NAT and the IPv6 forms that embed them. Whoever controls a domain controls its MX records, and an
    /// MX that points into the sender's own network would make the SMTP client a way to reach internal mail servers. Host names the operator chose (relay
    /// routes, through <see cref="MxResolver.ResolveHostAsync"/>) may be internal: they are the operator's own. Default true.
    /// </summary>
    public bool ExcludeSpecialAddresses { get; init; } = true;
}

/// <summary>
/// Picks the hosts to deliver a message to, following RFC 5321 §5.1 and RFC 7505:
/// MX records sorted by preference (hosts of equal preference in random order), implicit MX
/// (the domain's own A/AAAA) when there is no MX record, and the null MX ("." exchange) meaning "no mail accepted".
/// Thread-safe if the supplied <see cref="Random"/> is (the default, <see cref="Random.Shared"/>, is).
/// </summary>
public sealed class MxResolver
{
    private readonly IDnsResolver _dns;
    private readonly MxResolverOptions _options;
    private readonly Random _random;

    public MxResolver(IDnsResolver dns, MxResolverOptions? options = null, Random? random = null)
    {
        ArgumentNullException.ThrowIfNull(dns);
        _dns = dns;
        _options = options ?? new MxResolverOptions();
        _random = random ?? Random.Shared;
        if (_options.MaxMxHosts < 1 || _options.MaxAddressesPerHost < 1)
        {
            throw new ArgumentException("MaxMxHosts and MaxAddressesPerHost must be at least 1.", nameof(options));
        }
    }

    /// <summary>Resolves the mail hosts for <paramref name="domain"/> (the part after '@'; IDNA is applied). Never throws for DNS failures; they become <see cref="MxResolutionStatus.TempFail"/>.</summary>
    public async Task<MxResolution> ResolveAsync(string domain, CancellationToken cancellationToken = default)
    {
        if (!DnsName.TryNormalize(domain, out var name) || name.Length == 0)
        {
            return Fail(MxResolutionStatus.NonExistentDomain, $"'{domain}' is not a valid domain name");
        }

        DnsResponse mx;
        try
        {
            mx = await _dns.QueryAsync(name, DnsRecordType.MX, cancellationToken).ConfigureAwait(false);
        }
        catch (DnsException ex)
        {
            return Fail(MxResolutionStatus.TempFail, $"MX lookup for {name} failed: {ex.Message}");
        }

        switch (mx.Rcode)
        {
            case DnsRcode.NameError:
                return Fail(MxResolutionStatus.NonExistentDomain, $"domain {name} does not exist");
            case DnsRcode.NoError:
                break;
            default:
                return Fail(MxResolutionStatus.TempFail, $"MX lookup for {name} returned {mx.Rcode}");
        }

        var records = mx.Get<MxRecord>().ToList();
        if (records.Count == 0)
        {
            return await ResolveImplicitMxAsync(name, cancellationToken).ConfigureAwait(false);
        }

        var real = records.Where(r => r.Exchange.Length != 0).ToList();
        if (real.Count == 0)
        {
            return Fail(MxResolutionStatus.NullMx, $"domain {name} publishes a null MX (RFC 7505) and does not accept mail");
        }

        var selected = SortByPreference(real).Take(_options.MaxMxHosts).ToList();
        var lookups = selected.Select(r => ResolveHostCoreAsync(r.Exchange, recipientControlled: true, cancellationToken)).ToList();
        var results = await Task.WhenAll(lookups).ConfigureAwait(false);

        var exchangers = new List<MailExchanger>(selected.Count);
        bool anyTemporary = false;
        for (int i = 0; i < selected.Count; i++)
        {
            var r = results[i];
            if (r.Status == MxResolutionStatus.Ok)
            {
                exchangers.Add(new MailExchanger(selected[i].Exchange, selected[i].Preference, r.Addresses) { ResolvedViaCname = r.ResolvedViaCname });
            }
            else if (r.Status == MxResolutionStatus.TempFail)
            {
                anyTemporary = true;
            }
        }

        if (exchangers.Count > 0)
        {
            return new MxResolution(MxResolutionStatus.Ok, exchangers) { MxAuthenticated = mx.AuthenticatedData };
        }

        return anyTemporary
            ? Fail(MxResolutionStatus.TempFail, $"no MX host of {name} could be resolved right now")
            : Fail(MxResolutionStatus.NoMailHost, $"none of the MX hosts of {name} has an address");
    }

    /// <summary>
    /// Resolves A and AAAA for one host name an operator chose (queried concurrently), applying the address filter, order and limit from the options.
    /// Internal-network addresses are kept (see <see cref="MxResolverOptions.ExcludeSpecialAddresses"/>); the hosts of recipient domains are resolved by <see cref="ResolveAsync"/>.
    /// </summary>
    public Task<HostAddresses> ResolveHostAsync(string host, CancellationToken cancellationToken = default) =>
        ResolveHostCoreAsync(host, recipientControlled: false, cancellationToken);

    private async Task<HostAddresses> ResolveHostCoreAsync(string host, bool recipientControlled, CancellationToken cancellationToken)
    {
        if (!DnsName.TryNormalize(host, out var name) || name.Length == 0)
        {
            return new HostAddresses(MxResolutionStatus.NonExistentDomain, []);
        }

        bool wantV4 = _options.AddressPreference != MxAddressPreference.Ipv6Only;
        bool wantV6 = _options.AddressPreference != MxAddressPreference.Ipv4Only;
        var v4Task = wantV4 ? QueryOrNullAsync(name, DnsRecordType.A, cancellationToken) : Task.FromResult<DnsResponse?>(null);
        var v6Task = wantV6 ? QueryOrNullAsync(name, DnsRecordType.AAAA, cancellationToken) : Task.FromResult<DnsResponse?>(null);
        var v4 = await v4Task.ConfigureAwait(false);
        var v6 = await v6Task.ConfigureAwait(false);

        var queried = new List<DnsResponse?>(2);
        if (wantV4)
        {
            queried.Add(v4);
        }

        if (wantV6)
        {
            queried.Add(v6);
        }

        bool viaCname = queried.Any(r => r is not null && r.Answers.OfType<CnameRecord>().Any());
        if (viaCname && !_options.AllowCnameExchanger)
        {
            return new HostAddresses(MxResolutionStatus.NoMailHost, []) { ResolvedViaCname = true };
        }

        var first = new List<IPAddress>();
        var second = new List<IPAddress>();
        bool temporary = false;
        bool nxDomain = true;
        foreach (var response in queried)
        {
            if (response is null || response.Rcode is not (DnsRcode.NoError or DnsRcode.NameError))
            {
                temporary = true;
                nxDomain = false;
                continue;
            }

            if (response.Rcode == DnsRcode.NoError)
            {
                nxDomain = false;
            }
        }

        bool v6First = _options.AddressPreference == MxAddressPreference.Ipv6First;
        var v4Target = v6First ? second : first;
        var v6Target = v6First ? first : second;
        CollectAddresses(v4, v4Target);
        CollectAddresses(v6, v6Target);

        var all = new List<IPAddress>(first.Count + second.Count);
        foreach (var address in first.Concat(second))
        {
            if (all.Count >= _options.MaxAddressesPerHost)
            {
                break;
            }

            if (!all.Contains(address) && !(_options.ExcludeSpecialAddresses && (IsSpecial(address) || (recipientControlled && NetworkAddresses.IsInternalNetwork(address)))))
            {
                all.Add(address);
            }
        }

        if (all.Count > 0)
        {
            return new HostAddresses(MxResolutionStatus.Ok, all) { ResolvedViaCname = viaCname };
        }

        if (temporary)
        {
            return new HostAddresses(MxResolutionStatus.TempFail, []) { ResolvedViaCname = viaCname };
        }

        return new HostAddresses(nxDomain ? MxResolutionStatus.NonExistentDomain : MxResolutionStatus.NoMailHost, []) { ResolvedViaCname = viaCname };
    }

    private async Task<MxResolution> ResolveImplicitMxAsync(string name, CancellationToken cancellationToken)
    {
        var host = await ResolveHostCoreAsync(name, recipientControlled: true, cancellationToken).ConfigureAwait(false);
        return host.Status switch
        {
            MxResolutionStatus.Ok => new MxResolution(MxResolutionStatus.Ok, [new MailExchanger(name, 0, host.Addresses) { ResolvedViaCname = host.ResolvedViaCname }]) { UsedImplicitMx = true },
            MxResolutionStatus.TempFail => Fail(MxResolutionStatus.TempFail, $"address lookup for {name} (implicit MX) failed temporarily"),
            _ => Fail(MxResolutionStatus.NoMailHost, $"domain {name} has no MX record and no usable address record"),
        };
    }

    private IEnumerable<MxRecord> SortByPreference(List<MxRecord> records)
    {
        foreach (var group in records.GroupBy(r => r.Preference).OrderBy(g => g.Key))
        {
            var members = group.ToList();
            // Fisher-Yates: equal-preference hosts in random order spreads load (RFC 5321 §5.1).
            for (int i = members.Count - 1; i > 0; i--)
            {
                int j = _random.Next(i + 1);
                (members[i], members[j]) = (members[j], members[i]);
            }

            foreach (var member in members)
            {
                yield return member;
            }
        }
    }

    private async Task<DnsResponse?> QueryOrNullAsync(string name, DnsRecordType type, CancellationToken cancellationToken)
    {
        try
        {
            return await _dns.QueryAsync(name, type, cancellationToken).ConfigureAwait(false);
        }
        catch (DnsException)
        {
            return null;
        }
    }

    private static void CollectAddresses(DnsResponse? response, List<IPAddress> target)
    {
        if (response is not { Rcode: DnsRcode.NoError })
        {
            return;
        }

        foreach (var record in response.Answers)
        {
            switch (record)
            {
                case ARecord a:
                    target.Add(a.Address);
                    break;
                case AaaaRecord aaaa:
                    target.Add(aaaa.Address);
                    break;
            }
        }
    }

    /// <summary>True for loopback, unspecified, broadcast, multicast and reserved addresses: the ones <see cref="MxResolverOptions.ExcludeSpecialAddresses"/> leaves out.</summary>
    public static bool IsSpecialAddress(IPAddress address) => IsSpecial(address);

    private static bool IsSpecial(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return address.GetAddressBytes()[0] >= 224; // multicast 224/4 and reserved 240/4
        }

        return address.IsIPv6Multicast;
    }

    private static MxResolution Fail(MxResolutionStatus status, string detail) => new(status, []) { Detail = detail };
}
