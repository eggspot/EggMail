using System.Net;
using Mta.Auth.Domains;
using Mta.Auth.Spf;
using Mta.Dkim;
using Mta.Dns;
using Mta.Policy;

namespace Mta.Host.Domains;

/// <summary>Outcome of one verification pass over a domain's records.</summary>
public sealed record DomainCheckResult(IReadOnlyList<DomainRecordCheck> Records, VerificationCheckResult Result, string? Error);

/// <summary>
/// Looks the planned records up in DNS. Only required records decide the result; a DNS failure (timeout, SERVFAIL) is reported as
/// <see cref="VerificationCheckResult.DnsTemporaryFailure"/> so a resolver outage never marks a domain as broken.
/// <para>Per record the status says: <c>Ok</c> (found as expected), <c>Missing</c> (nothing of that kind at the name), <c>Invalid</c> (a record of that kind
/// exists but is malformed, or there are several where one is allowed) or <c>Mismatch</c> (a well-formed record with another value than expected). The text
/// DNS returned is kept as <see cref="DomainRecordCheck.Found"/> next to the expected value.</para>
/// </summary>
public sealed class DomainChecker
{
    /// <summary>Lookups of one check that run at the same time.</summary>
    public const int MaxParallelRecords = 4;

    private readonly IDnsResolver _dns;
    private readonly TimeSpan _recordTimeout;

    /// <param name="dns">The resolver.</param>
    /// <param name="recordTimeout">The longest one record may take (all its lookups together); a record that takes longer is <c>Pending</c> like a DNS failure. Default 20 seconds.</param>
    public DomainChecker(IDnsResolver dns, TimeSpan? recordTimeout = null)
    {
        _dns = dns ?? throw new ArgumentNullException(nameof(dns));
        _recordTimeout = recordTimeout ?? TimeSpan.FromSeconds(20);
    }

    public async Task<DomainCheckResult> CheckAsync(IReadOnlyList<ExpectedDomainRecord> expected, CancellationToken cancellationToken)
    {
        var checks = new DomainRecordCheck[expected.Count];
        var dnsFailed = new bool[expected.Count];
        using var gate = new SemaphoreSlim(MaxParallelRecords);
        await Task.WhenAll(expected.Select(async (record, i) =>
        {
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                limit.CancelAfter(_recordTimeout);
                try
                {
                    checks[i] = await CheckOneAsync(record, limit.Token).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is DnsException || ex is OperationCanceledException && !cancellationToken.IsCancellationRequested)
                {
                    checks[i] = new DomainRecordCheck(record, DomainRecordStatus.Pending, null);
                    dnsFailed[i] = record.Required;
                }
            }
            finally
            {
                gate.Release();
            }
        })).ConfigureAwait(false);

        string? firstProblem = null;
        for (int i = 0; i < checks.Length; i++)
        {
            ExpectedDomainRecord record = expected[i];
            if (record.Required && checks[i].Status is DomainRecordStatus.Missing or DomainRecordStatus.Invalid or DomainRecordStatus.Mismatch)
            {
                firstProblem ??= $"{record.Purpose} record {record.Host} " + checks[i].Status switch
                {
                    DomainRecordStatus.Missing => "is missing",
                    DomainRecordStatus.Invalid => "is invalid",
                    _ => "does not have the expected value",
                };
            }
        }

        // A definite problem outranks a temporary DNS failure on another record: the domain is not verifiable right now either way.
        if (firstProblem is not null)
        {
            return new DomainCheckResult(checks, VerificationCheckResult.RecordsNotOk, firstProblem);
        }

        return dnsFailed.Any(f => f)
            ? new DomainCheckResult(checks, VerificationCheckResult.DnsTemporaryFailure, "DNS lookup failed")
            : new DomainCheckResult(checks, VerificationCheckResult.AllRecordsOk, null);
    }

    private Task<DomainRecordCheck> CheckOneAsync(ExpectedDomainRecord record, CancellationToken ct) => record.Purpose switch
    {
        DomainRecordPurpose.Dkim => CheckDkimAsync(record, ct),
        DomainRecordPurpose.ReturnPath => CheckCnameAsync(record, ct),
        DomainRecordPurpose.Spf => CheckSpfAsync(record, ct),
        DomainRecordPurpose.Dmarc => CheckDmarcAsync(record, ct),
        DomainRecordPurpose.TlsRpt => CheckTlsRptAsync(record, ct),
        DomainRecordPurpose.MtaSts => CheckMtaStsAsync(record, ct),
        DomainRecordPurpose.MtaStsHost => CheckMtaStsHostAsync(record, ct),
        DomainRecordPurpose.BounceMx => CheckMxAsync(record, ct),
        _ => CheckPtrAsync(record, ct),
    };

    private async Task<DomainRecordCheck> CheckDkimAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        var texts = await GetTxtAsync(record.Host, ct).ConfigureAwait(false);
        if (texts.Count == 0)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        DkimKeyTools.TryParseDnsTxtValue(record.Value, out var wanted, out _);
        string? otherKey = null;
        foreach (string text in texts)
        {
            if (DkimKeyRecord.TryParse(text, out var parsed, out _))
            {
                if (wanted is not null && parsed!.PublicKeySubjectPublicKeyInfo.AsSpan().SequenceEqual(wanted.PublicKeySubjectPublicKeyInfo))
                {
                    return new DomainRecordCheck(record, DomainRecordStatus.Ok, text);
                }

                otherKey ??= text;
            }
        }

        // A readable key that is not ours is a mismatch; text that is not a DKIM key at all is invalid.
        return otherKey is not null
            ? new DomainRecordCheck(record, DomainRecordStatus.Mismatch, otherKey)
            : new DomainRecordCheck(record, DomainRecordStatus.Invalid, texts[0]);
    }

    private async Task<DomainRecordCheck> CheckCnameAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        var chain = await GetCnameChainAsync(record.Host, ct).ConfigureAwait(false);
        if (chain.Count == 0)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        // The expected target may be reached through other names (the customer's DNS provider aliasing it): any link of the chain counts.
        return new DomainRecordCheck(record, chain.Contains(DomainRecordPlanner.Normalize(record.Value)) ? DomainRecordStatus.Ok : DomainRecordStatus.Mismatch, string.Join(" -> ", chain));
    }

    /// <summary>The names a CNAME chain leads through, starting at the target of <paramref name="host"/> (empty when there is no CNAME); at most 8 links.</summary>
    private async Task<List<string>> GetCnameChainAsync(string host, CancellationToken ct)
    {
        var chain = new List<string>();
        string current = host;
        for (int i = 0; i < 8; i++)
        {
            string? target = await GetCnameTargetAsync(current, ct).ConfigureAwait(false);
            if (target is null || chain.Contains(target))
            {
                break;
            }

            chain.Add(target);
            current = target;
        }

        return chain;
    }

    private async Task<string?> GetCnameTargetAsync(string host, CancellationToken ct)
    {
        var response = await _dns.QueryAsync(host, DnsRecordType.CNAME, ct).ConfigureAwait(false);
        ThrowIfServerFailure(response);
        string name = DomainRecordPlanner.Normalize(host);
        var cname = response.Get<CnameRecord>().FirstOrDefault(c => DomainRecordPlanner.Normalize(c.Name) == name);
        return cname is null ? null : DomainRecordPlanner.Normalize(cname.Target);
    }

    /// <summary>
    /// SPF (advice): exactly one <c>v=spf1</c> record must exist (two are a permanent error for receivers). It must authorize this server: when the expected value names
    /// addresses (<c>ip4:</c>, <c>ip6:</c>, or <c>a:</c> of our host name) the record is evaluated as RFC 7208 does for each of them (CIDR ranges, <c>include:</c>,
    /// <c>mx</c> and the rest count); when it only names an <c>include:</c> host, that mechanism must be in the record. Anything else in it is the customer's to keep.
    /// </summary>
    private async Task<DomainRecordCheck> CheckSpfAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        var records = (await GetTxtAsync(record.Host, ct).ConfigureAwait(false)).Where(t => HasVersion(t, "v=spf1")).ToList();
        if (records.Count == 0)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        if (records.Count > 1)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Invalid, string.Join(" | ", records));
        }

        var wanted = SpfTokens(record.Value).Where(t => !IsAllMechanism(t)).ToList();
        var addresses = new List<IPAddress>();
        foreach (string token in wanted)
        {
            string body = token.TrimStart('+');
            if ((body.StartsWith("ip4:", StringComparison.Ordinal) || body.StartsWith("ip6:", StringComparison.Ordinal)) && IPAddress.TryParse(body[4..].Split('/')[0], out IPAddress? ip))
            {
                addresses.Add(ip);
            }
            else if (body.StartsWith("a:", StringComparison.Ordinal))
            {
                addresses.AddRange((await GetAddressesAsync(body[2..], ct).ConfigureAwait(false)).Select(IPAddress.Parse));
            }
        }

        bool authorized;
        if (addresses.Count > 0)
        {
            var spf = new SpfEvaluator(_dns);
            authorized = true;
            foreach (IPAddress ip in addresses)
            {
                SpfCheckResult result = await spf.CheckHostAsync(new SpfCheckRequest(ip, record.Host, "postmaster@" + record.Host, record.Host), ct).ConfigureAwait(false);
                if (result.Result == SpfResult.TempError)
                {
                    throw new DnsException("SPF evaluation did not finish: " + result.Reason);
                }

                authorized &= result.Result == SpfResult.Pass;
            }
        }
        else
        {
            var found = SpfTokens(records[0]);
            authorized = wanted.All(found.Contains);
        }

        return new DomainRecordCheck(record, authorized ? DomainRecordStatus.Ok : DomainRecordStatus.Mismatch, records[0]);
    }

    /// <summary>
    /// DMARC: one record with a valid policy. The policy and report address are the customer's to choose, so a different one is not a mismatch. A subdomain without
    /// a record of its own inherits the one of its organizational domain (RFC 7489 section 6.6.3), which counts.
    /// </summary>
    private async Task<DomainRecordCheck> CheckDmarcAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        var records = (await GetTxtAsync(record.Host, ct).ConfigureAwait(false)).Where(t => HasVersion(t, "v=DMARC1")).ToList();
        string prefix = "";
        string name = record.Host.StartsWith("_dmarc.", StringComparison.Ordinal) ? record.Host["_dmarc.".Length..] : record.Host;
        if (records.Count == 0)
        {
            string organizational = PublicSuffixList.Default.GetOrganizationalDomain(name);
            if (organizational != name)
            {
                string parentHost = "_dmarc." + organizational;
                records = (await GetTxtAsync(parentHost, ct).ConfigureAwait(false)).Where(t => HasVersion(t, "v=DMARC1")).ToList();
                prefix = $"inherited from {parentHost}: ";
            }
        }

        if (records.Count == 0)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        bool valid = records.Count == 1 && Tag(records[0], "p")?.ToLowerInvariant() is "none" or "quarantine" or "reject";
        return new DomainRecordCheck(record, valid ? DomainRecordStatus.Ok : DomainRecordStatus.Invalid, prefix + string.Join(" | ", records));
    }

    /// <summary>TLS-RPT: one <c>v=TLSRPTv1</c> record with a <c>rua</c> destination.</summary>
    private async Task<DomainRecordCheck> CheckTlsRptAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        var records = (await GetTxtAsync(record.Host, ct).ConfigureAwait(false)).Where(t => HasVersion(t, "v=TLSRPTv1")).ToList();
        if (records.Count == 0)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        bool valid = records.Count == 1 && Tag(records[0], "rua") is { Length: > 0 } rua
            && rua.Split(',').All(u => u.Trim().StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) || u.Trim().StartsWith("https://", StringComparison.OrdinalIgnoreCase));
        return new DomainRecordCheck(record, valid ? DomainRecordStatus.Ok : DomainRecordStatus.Invalid, string.Join(" | ", records));
    }

    /// <summary>MTA-STS TXT: one <c>v=STSv1</c> record whose id is the one of the policy EggMail serves (an older id makes senders keep the cached policy).</summary>
    private async Task<DomainRecordCheck> CheckMtaStsAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        var records = (await GetTxtAsync(record.Host, ct).ConfigureAwait(false)).Where(t => HasVersion(t, "v=STSv1")).ToList();
        if (records.Count == 0)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        string? id = records.Count == 1 ? Tag(records[0], "id") : null;
        if (id is not { Length: > 0 and <= 32 } || !id.All(char.IsAsciiLetterOrDigit))
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Invalid, string.Join(" | ", records));
        }

        return new DomainRecordCheck(record, string.Equals(id, Tag(record.Value, "id"), StringComparison.Ordinal) ? DomainRecordStatus.Ok : DomainRecordStatus.Mismatch, records[0]);
    }

    /// <summary>The MTA-STS web name: a CNAME (chain) to this server's host name, or to a name with the same addresses, or A/AAAA records that are the host name's own addresses.</summary>
    private async Task<DomainRecordCheck> CheckMtaStsHostAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        var chain = await GetCnameChainAsync(record.Host, ct).ConfigureAwait(false);
        if (chain.Count > 0)
        {
            string found = string.Join(" -> ", chain);
            if (chain.Contains(DomainRecordPlanner.Normalize(record.Value)))
            {
                return new DomainRecordCheck(record, DomainRecordStatus.Ok, found);
            }

            // Another name for the same server (an alias of the host name) is fine when it leads to the same addresses.
            var viaTarget = await GetAddressesAsync(chain[^1], ct).ConfigureAwait(false);
            var server = await GetAddressesAsync(record.Value, ct).ConfigureAwait(false);
            return new DomainRecordCheck(record, viaTarget.Overlaps(server) ? DomainRecordStatus.Ok : DomainRecordStatus.Mismatch, found);
        }

        var own = await GetAddressesAsync(record.Host, ct).ConfigureAwait(false);
        if (own.Count == 0)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        var serverAddresses = await GetAddressesAsync(record.Value, ct).ConfigureAwait(false);
        return new DomainRecordCheck(record, own.Overlaps(serverAddresses) ? DomainRecordStatus.Ok : DomainRecordStatus.Mismatch, string.Join(", ", own.Order(StringComparer.Ordinal)));
    }

    /// <summary>The bounce domain's MX: must name this server (the preference is the operator's to choose).</summary>
    private async Task<DomainRecordCheck> CheckMxAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        var response = await _dns.QueryAsync(record.Host, DnsRecordType.MX, ct).ConfigureAwait(false);
        ThrowIfServerFailure(response);
        var mx = response.Get<MxRecord>().OrderBy(m => m.Preference).ToList();
        if (mx.Count == 0)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        string wanted = DomainRecordPlanner.Normalize(record.Value[(record.Value.IndexOf(' ', StringComparison.Ordinal) + 1)..]);
        string found = string.Join(", ", mx.Select(m => $"{m.Preference} {DomainRecordPlanner.Normalize(m.Exchange)}"));
        return new DomainRecordCheck(record, mx.Any(m => DomainRecordPlanner.Normalize(m.Exchange) == wanted) ? DomainRecordStatus.Ok : DomainRecordStatus.Mismatch, found);
    }

    /// <summary>
    /// Reverse DNS (advice): the PTR record of the sending IP must name this server. When the IP is configured the expected record is its reverse name;
    /// otherwise the host name's own addresses are looked up and each is reversed.
    /// </summary>
    private async Task<DomainRecordCheck> CheckPtrAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        string wanted = DomainRecordPlanner.Normalize(record.Value);
        var found = new List<(string Address, string Target)>();
        if (record.Host.EndsWith(".arpa", StringComparison.OrdinalIgnoreCase))
        {
            found.AddRange((await GetPtrTargetsAsync(record.Host, ct).ConfigureAwait(false)).Select(t => ("", t)));
        }
        else
        {
            var addresses = await GetAddressesAsync(wanted, ct).ConfigureAwait(false);
            foreach (string address in addresses.Order(StringComparer.Ordinal))
            {
                found.AddRange((await GetPtrTargetsAsync(DnsName.ReverseArpaName(IPAddress.Parse(address)), ct).ConfigureAwait(false)).Select(t => (address, t)));
            }
        }

        if (found.Count == 0)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        string text = string.Join(", ", found.Select(f => f.Address.Length == 0 ? f.Target : $"{f.Address} -> {f.Target}"));
        return new DomainRecordCheck(record, found.Any(f => f.Target == wanted) ? DomainRecordStatus.Ok : DomainRecordStatus.Mismatch, text);
    }

    private async Task<List<string>> GetPtrTargetsAsync(string arpaName, CancellationToken ct)
    {
        var response = await _dns.QueryAsync(arpaName, DnsRecordType.PTR, ct).ConfigureAwait(false);
        ThrowIfServerFailure(response);
        return response.Get<PtrRecord>().Select(p => DomainRecordPlanner.Normalize(p.Target)).ToList();
    }

    private async Task<HashSet<string>> GetAddressesAsync(string host, CancellationToken ct)
    {
        var addresses = new HashSet<string>(StringComparer.Ordinal);
        foreach (DnsRecordType type in new[] { DnsRecordType.A, DnsRecordType.AAAA })
        {
            var response = await _dns.QueryAsync(host, type, ct).ConfigureAwait(false);
            ThrowIfServerFailure(response);
            foreach (var a in response.Get<ARecord>())
            {
                addresses.Add(a.Address.ToString());
            }

            foreach (var a in response.Get<AaaaRecord>())
            {
                addresses.Add(a.Address.ToString());
            }
        }

        return addresses;
    }

    private async Task<List<string>> GetTxtAsync(string host, CancellationToken ct)
    {
        var response = await _dns.QueryAsync(host, DnsRecordType.TXT, ct).ConfigureAwait(false);
        ThrowIfServerFailure(response);
        return response.Get<TxtRecord>().Select(t => t.Text).ToList();
    }

    private static void ThrowIfServerFailure(DnsResponse response)
    {
        if (response.Rcode is not (DnsRcode.NoError or DnsRcode.NameError))
        {
            throw new DnsException("DNS server failure: " + response.Rcode);
        }
    }

    /// <summary>True when the first word of the record (up to a space or semicolon) is <paramref name="version"/> (so <c>v=spf10</c> is not <c>v=spf1</c>).</summary>
    private static bool HasVersion(string text, string version)
    {
        string trimmed = text.Trim();
        int end = trimmed.IndexOfAny([' ', ';', '\t']);
        return (end < 0 ? trimmed : trimmed[..end]).Equals(version, StringComparison.OrdinalIgnoreCase);
    }

    private static HashSet<string> SpfTokens(string spf) =>
        spf.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries).Skip(1).Select(t => t.ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);

    private static bool IsAllMechanism(string token) => token is "all" or "+all" or "-all" or "~all" or "?all";

    /// <summary>The value of a <c>tag=value</c> pair of a semicolon-separated record (DMARC, TLS-RPT, MTA-STS), or null.</summary>
    private static string? Tag(string record, string name)
    {
        foreach (string part in record.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int eq = part.IndexOf('=', StringComparison.Ordinal);
            if (eq > 0 && part[..eq].Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return part[(eq + 1)..].Trim();
            }
        }

        return null;
    }
}
