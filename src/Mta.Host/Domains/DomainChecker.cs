using System.Net;
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
    private readonly IDnsResolver _dns;

    public DomainChecker(IDnsResolver dns) => _dns = dns ?? throw new ArgumentNullException(nameof(dns));

    public async Task<DomainCheckResult> CheckAsync(IReadOnlyList<ExpectedDomainRecord> expected, CancellationToken cancellationToken)
    {
        var checks = new List<DomainRecordCheck>(expected.Count);
        bool dnsFailed = false;
        string? firstProblem = null;
        foreach (var record in expected)
        {
            DomainRecordCheck check;
            try
            {
                check = await CheckOneAsync(record, cancellationToken).ConfigureAwait(false);
            }
            catch (DnsException)
            {
                check = new DomainRecordCheck(record, DomainRecordStatus.Pending, null);
                if (record.Required)
                {
                    dnsFailed = true;
                }
            }

            checks.Add(check);
            if (record.Required && check.Status is DomainRecordStatus.Missing or DomainRecordStatus.Invalid or DomainRecordStatus.Mismatch)
            {
                firstProblem ??= $"{record.Purpose} record {record.Host} " + check.Status switch
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

        return dnsFailed
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
        string? target = await GetCnameTargetAsync(record.Host, ct).ConfigureAwait(false);
        if (target is null)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        return new DomainRecordCheck(record, target == DomainRecordPlanner.Normalize(record.Value) ? DomainRecordStatus.Ok : DomainRecordStatus.Mismatch, target);
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
    /// SPF: exactly one <c>v=spf1</c> record must exist (two are a permanent error for receivers) and it must contain every mechanism of the expected value
    /// (an <c>include:</c>, an <c>ip4:</c>, an <c>a:</c>); anything else in it, such as the customer's other senders, is theirs to keep.
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

        var found = SpfTokens(records[0]);
        bool allPresent = SpfTokens(record.Value).Where(t => !IsAllMechanism(t)).All(found.Contains);
        return new DomainRecordCheck(record, allPresent ? DomainRecordStatus.Ok : DomainRecordStatus.Mismatch, records[0]);
    }

    /// <summary>DMARC: one record with a valid policy. The policy and report address are the customer's to choose, so a different one is not a mismatch.</summary>
    private async Task<DomainRecordCheck> CheckDmarcAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        var records = (await GetTxtAsync(record.Host, ct).ConfigureAwait(false)).Where(t => HasVersion(t, "v=DMARC1")).ToList();
        if (records.Count == 0)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        bool valid = records.Count == 1 && Tag(records[0], "p")?.ToLowerInvariant() is "none" or "quarantine" or "reject";
        return new DomainRecordCheck(record, valid ? DomainRecordStatus.Ok : DomainRecordStatus.Invalid, string.Join(" | ", records));
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

    /// <summary>The MTA-STS web name: a CNAME to this server's host name, or A/AAAA records that are the host name's own addresses.</summary>
    private async Task<DomainRecordCheck> CheckMtaStsHostAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        string? target = await GetCnameTargetAsync(record.Host, ct).ConfigureAwait(false);
        if (target is not null)
        {
            if (target == DomainRecordPlanner.Normalize(record.Value))
            {
                return new DomainRecordCheck(record, DomainRecordStatus.Ok, target);
            }

            // Another name for the same server (an alias of the host name) is fine when it leads to the same addresses.
            var viaTarget = await GetAddressesAsync(target, ct).ConfigureAwait(false);
            var server = await GetAddressesAsync(record.Value, ct).ConfigureAwait(false);
            return new DomainRecordCheck(record, viaTarget.Overlaps(server) ? DomainRecordStatus.Ok : DomainRecordStatus.Mismatch, target);
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
