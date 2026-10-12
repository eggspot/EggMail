using Mta.Dkim;
using Mta.Dns;
using Mta.Policy;

namespace Mta.Host.Domains;

/// <summary>Outcome of one verification pass over a domain's records.</summary>
public sealed record DomainCheckResult(IReadOnlyList<DomainRecordCheck> Records, VerificationCheckResult Result, string? Error);

/// <summary>
/// Looks the planned records up in DNS. Only required records decide the result; a DNS failure (timeout, SERVFAIL) is reported as
/// <see cref="VerificationCheckResult.DnsTemporaryFailure"/> so a resolver outage never marks a domain as broken.
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
            if (record.Required && check.Status is DomainRecordStatus.Missing or DomainRecordStatus.Invalid)
            {
                firstProblem ??= $"{record.Purpose} record {record.Host} is {check.Status.ToString().ToLowerInvariant()}";
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

    private async Task<DomainRecordCheck> CheckOneAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        switch (record.Purpose)
        {
            case DomainRecordPurpose.Dkim:
                return await CheckDkimAsync(record, ct).ConfigureAwait(false);
            case DomainRecordPurpose.ReturnPath:
                return await CheckCnameAsync(record, ct).ConfigureAwait(false);
            default:
                return await CheckTxtPrefixAsync(record, record.Purpose == DomainRecordPurpose.Spf ? "v=spf1" : "v=DMARC1", ct).ConfigureAwait(false);
        }
    }

    private async Task<DomainRecordCheck> CheckDkimAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        var texts = await GetTxtAsync(record.Host, ct).ConfigureAwait(false);
        if (texts.Count == 0)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        DkimKeyTools.TryParseDnsTxtValue(record.Value, out var wanted, out _);
        foreach (string text in texts)
        {
            if (DkimKeyRecord.TryParse(text, out var parsed, out _)
                && wanted is not null
                && parsed!.PublicKeySubjectPublicKeyInfo.AsSpan().SequenceEqual(wanted.PublicKeySubjectPublicKeyInfo))
            {
                return new DomainRecordCheck(record, DomainRecordStatus.Ok, text);
            }
        }

        return new DomainRecordCheck(record, DomainRecordStatus.Invalid, texts[0]);
    }

    private async Task<DomainRecordCheck> CheckCnameAsync(ExpectedDomainRecord record, CancellationToken ct)
    {
        var response = await _dns.QueryAsync(record.Host, DnsRecordType.CNAME, ct).ConfigureAwait(false);
        ThrowIfServerFailure(response);
        string host = DomainRecordPlanner.Normalize(record.Host);
        var cname = response.Get<CnameRecord>().FirstOrDefault(c => DomainRecordPlanner.Normalize(c.Name) == host);
        if (cname is null)
        {
            return new DomainRecordCheck(record, DomainRecordStatus.Missing, null);
        }

        string target = DomainRecordPlanner.Normalize(cname.Target);
        return new DomainRecordCheck(record, target == DomainRecordPlanner.Normalize(record.Value) ? DomainRecordStatus.Ok : DomainRecordStatus.Invalid, target);
    }

    private async Task<DomainRecordCheck> CheckTxtPrefixAsync(ExpectedDomainRecord record, string prefix, CancellationToken ct)
    {
        var texts = await GetTxtAsync(record.Host, ct).ConfigureAwait(false);
        string? found = texts.FirstOrDefault(t => t.TrimStart().StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        return found is null
            ? new DomainRecordCheck(record, DomainRecordStatus.Missing, texts.Count > 0 ? texts[0] : null)
            : new DomainRecordCheck(record, DomainRecordStatus.Ok, found);
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
}
