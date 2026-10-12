using Mta.Dns;

namespace Mta.Tls.Dane;

/// <summary>The outcome class of a TLSA lookup for one MX host.</summary>
public enum DaneStatus
{
    /// <summary>DANE does not apply: no TLSA records, or the answer was not DNSSEC-authenticated (treated as no TLSA records).</summary>
    NotApplicable,

    /// <summary>A secure TLSA record set with at least one usable record: authenticate the server with it.</summary>
    Usable,

    /// <summary>A secure TLSA record set with no usable record: an authenticated failure, never a downgrade (RFC 7672 section 2.1.1).</summary>
    Unusable,

    /// <summary>The lookup failed (SERVFAIL, i.e. DNSSEC validation failure, or a transport error): the MX cannot be used safely right now.</summary>
    LookupFailed,
}

/// <summary>The result of <see cref="DaneTlsaLookup.LookupAsync"/>.</summary>
/// <param name="Status">The outcome class.</param>
/// <param name="TlsaName">The queried TLSA owner name (<c>_25._tcp.host</c>) the records were found under, if any.</param>
/// <param name="UsableRecords">The records usable for SMTP (usages 2 and 3 with valid parameters).</param>
/// <param name="IgnoredRecords">Records present but unusable (for example usage 0 or 1).</param>
/// <param name="ReferenceNames">The names a DANE-TA certificate may match: the TLSA base domain and the original MX name.</param>
/// <param name="Failure">The TLS-RPT classification for <see cref="DaneStatus.Unusable"/> and <see cref="DaneStatus.LookupFailed"/>.</param>
/// <param name="Notes">Human-readable notes for logs.</param>
public sealed record DaneLookupResult(
    DaneStatus Status,
    string? TlsaName,
    IReadOnlyList<TlsaRecord> UsableRecords,
    IReadOnlyList<TlsaRecord> IgnoredRecords,
    IReadOnlyList<string> ReferenceNames,
    TlsResultType? Failure,
    IReadOnlyList<string> Notes)
{
    /// <summary>True when the MX must not be used without successful DANE authentication (no fallback to other policies or plaintext).</summary>
    public bool RequiresDane => Status is DaneStatus.Usable or DaneStatus.Unusable or DaneStatus.LookupFailed;

    internal static DaneLookupResult NotApplicable(params string[] notes) =>
        new(DaneStatus.NotApplicable, null, [], [], [], null, notes);
}

/// <summary>Options for <see cref="DaneTlsaLookup"/>.</summary>
public sealed class DaneLookupOptions
{
    /// <summary>
    /// When the MX name is an alias with an authenticated CNAME chain, look for TLSA records at the final name first and
    /// at the original name second (RFC 7672 section 2.2.2). Costs one extra (cacheable) address query. Default true.
    /// </summary>
    public bool FollowAddressCname { get; init; } = true;
}

/// <summary>
/// Finds the DANE TLSA record set for an MX host (<c>_25._tcp.&lt;host&gt;</c>). TLSA data is only trusted when the
/// resolver says it was DNSSEC-validated (AD bit); the resolver must therefore be a trusted local validating resolver.
/// </summary>
public sealed class DaneTlsaLookup
{
    private readonly IDnsResolver _resolver;
    private readonly DaneLookupOptions _options;

    /// <summary>Creates a lookup over <paramref name="resolver"/>.</summary>
    public DaneTlsaLookup(IDnsResolver resolver, DaneLookupOptions? options = null)
    {
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _options = options ?? new DaneLookupOptions();
    }

    /// <summary>Looks up TLSA records for <paramref name="mxHost"/>. Does not throw on DNS failures.</summary>
    /// <param name="mxHost">The MX host name.</param>
    /// <param name="port">The SMTP port (default 25).</param>
    /// <param name="mxRrsetAuthenticated">
    /// Whether the MX RRset that produced <paramref name="mxHost"/> was DNSSEC-authenticated. RFC 7672 section 2.2.1 allows
    /// DANE only for secure MX records; pass false for an insecure MX answer to skip DANE.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async ValueTask<DaneLookupResult> LookupAsync(string mxHost, int port = 25, bool mxRrsetAuthenticated = true, CancellationToken cancellationToken = default)
    {
        if (!DnsNames.TryNormalizeHost(mxHost, out string host))
        {
            return DaneLookupResult.NotApplicable("MX host name is not a valid DNS name");
        }

        if (!mxRrsetAuthenticated)
        {
            return DaneLookupResult.NotApplicable("MX records are not DNSSEC-authenticated; DANE does not apply (RFC 7672 section 2.2.1)");
        }

        var notes = new List<string>();
        var bases = new List<string> { host };
        if (_options.FollowAddressCname)
        {
            string? target = await TryFollowCnameAsync(host, notes, cancellationToken).ConfigureAwait(false);
            if (target is not null)
            {
                bases.Insert(0, target);
            }
        }

        foreach (string baseDomain in bases)
        {
            string tlsaName = $"_{port}._tcp.{baseDomain}";
            DnsResponse response;
            try
            {
                response = await _resolver.QueryAsync(tlsaName, DnsRecordType.TLSA, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                notes.Add($"TLSA lookup for {tlsaName} failed: {ex.Message}");
                return new DaneLookupResult(DaneStatus.LookupFailed, tlsaName, [], [], [], TlsResultType.ValidationFailure, notes);
            }

            if (response.Rcode == DnsRcode.ServerFailure)
            {
                notes.Add($"TLSA lookup for {tlsaName} returned SERVFAIL (DNSSEC validation failure or resolver error)");
                return new DaneLookupResult(DaneStatus.LookupFailed, tlsaName, [], [], [], TlsResultType.DnssecInvalid, notes);
            }

            if (response.Rcode is not (DnsRcode.NoError or DnsRcode.NameError))
            {
                notes.Add($"TLSA lookup for {tlsaName} returned {response.Rcode}");
                return new DaneLookupResult(DaneStatus.LookupFailed, tlsaName, [], [], [], TlsResultType.ValidationFailure, notes);
            }

            var all = response.Get<TlsaRecord>().ToList();
            if (all.Count == 0)
            {
                notes.Add($"no TLSA records at {tlsaName}");
                continue;
            }

            if (!response.AuthenticatedData)
            {
                notes.Add($"TLSA records at {tlsaName} are not DNSSEC-authenticated; ignored (RFC 7672 section 2.2)");
                return new DaneLookupResult(DaneStatus.NotApplicable, tlsaName, [], [], [], null, notes);
            }

            var usable = new List<TlsaRecord>();
            var ignored = new List<TlsaRecord>();
            foreach (var record in all)
            {
                if (TlsaRecordClassifier.IsUsable(record, out string? reason))
                {
                    usable.Add(record);
                }
                else
                {
                    ignored.Add(record);
                    notes.Add(reason!);
                }
            }

            string[] references = baseDomain == host ? [host] : [baseDomain, host];
            if (usable.Count == 0)
            {
                notes.Add("secure TLSA record set has no usable record; delivery to this MX must fail rather than downgrade (RFC 7672 section 2.1.1)");
                return new DaneLookupResult(DaneStatus.Unusable, tlsaName, [], ignored, references, TlsResultType.TlsaInvalid, notes);
            }

            return new DaneLookupResult(DaneStatus.Usable, tlsaName, usable, ignored, references, null, notes);
        }

        return new DaneLookupResult(DaneStatus.NotApplicable, null, [], [], [], null, notes);
    }

    private async ValueTask<string?> TryFollowCnameAsync(string host, List<string> notes, CancellationToken ct)
    {
        try
        {
            DnsResponse response = await _resolver.QueryAsync(host, DnsRecordType.A, ct).ConfigureAwait(false);
            if (!response.IsSuccess || !response.AuthenticatedData)
            {
                return null;
            }

            // Follow the alias chain by name; bounded to avoid loops in hostile answers.
            string current = host;
            for (int i = 0; i < 8; i++)
            {
                var cname = response.Get<CnameRecord>().FirstOrDefault(c => string.Equals(c.Name.TrimEnd('.'), current, StringComparison.OrdinalIgnoreCase));
                if (cname is null)
                {
                    break;
                }

                if (!DnsNames.TryNormalizeHost(cname.Target, out string next))
                {
                    return null;
                }

                current = next;
            }

            if (current != host)
            {
                notes.Add($"MX host is an authenticated alias for {current}");
                return current;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            notes.Add("address lookup for CNAME detection failed: " + ex.Message);
        }

        return null;
    }
}
