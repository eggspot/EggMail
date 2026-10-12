using System.Net;
using System.Net.Sockets;
using Mta.Dns;

namespace Mta.Auth.Spf;

/// <summary>Evaluates SPF (RFC 7208).</summary>
public interface ISpfEvaluator
{
    /// <summary>Runs RFC 7208 <c>check_host()</c> for one identity.</summary>
    /// <param name="request">The client address, domain and sender.</param>
    /// <param name="cancellationToken">Cancels the check (the exception propagates; an internal timeout yields TempError instead).</param>
    ValueTask<SpfCheckResult> CheckHostAsync(SpfCheckRequest request, CancellationToken cancellationToken = default);

    /// <summary>Checks the HELO identity and (when present) the MAIL FROM identity of one SMTP transaction.</summary>
    /// <param name="clientIp">The SMTP client address.</param>
    /// <param name="heloDomain">The HELO/EHLO argument.</param>
    /// <param name="mailFrom">The MAIL FROM address without angle brackets; null or empty for the null reverse-path.</param>
    /// <param name="cancellationToken">Cancels the check.</param>
    ValueTask<SpfSessionResult> CheckSessionAsync(IPAddress clientIp, string heloDomain, string? mailFrom, CancellationToken cancellationToken = default);
}

/// <summary>
/// An RFC 7208 SPF evaluator. DNS answers are treated as hostile: the 10-term, 2-void-lookup, 10 MX/PTR name,
/// macro-size and record-length limits are enforced strictly; DNS errors and timeouts give TempError; no input
/// throws (only caller cancellation propagates). Instances are stateless and safe for concurrent use.
/// </summary>
public sealed class SpfEvaluator : ISpfEvaluator
{
    private readonly IDnsResolver _resolver;
    private readonly SpfOptions _options;

    /// <summary>Creates an evaluator.</summary>
    /// <param name="resolver">The DNS resolver (a caching resolver is expected).</param>
    /// <param name="options">The limits; null uses <see cref="SpfOptions.Default"/>.</param>
    public SpfEvaluator(IDnsResolver resolver, SpfOptions? options = null)
    {
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _options = options ?? SpfOptions.Default;
    }

    /// <inheritdoc />
    public async ValueTask<SpfCheckResult> CheckHostAsync(SpfCheckRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!SpfDomainName.TryNormalizeCheckDomain(request.Domain, out string? domain))
        {
            return new SpfCheckResult(SpfResult.None, (request.Domain ?? string.Empty).ToLowerInvariant(), Reason: "not a valid domain name");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (_options.Timeout > TimeSpan.Zero && _options.Timeout != Timeout.InfiniteTimeSpan)
        {
            timeout.CancelAfter(_options.Timeout);
        }

        var run = new Run(_resolver, _options, request, timeout.Token);
        Outcome outcome;
        try
        {
            outcome = await run.CheckDomainAsync(domain, 0, isInclude: false).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            outcome = new Outcome(SpfResult.TempError, null, "evaluation timed out", null);
        }
#pragma warning disable CA1031 // Hostile DNS data must never surface as an exception to the SMTP pipeline.
        catch (Exception ex) when (ex is not OperationCanceledException)
#pragma warning restore CA1031
        {
            outcome = new Outcome(SpfResult.TempError, null, "internal error: " + ex.GetType().Name, null);
        }

        return new SpfCheckResult(outcome.Result, domain, outcome.Matched, outcome.Explanation, outcome.Reason, run.DnsLookups, run.VoidLookups);
    }

    /// <inheritdoc />
    public async ValueTask<SpfSessionResult> CheckSessionAsync(IPAddress clientIp, string heloDomain, string? mailFrom, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(clientIp);
        SpfCheckResult helo = await CheckHostAsync(SpfCheckRequest.ForHelo(clientIp, heloDomain), cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrEmpty(mailFrom))
        {
            return new SpfSessionResult(helo, null);
        }

        SpfCheckResult mailFromResult = await CheckHostAsync(SpfCheckRequest.ForMailFrom(clientIp, heloDomain, mailFrom), cancellationToken).ConfigureAwait(false);
        return new SpfSessionResult(helo, mailFromResult);
    }

    private readonly record struct Outcome(SpfResult Result, string? Matched, string? Reason, string? Explanation);

    private enum MatchState
    {
        NoMatch,
        Match,
        Error,
    }

    private readonly record struct MatchOutcome(MatchState State, Outcome Error = default)
    {
        public static readonly MatchOutcome NoMatch = new(MatchState.NoMatch);
        public static readonly MatchOutcome Match = new(MatchState.Match);

        public static MatchOutcome Fail(SpfResult result, string reason) => new(MatchState.Error, new Outcome(result, null, reason, null));
    }

    /// <summary>The state of one top-level check_host() evaluation (counters are shared across include and redirect).</summary>
    private sealed class Run
    {
        private readonly IDnsResolver _resolver;
        private readonly SpfOptions _options;
        private readonly SpfCheckRequest _request;
        private readonly IPAddress _clientIp;
        private readonly CancellationToken _ct;
        private readonly DateTimeOffset _now;
        private List<string>? _validatedNames;
        private bool _macroOverflow;

        public Run(IDnsResolver resolver, SpfOptions options, SpfCheckRequest request, CancellationToken ct)
        {
            _resolver = resolver;
            _options = options;
            _request = request;
            _clientIp = request.ClientIp.IsIPv4MappedToIPv6 ? request.ClientIp.MapToIPv4() : request.ClientIp;
            _ct = ct;
            _now = options.Clock.UtcNow;
        }

        public int DnsLookups { get; private set; }

        public int VoidLookups { get; private set; }

        private bool ClientIsIpv4 => _clientIp.AddressFamily == AddressFamily.InterNetwork;

        public async ValueTask<Outcome> CheckDomainAsync(string domain, int depth, bool isInclude)
        {
            if (depth > _options.MaxNestingDepth)
            {
                return new Outcome(SpfResult.PermError, null, "include/redirect nesting too deep", null);
            }

            // 4.5: select the record.
            DnsResponse? txt = await QueryAsync(domain, DnsRecordType.TXT).ConfigureAwait(false);
            if (txt is null)
            {
                return new Outcome(SpfResult.TempError, null, "DNS error looking up TXT for " + domain, null);
            }

            string? recordText = null;
            foreach (TxtRecord t in txt.Get<TxtRecord>())
            {
                if (!SpfRecord.IsSpfRecord(t.Text))
                {
                    continue;
                }

                if (recordText is not null)
                {
                    return new Outcome(SpfResult.PermError, null, "multiple SPF records for " + domain, null);
                }

                recordText = t.Text;
            }

            if (recordText is null)
            {
                return new Outcome(SpfResult.None, null, "no SPF record for " + domain, null);
            }

            if (!SpfRecord.TryParse(recordText, _options.MaxRecordLength, out SpfRecord? record, out string? parseError))
            {
                return new Outcome(SpfResult.PermError, null, parseError, null);
            }

            // 4.6: evaluate.
            foreach (SpfDirective directive in record.Directives)
            {
                MatchOutcome m = await EvaluateMechanismAsync(directive.Mechanism, domain, depth).ConfigureAwait(false);
                if (_macroOverflow)
                {
                    return new Outcome(SpfResult.PermError, null, "macro expansion exceeds " + _options.MaxMacroExpansionLength + " characters", null);
                }

                if (m.State == MatchState.Error)
                {
                    return m.Error;
                }

                if (m.State == MatchState.Match)
                {
                    SpfResult result = directive.MatchResult;
                    string? explanation = null;
                    if (result == SpfResult.Fail && !isInclude)
                    {
                        explanation = await ExplainAsync(record, domain).ConfigureAwait(false);
                    }

                    return new Outcome(result, directive.Mechanism.Text, null, explanation);
                }
            }

            if (record.Redirect is not null && !record.HasAllMechanism)
            {
                if (!TryCountLookup())
                {
                    return LimitOutcome();
                }

                string? target = await ExpandDomainAsync(record.Redirect, domain).ConfigureAwait(false);
                if (target is null)
                {
                    return new Outcome(
                        SpfResult.PermError,
                        null,
                        _macroOverflow ? "macro expansion exceeds " + _options.MaxMacroExpansionLength + " characters" : "redirect: invalid target domain",
                        null);
                }

                Outcome redirected = await CheckDomainAsync(target, depth + 1, isInclude).ConfigureAwait(false);
                if (redirected.Result == SpfResult.None)
                {
                    return new Outcome(SpfResult.PermError, null, "redirect target " + target + " has no SPF record", null);
                }

                return redirected;
            }

            return new Outcome(SpfResult.Neutral, null, null, null);
        }

        private async ValueTask<MatchOutcome> EvaluateMechanismAsync(SpfMechanism mechanism, string domain, int depth)
        {
            switch (mechanism.Kind)
            {
                case SpfMechanismKind.All:
                    return MatchOutcome.Match;

                case SpfMechanismKind.Ip4:
                    return ClientIsIpv4 && IpInNetwork(_clientIp, mechanism.Network!, mechanism.Ip4Prefix) ? MatchOutcome.Match : MatchOutcome.NoMatch;

                case SpfMechanismKind.Ip6:
                    return !ClientIsIpv4 && IpInNetwork(_clientIp, mechanism.Network!, mechanism.Ip6Prefix) ? MatchOutcome.Match : MatchOutcome.NoMatch;

                case SpfMechanismKind.Include:
                    return await EvaluateIncludeAsync(mechanism, domain, depth).ConfigureAwait(false);

                case SpfMechanismKind.A:
                    return await EvaluateAAsync(mechanism, domain).ConfigureAwait(false);

                case SpfMechanismKind.Mx:
                    return await EvaluateMxAsync(mechanism, domain).ConfigureAwait(false);

                case SpfMechanismKind.Ptr:
                    return await EvaluatePtrAsync(mechanism, domain).ConfigureAwait(false);

                default:
                    return await EvaluateExistsAsync(mechanism, domain).ConfigureAwait(false);
            }
        }

        private async ValueTask<MatchOutcome> EvaluateIncludeAsync(SpfMechanism mechanism, string domain, int depth)
        {
            if (!TryCountLookup())
            {
                return LimitFailure();
            }

            string? target = await ExpandDomainAsync(mechanism.Domain!, domain).ConfigureAwait(false);
            if (target is null)
            {
                return MatchOutcome.Fail(SpfResult.PermError, "include: invalid target domain");
            }

            Outcome inner = await CheckDomainAsync(target, depth + 1, isInclude: true).ConfigureAwait(false);
            switch (inner.Result)
            {
                case SpfResult.Pass:
                    return MatchOutcome.Match;
                case SpfResult.Fail:
                case SpfResult.SoftFail:
                case SpfResult.Neutral:
                    return MatchOutcome.NoMatch;
                case SpfResult.None:
                    return MatchOutcome.Fail(SpfResult.PermError, "include target " + target + " has no SPF record");
                default:
                    return new MatchOutcome(MatchState.Error, new Outcome(inner.Result, null, inner.Reason, null));
            }
        }

        private async ValueTask<MatchOutcome> EvaluateAAsync(SpfMechanism mechanism, string domain)
        {
            if (!TryCountLookup())
            {
                return LimitFailure();
            }

            string? target = mechanism.Domain is null ? domain : await ExpandDomainAsync(mechanism.Domain, domain).ConfigureAwait(false);
            if (target is null)
            {
                return MatchOutcome.NoMatch;
            }

            return await MatchAddressesAsync(target, mechanism).ConfigureAwait(false);
        }

        /// <summary>Looks up the client-family address records of <paramref name="host"/> and compares them to the client.</summary>
        private async ValueTask<MatchOutcome> MatchAddressesAsync(string host, SpfMechanism mechanism)
        {
            DnsResponse? response = await QueryAsync(host, ClientIsIpv4 ? DnsRecordType.A : DnsRecordType.AAAA).ConfigureAwait(false);
            if (response is null)
            {
                return MatchOutcome.Fail(SpfResult.TempError, "DNS error looking up addresses of " + host);
            }

            bool any = false;
            int prefix = ClientIsIpv4 ? mechanism.Ip4Prefix : mechanism.Ip6Prefix;
            foreach (IPAddress address in Addresses(response))
            {
                any = true;
                if (IpInNetwork(_clientIp, address, prefix))
                {
                    return MatchOutcome.Match;
                }
            }

            if (!any && !TryCountVoid())
            {
                return VoidFailure();
            }

            return MatchOutcome.NoMatch;
        }

        private async ValueTask<MatchOutcome> EvaluateMxAsync(SpfMechanism mechanism, string domain)
        {
            if (!TryCountLookup())
            {
                return LimitFailure();
            }

            string? target = mechanism.Domain is null ? domain : await ExpandDomainAsync(mechanism.Domain, domain).ConfigureAwait(false);
            if (target is null)
            {
                return MatchOutcome.NoMatch;
            }

            DnsResponse? mx = await QueryAsync(target, DnsRecordType.MX).ConfigureAwait(false);
            if (mx is null)
            {
                return MatchOutcome.Fail(SpfResult.TempError, "DNS error looking up MX for " + target);
            }

            var exchanges = mx.Get<MxRecord>().OrderBy(r => r.Preference).ToList();
            if (exchanges.Count == 0)
            {
                return TryCountVoid() ? MatchOutcome.NoMatch : VoidFailure();
            }

            if (exchanges.Count > _options.MaxMxPtrNames)
            {
                return MatchOutcome.Fail(SpfResult.PermError, "mx: more than " + _options.MaxMxPtrNames + " MX records for " + target);
            }

            foreach (MxRecord exchange in exchanges)
            {
                if (!SpfDomainName.TryNormalizeExpanded(exchange.Exchange, out string? host))
                {
                    continue; // the null MX "." and malformed names are skipped
                }

                MatchOutcome m = await MatchAddressesAsync(host, mechanism).ConfigureAwait(false);
                if (m.State != MatchState.NoMatch)
                {
                    return m;
                }
            }

            return MatchOutcome.NoMatch;
        }

        private async ValueTask<MatchOutcome> EvaluatePtrAsync(SpfMechanism mechanism, string domain)
        {
            if (!TryCountLookup())
            {
                return LimitFailure();
            }

            string? target = mechanism.Domain is null ? domain : await ExpandDomainAsync(mechanism.Domain, domain).ConfigureAwait(false);
            if (target is null)
            {
                return MatchOutcome.NoMatch;
            }

            foreach (string name in await GetValidatedNamesAsync().ConfigureAwait(false))
            {
                if (IsSameOrSubdomain(name, target))
                {
                    return MatchOutcome.Match;
                }
            }

            return MatchOutcome.NoMatch;
        }

        private async ValueTask<MatchOutcome> EvaluateExistsAsync(SpfMechanism mechanism, string domain)
        {
            if (!TryCountLookup())
            {
                return LimitFailure();
            }

            string? target = await ExpandDomainAsync(mechanism.Domain!, domain).ConfigureAwait(false);
            if (target is null)
            {
                return MatchOutcome.NoMatch;
            }

            DnsResponse? response = await QueryAsync(target, DnsRecordType.A).ConfigureAwait(false);
            if (response is null)
            {
                return MatchOutcome.Fail(SpfResult.TempError, "DNS error looking up " + target);
            }

            if (response.Get<ARecord>().Any())
            {
                return MatchOutcome.Match;
            }

            return TryCountVoid() ? MatchOutcome.NoMatch : VoidFailure();
        }

        /// <summary>
        /// The PTR names of the client that resolve back to the client address (RFC 7208 section 5.5), at most
        /// <see cref="SpfOptions.MaxMxPtrNames"/> examined. DNS errors skip the name. Computed once per check.
        /// </summary>
        private async ValueTask<List<string>> GetValidatedNamesAsync()
        {
            if (_validatedNames is not null)
            {
                return _validatedNames;
            }

            var validated = new List<string>();
            _validatedNames = validated;
            DnsResponse? ptr = await QueryAsync(ReverseName(_clientIp), DnsRecordType.PTR).ConfigureAwait(false);
            if (ptr is null)
            {
                return validated;
            }

            int examined = 0;
            foreach (PtrRecord record in ptr.Get<PtrRecord>())
            {
                if (examined++ >= _options.MaxMxPtrNames)
                {
                    break;
                }

                if (!SpfDomainName.TryNormalizeExpanded(record.Target, out string? name))
                {
                    continue;
                }

                DnsResponse? forward = await QueryAsync(name, ClientIsIpv4 ? DnsRecordType.A : DnsRecordType.AAAA).ConfigureAwait(false);
                if (forward is null)
                {
                    continue;
                }

                if (Addresses(forward).Any(a => a.Equals(_clientIp)))
                {
                    validated.Add(name);
                }
            }

            return validated;
        }

        private IEnumerable<IPAddress> Addresses(DnsResponse response)
        {
            if (ClientIsIpv4)
            {
                foreach (ARecord a in response.Get<ARecord>())
                {
                    yield return a.Address;
                }
            }
            else
            {
                foreach (AaaaRecord a in response.Get<AaaaRecord>())
                {
                    yield return a.Address;
                }
            }
        }

        private async ValueTask<string?> ExpandDomainAsync(SpfMacroString macro, string currentDomain)
        {
            SpfMacroContext context = await CreateContextAsync(macro, currentDomain).ConfigureAwait(false);
            if (!macro.TryExpand(context, _options.MaxMacroExpansionLength, out string? expanded))
            {
                _macroOverflow = true;
                return null;
            }

            return SpfDomainName.TryNormalizeExpanded(expanded, out string? domain) ? domain : null;
        }

        private async ValueTask<SpfMacroContext> CreateContextAsync(SpfMacroString macro, string currentDomain)
        {
            string validated = "unknown";
            if (macro.UsesValidatedDomainName)
            {
                List<string> names = await GetValidatedNamesAsync().ConfigureAwait(false);
                string? preferred = names.FirstOrDefault(n => IsSameOrSubdomain(n, currentDomain)) ?? names.FirstOrDefault();
                validated = preferred ?? "unknown";
            }

            return new SpfMacroContext(_request.Sender, currentDomain, _clientIp, _request.HeloDomain)
            {
                ValidatedDomain = validated,
                ReceivingHostName = _options.ReceivingHostName,
                Timestamp = _now,
            };
        }

        /// <summary>RFC 7208 section 6.2: the explanation for a Fail result, from <c>exp=</c> or the default text.</summary>
        private async ValueTask<string?> ExplainAsync(SpfRecord record, string domain)
        {
            if (!_options.EvaluateExplanations)
            {
                return null;
            }

            string? text = null;
            if (record.Explanation is not null)
            {
                text = await FetchExplanationAsync(record.Explanation, domain).ConfigureAwait(false);
            }

            if (text is null && _options.DefaultExplanation is { } fallback
                && SpfMacroString.TryParse(fallback, SpfMacroKind.Explanation, out SpfMacroString? defaultMacro, out _))
            {
                text = await ExpandExplanationAsync(defaultMacro, domain).ConfigureAwait(false);
            }

            return text;
        }

        private async ValueTask<string?> FetchExplanationAsync(SpfMacroString domainSpec, string domain)
        {
            string? target = await ExpandDomainAsync(domainSpec, domain).ConfigureAwait(false);
            if (target is null)
            {
                return null;
            }

            DnsResponse? response = await QueryAsync(target, DnsRecordType.TXT).ConfigureAwait(false);
            if (response is null)
            {
                return null;
            }

            TxtRecord[] records = response.Get<TxtRecord>().Take(2).ToArray();
            if (records.Length != 1 || records[0].Text.Length > _options.MaxMacroExpansionLength)
            {
                return null;
            }

            if (!SpfMacroString.TryParse(records[0].Text, SpfMacroKind.Explanation, out SpfMacroString? macro, out _))
            {
                return null;
            }

            return await ExpandExplanationAsync(macro, domain).ConfigureAwait(false);
        }

        private async ValueTask<string?> ExpandExplanationAsync(SpfMacroString macro, string domain)
        {
            SpfMacroContext context = await CreateContextAsync(macro, domain).ConfigureAwait(false);
            if (!macro.TryExpand(context, _options.MaxExplanationLength, out string? text))
            {
                return null;
            }

            foreach (char c in text)
            {
                if (c is < ' ' or > '~')
                {
                    return null;
                }
            }

            return text;
        }

        /// <summary>Runs one DNS query; returns null on timeout, transport failure or any rcode other than NOERROR and NXDOMAIN.</summary>
        private async ValueTask<DnsResponse?> QueryAsync(string name, DnsRecordType type)
        {
            try
            {
                DnsResponse response = await _resolver.QueryAsync(name, type, _ct).ConfigureAwait(false);
                return response.Rcode is DnsRcode.NoError or DnsRcode.NameError ? response : null;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
#pragma warning disable CA1031 // Any resolver failure is a transient DNS error for SPF purposes.
            catch (Exception)
#pragma warning restore CA1031
            {
                return null;
            }
        }

        private bool TryCountLookup() => ++DnsLookups <= _options.MaxDnsLookups;

        private bool TryCountVoid() => ++VoidLookups <= _options.MaxVoidLookups;

        private MatchOutcome LimitFailure() => MatchOutcome.Fail(SpfResult.PermError, "too many DNS lookups (limit " + _options.MaxDnsLookups + ")");

        private Outcome LimitOutcome() => new(SpfResult.PermError, null, "too many DNS lookups (limit " + _options.MaxDnsLookups + ")", null);

        private MatchOutcome VoidFailure() => MatchOutcome.Fail(SpfResult.PermError, "too many void DNS lookups (limit " + _options.MaxVoidLookups + ")");
    }

    private static bool IsSameOrSubdomain(string name, string domain) =>
        name.Equals(domain, StringComparison.OrdinalIgnoreCase)
        || (name.Length > domain.Length && name.EndsWith(domain, StringComparison.OrdinalIgnoreCase) && name[name.Length - domain.Length - 1] == '.');

    /// <summary>True when <paramref name="address"/> lies in <paramref name="network"/>/<paramref name="prefix"/> (same family only).</summary>
    internal static bool IpInNetwork(IPAddress address, IPAddress network, int prefix)
    {
        if (address.AddressFamily != network.AddressFamily)
        {
            return false;
        }

        Span<byte> a = stackalloc byte[16];
        Span<byte> n = stackalloc byte[16];
        if (!address.TryWriteBytes(a, out int len) || !network.TryWriteBytes(n, out int len2) || len != len2)
        {
            return false;
        }

        int bits = Math.Min(prefix, len * 8);
        int fullBytes = bits / 8;
        if (!a[..fullBytes].SequenceEqual(n[..fullBytes]))
        {
            return false;
        }

        int rem = bits % 8;
        if (rem == 0)
        {
            return true;
        }

        int mask = 0xFF << (8 - rem) & 0xFF;
        return (a[fullBytes] & mask) == (n[fullBytes] & mask);
    }

    /// <summary>The reverse-lookup name (<c>in-addr.arpa</c> or <c>ip6.arpa</c>) of an address.</summary>
    internal static string ReverseName(IPAddress ip)
    {
        Span<byte> bytes = stackalloc byte[16];
        ip.TryWriteBytes(bytes, out int len);
        var sb = new System.Text.StringBuilder(73);
        if (len == 4)
        {
            for (int i = 3; i >= 0; i--)
            {
                sb.Append(bytes[i]).Append('.');
            }

            sb.Append("in-addr.arpa");
        }
        else
        {
            for (int i = 15; i >= 0; i--)
            {
                sb.Append("0123456789abcdef"[bytes[i] & 0xF]).Append('.').Append("0123456789abcdef"[bytes[i] >> 4]).Append('.');
            }

            sb.Append("ip6.arpa");
        }

        return sb.ToString();
    }
}
