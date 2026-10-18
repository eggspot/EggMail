using System.Diagnostics.Metrics;

namespace Mta.Host.Ingest;

/// <summary>
/// Meters of the inbound receive path (<c>Mta.Inbound</c>, design section 11.11). Labels are small fixed sets: never a domain, an address or a tenant.
/// The route actions have their own instruments, where they are carried out.
/// </summary>
public static class InboundMetrics
{
    public static readonly Meter Meter = new("Mta.Inbound");

    /// <summary>What happened to each recipient of the inbound listener: <c>accepted</c>, <c>postmaster</c>, <c>srs_bounce</c>, <c>bounce</c>, <c>relay_denied</c>, <c>unknown_mailbox</c>, <c>rate_limited</c>, <c>too_many</c>, <c>mailbox_full</c>, <c>domain_unverified</c>, <c>tenant_disabled</c>, <c>mixed_kinds</c>, <c>message_too_large</c>, <c>budget</c>, <c>dnsbl_rejected</c>, <c>unavailable</c>.</summary>
    public static readonly Counter<long> Recipients = Meter.CreateCounter<long>("mta.inbound.recipients", "{recipient}", "Recipients of the inbound listener by outcome");

    /// <summary>What happened to each inbound message that reached the end of DATA: <c>accepted</c>, <c>rejected_dmarc</c>, <c>rejected_verification</c>, <c>rejected_size</c>, <c>rejected_busy</c>, <c>rejected_other</c>.</summary>
    public static readonly Counter<long> Messages = Meter.CreateCounter<long>("mta.inbound.messages", "{message}", "Inbound messages by outcome");

    public static readonly Counter<long> Bytes = Meter.CreateCounter<long>("mta.inbound.bytes", "By", "Bytes of inbound messages accepted (one copy per message, not per recipient)");

    /// <summary>Verification results by mechanism (<c>spf</c>, <c>spf_helo</c>, <c>dkim</c>, <c>dmarc</c>, <c>arc</c>) and result (<c>pass</c>, <c>fail</c>, <c>softfail</c>, <c>neutral</c>, <c>none</c>, <c>temperror</c>, <c>permerror</c>, <c>policy</c>).</summary>
    public static readonly Counter<long> Auth = Meter.CreateCounter<long>("mta.inbound.auth", "{result}", "Verification results of inbound messages by mechanism and result");

    public static readonly Histogram<double> VerificationSeconds = Meter.CreateHistogram<double>("mta.inbound.verification.duration", "s", "Time the verification of one inbound message took (SPF, DKIM, DMARC and ARC together)");

    /// <summary>Lookups of the connecting address in the configured blocklists by result (<c>hit</c>, <c>miss</c>, <c>error</c>).</summary>
    public static readonly Counter<long> Dnsbl = Meter.CreateCounter<long>("mta.inbound.dnsbl", "{lookup}", "Blocklist lookups by result");

    public static readonly UpDownCounter<long> VerificationSlotsInUse = Meter.CreateUpDownCounter<long>("mta.inbound.verification.slots.in_use", "{slot}", "Verification slots in use");

    public static readonly Counter<long> LimiterEvictions = Meter.CreateCounter<long>("mta.inbound.limiter.evictions", "{entry}", "Entries a rate limiter dropped to stay within its size, by limiter (domain, remote)");

    /// <summary>Transactions refused as a whole: <c>mixed_kinds</c>, <c>budget</c>, <c>no_verification_slot</c>, <c>dmarc</c>, <c>verification_temperror</c>.</summary>
    public static readonly Counter<long> TransactionsRefused = Meter.CreateCounter<long>("mta.inbound.transactions.refused", "{transaction}", "Inbound transactions refused as a whole, by reason");

    // The gauges read the receive path of this process; the last one built is the one reported (a process has one).
    private static volatile Func<double>? s_configAgeSeconds;
    private static volatile Func<(int Domain, int Remote)>? s_limiterEntries;

    static InboundMetrics()
    {
        Meter.CreateObservableGauge("mta.inbound.config.age", () => s_configAgeSeconds is { } age ? age() : 0, "s", "Age of the receive path's cached configuration; alert when it keeps growing (the refresh has stopped)");
        Meter.CreateObservableGauge("mta.inbound.limiter.entries", ObserveLimiters, "{entry}", "Entries held by each rate limiter, by limiter (domain, remote)");
    }

    internal static void Attach(Func<double> configAgeSeconds, Func<(int Domain, int Remote)> limiterEntries)
    {
        s_configAgeSeconds = configAgeSeconds;
        s_limiterEntries = limiterEntries;
    }

    private static IEnumerable<Measurement<long>> ObserveLimiters()
    {
        (int domain, int remote) = s_limiterEntries is { } entries ? entries() : (0, 0);
        yield return new Measurement<long>(domain, new KeyValuePair<string, object?>("limiter", "domain"));
        yield return new Measurement<long>(remote, new KeyValuePair<string, object?>("limiter", "remote"));
    }

    internal static void Recipient(string outcome) => Recipients.Add(1, new KeyValuePair<string, object?>("outcome", outcome));

    internal static void Message(string outcome) => Messages.Add(1, new KeyValuePair<string, object?>("outcome", outcome));

    internal static void Refused(string reason) => TransactionsRefused.Add(1, new KeyValuePair<string, object?>("reason", reason));
}
