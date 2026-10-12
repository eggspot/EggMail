using Mta.Auth.Dmarc;
using Mta.Auth.Spf;

namespace Mta.Auth.Reports;

/// <summary>Why the receiver's disposition differs from the published policy (<c>PolicyOverrideType</c>, RFC 7489 Appendix C).</summary>
public enum DmarcPolicyOverride
{
    /// <summary>The message was relayed by a known forwarder.</summary>
    Forwarded = 0,

    /// <summary>The message was outside the <c>pct</c> sample, so a weaker policy was applied.</summary>
    SampledOut,

    /// <summary>The message came through a forwarder the receiver trusts.</summary>
    TrustedForwarder,

    /// <summary>The message came from a mailing list.</summary>
    MailingList,

    /// <summary>Local receiver policy overrode DMARC.</summary>
    LocalPolicy,

    /// <summary>Some other reason, described in the comment.</summary>
    Other,
}

/// <summary>A DKIM result keyword in an aggregate report (<c>DKIMResultType</c>).</summary>
public enum DkimReportResult
{
    /// <summary>No signature was present or checked.</summary>
    None = 0,

    /// <summary>The signature verified.</summary>
    Pass,

    /// <summary>The signature failed to verify.</summary>
    Fail,

    /// <summary>The signature was rejected by local policy.</summary>
    Policy,

    /// <summary>The signature was syntactically valid but not verified.</summary>
    Neutral,

    /// <summary>A transient error prevented verification.</summary>
    TempError,

    /// <summary>A permanent error (for example a bad key record) prevented verification.</summary>
    PermError,
}

/// <summary>Which SPF identity a report entry is about (<c>SPFDomainScope</c>).</summary>
public enum SpfReportScope
{
    /// <summary>The MAIL FROM identity (<c>mfrom</c>).</summary>
    MailFrom = 0,

    /// <summary>The HELO identity (<c>helo</c>).</summary>
    Helo,
}

/// <summary>An override reason in a report row.</summary>
/// <param name="Type">The reason.</param>
/// <param name="Comment">Optional free text.</param>
public sealed record DmarcPolicyOverrideReason(DmarcPolicyOverride Type, string? Comment = null);

/// <summary>A DKIM entry of <c>auth_results</c>.</summary>
/// <param name="Domain">The signing domain (<c>d=</c>).</param>
/// <param name="Selector">The selector (<c>s=</c>), or null.</param>
/// <param name="Result">The result.</param>
/// <param name="HumanResult">Optional human-readable detail.</param>
public sealed record DkimReportAuthResult(string Domain, string? Selector, DkimReportResult Result, string? HumanResult = null);

/// <summary>An SPF entry of <c>auth_results</c>.</summary>
/// <param name="Domain">The domain SPF was evaluated for.</param>
/// <param name="Scope">Whether it was the MAIL FROM or the HELO identity.</param>
/// <param name="Result">The SPF result.</param>
public sealed record SpfReportAuthResult(string Domain, SpfReportScope Scope, SpfResult Result);

/// <summary>The <c>report_metadata</c> block.</summary>
/// <param name="OrganizationName">The reporting organization (<c>org_name</c>).</param>
/// <param name="ContactEmail">Where to send questions (<c>email</c>); its domain is also the <c>receiver</c> part of the file name.</param>
/// <param name="ReportId">A unique identifier of this report.</param>
/// <param name="Begin">The start of the covered period.</param>
/// <param name="End">The end of the covered period.</param>
/// <param name="ExtraContactInfo">Optional URL or text for more information.</param>
/// <param name="Errors">Problems encountered while generating the report (for example truncation).</param>
public sealed record DmarcReportMetadata(
    string OrganizationName,
    string ContactEmail,
    string ReportId,
    DateTimeOffset Begin,
    DateTimeOffset End,
    string? ExtraContactInfo = null,
    IReadOnlyList<string>? Errors = null);

/// <summary>The <c>policy_published</c> block: the policy the reporter found in DNS.</summary>
/// <param name="Domain">The domain the policy was published for.</param>
/// <param name="DkimAlignment">The <c>adkim</c> mode.</param>
/// <param name="SpfAlignment">The <c>aspf</c> mode.</param>
/// <param name="Policy">The <c>p</c> policy.</param>
/// <param name="SubdomainPolicy">The effective <c>sp</c> policy (equal to <paramref name="Policy"/> when unpublished).</param>
/// <param name="Percentage">The <c>pct</c> value.</param>
/// <param name="FailureReportingOptions">The <c>fo</c> value.</param>
public sealed record DmarcPublishedPolicy(
    string Domain,
    DmarcAlignmentMode DkimAlignment,
    DmarcAlignmentMode SpfAlignment,
    DmarcPolicy Policy,
    DmarcPolicy SubdomainPolicy,
    int Percentage,
    string FailureReportingOptions = "0")
{
    /// <summary>Builds the block from a policy record found for <paramref name="domain"/>.</summary>
    /// <param name="domain">The domain the record was published for.</param>
    /// <param name="record">The record.</param>
    public static DmarcPublishedPolicy FromRecord(string domain, DmarcRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        return new DmarcPublishedPolicy(
            domain, record.DkimAlignment, record.SpfAlignment, record.Policy, record.SubdomainPolicy ?? record.Policy, record.Percentage, record.FailureReportingOptions);
    }
}

/// <summary>One aggregated row of a report: a count of messages with identical properties.</summary>
/// <param name="SourceIp">The connecting client address (text form).</param>
/// <param name="Count">How many messages had these properties.</param>
/// <param name="Disposition">The action the receiver took.</param>
/// <param name="DkimAligned">DMARC-aligned DKIM result (<c>policy_evaluated/dkim</c>: pass or fail).</param>
/// <param name="SpfAligned">DMARC-aligned SPF result (<c>policy_evaluated/spf</c>: pass or fail).</param>
/// <param name="Reasons">Why the disposition differs from the policy, if it does.</param>
/// <param name="EnvelopeTo">The recipient domain, or null.</param>
/// <param name="EnvelopeFrom">The MAIL FROM domain (or HELO domain for bounces).</param>
/// <param name="HeaderFrom">The RFC 5322 From domain.</param>
/// <param name="DkimResults">Raw DKIM results.</param>
/// <param name="SpfResults">Raw SPF results.</param>
public sealed record DmarcAggregateRecord(
    string SourceIp,
    long Count,
    DmarcDisposition Disposition,
    bool DkimAligned,
    bool SpfAligned,
    IReadOnlyList<DmarcPolicyOverrideReason> Reasons,
    string? EnvelopeTo,
    string EnvelopeFrom,
    string HeaderFrom,
    IReadOnlyList<DkimReportAuthResult> DkimResults,
    IReadOnlyList<SpfReportAuthResult> SpfResults);

/// <summary>A complete DMARC aggregate report (RFC 7489 Appendix C): one policy domain, one period.</summary>
/// <param name="Metadata">The report metadata.</param>
/// <param name="PolicyPublished">The published policy.</param>
/// <param name="Records">The aggregated rows.</param>
public sealed record DmarcAggregateReport(
    DmarcReportMetadata Metadata,
    DmarcPublishedPolicy PolicyPublished,
    IReadOnlyList<DmarcAggregateRecord> Records);
