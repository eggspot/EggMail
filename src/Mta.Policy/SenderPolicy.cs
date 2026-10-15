using Mta.Core;
using Mta.Storage;

namespace Mta.Policy;

/// <summary>Configuration for <see cref="SenderPolicy"/>. Defaults are proposed.</summary>
public sealed class SenderPolicyOptions
{
    /// <summary>Maximum recipients in one message. Default 100 (the RFC 5321 minimum every server must accept).</summary>
    public int MaxRecipientsPerMessage { get; init; } = 100;

    /// <summary>A subdomain of a tenant-owned verified domain (mail.example.com under example.com) may send. An explicit record for the subdomain overrides its parent. Default true.</summary>
    public bool AllowSubdomains { get; init; } = true;

    /// <summary>The envelope sender domain must also be owned and usable by the tenant, not only the header From domain. Default true.</summary>
    public bool RequireEnvelopeFromDomainOwned { get; init; } = true;

    /// <summary>Allow the null reverse-path (<c>MAIL FROM:&lt;&gt;</c>) on tenant submissions. Default false: only the bounce role may use it.</summary>
    public bool AllowNullEnvelopeSender { get; init; } = false;
}

/// <summary>A refusal that maps to both an SMTP reply and an API error.</summary>
/// <param name="ApiErrorCode">Stable machine-readable code for the HTTP API problem details.</param>
/// <param name="SmtpCode">SMTP reply code (550 for permanent refusals, 452 for too many recipients).</param>
/// <param name="EnhancedCode">Enhanced status code to send.</param>
/// <param name="Message">Human readable text, safe to return to the client.</param>
public sealed record SenderRejection(string ApiErrorCode, int SmtpCode, string EnhancedCode, string Message)
{
    /// <summary>True when the client may retry later or split the message (4xx).</summary>
    public bool IsTemporary => SmtpCode / 100 == 4;

    /// <summary>The full SMTP reply line text, such as <c>5.7.1 Sender domain example.com is not verified</c>.</summary>
    public string ToSmtpText() => EnhancedCode + " " + Message;
}

/// <summary>The result of <see cref="SenderPolicy.Evaluate"/>.</summary>
/// <param name="IsAllowed">True when the message may be accepted.</param>
/// <param name="SendingDomain">The tenant's registered domain the message is attributed to (used for DKIM, limits and statistics); null when rejected.</param>
/// <param name="ShowTemporaryFailureBanner">True when sending is allowed but a domain is in <see cref="DomainStatus.TemporaryFailure"/> (dashboard banner and alert).</param>
/// <param name="Rejection">Why the message was refused; null when allowed.</param>
public readonly record struct SenderDecision(bool IsAllowed, DomainRecord? SendingDomain, bool ShowTemporaryFailureBanner, SenderRejection? Rejection);

/// <summary>Which return-path (bounce) host to use.</summary>
/// <param name="Host">The bounce host, for example <c>bounces.customer.com</c> or the shared bounce domain.</param>
/// <param name="IsDedicated">True when the tenant's own verified return-path host is used.</param>
/// <param name="Reason">Short constant describing the choice.</param>
public sealed record ReturnPathChoice(string Host, bool IsDedicated, string Reason);

/// <summary>Everything needed to build and sign a VERP return address. Signing and encoding live elsewhere.</summary>
public readonly record struct VerpInputs(string Host, Guid TenantId, Guid MessageId, Guid DeliveryId, EmailAddress Recipient);

/// <summary>
/// Decides whether a tenant may send as a given domain: the domain must be registered to that tenant and verified (or in temporary failure,
/// which still sends with a banner), not paused; unknown or unverified domains get a clear SMTP 5.7.1 and API error code. Also enforces the
/// recipient limit per message and picks the return-path host. Stateless and thread-safe.
/// </summary>
public sealed class SenderPolicy
{
    private readonly SenderPolicyOptions _options;

    /// <summary>Creates the policy.</summary>
    public SenderPolicy(SenderPolicyOptions? options = null)
    {
        _options = options ?? new SenderPolicyOptions();
        if (_options.MaxRecipientsPerMessage < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "MaxRecipientsPerMessage must be at least 1.");
        }
    }

    /// <summary>Checks the sender of a tenant submission.</summary>
    /// <param name="tenant">The authenticated tenant.</param>
    /// <param name="envelopeFrom">The SMTP MAIL FROM (or API envelope sender); <see cref="EmailAddress.Null"/> for the null path.</param>
    /// <param name="headerFromDomain">The domain of the header From address, or null if not yet known.</param>
    /// <param name="tenantDomains">The tenant's registered domains (domains of other tenants are ignored).</param>
    public SenderDecision Evaluate(Tenant tenant, in EmailAddress envelopeFrom, string? headerFromDomain, IReadOnlyList<DomainRecord> tenantDomains)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        ArgumentNullException.ThrowIfNull(tenantDomains);
        if (!tenant.Enabled)
        {
            return Reject(new SenderRejection("tenant_disabled", 550, "5.7.1", "This account is disabled and cannot send mail."));
        }

        bool hasHeader = !string.IsNullOrWhiteSpace(headerFromDomain);
        bool hasEnvelope = !envelopeFrom.IsNull;
        if (!hasEnvelope && !_options.AllowNullEnvelopeSender)
        {
            return Reject(new SenderRejection("null_sender_not_allowed", 550, "5.7.1", "A sender address is required: the null reverse-path is not accepted for submissions."));
        }

        if (!hasEnvelope && !hasHeader)
        {
            return Reject(new SenderRejection("sender_required", 550, "5.7.1", "No sender domain could be determined."));
        }

        DomainRecord? attributed = null;
        bool banner = false;
        if (hasHeader)
        {
            SenderRejection? rejection = Check(tenant.Id, Normalize(headerFromDomain!), tenantDomains, "From header domain", out DomainRecord? record, out bool temporaryFailure);
            if (rejection is not null)
            {
                return Reject(rejection);
            }

            attributed = record;
            banner |= temporaryFailure;
        }

        if (hasEnvelope && (_options.RequireEnvelopeFromDomainOwned || !hasHeader))
        {
            SenderRejection? rejection = Check(tenant.Id, envelopeFrom.Domain, tenantDomains, "envelope sender domain", out DomainRecord? record, out bool temporaryFailure);
            if (rejection is not null)
            {
                return Reject(rejection);
            }

            attributed ??= record;
            banner |= temporaryFailure;
        }

        return new SenderDecision(true, attributed, banner, null);
    }

    /// <summary>Checks the number of recipients of a message (pass the total including the one being added).</summary>
    /// <returns>null when within the limit, otherwise a temporary (452 4.5.3) rejection so SMTP clients split the message.</returns>
    public SenderRejection? CheckRecipientCount(int recipientCount) =>
        recipientCount <= _options.MaxRecipientsPerMessage
            ? null
            : new SenderRejection("too_many_recipients", 452, "4.5.3", $"Too many recipients: at most {_options.MaxRecipientsPerMessage} per message.");

    /// <summary>First label of a sending domain's own return-path host (<c>bounce.example.com</c>): the domain records ask for it, delivery uses it and the bounce listener accepts it.</summary>
    public const string DefaultReturnPathLabel = "bounce";

    /// <summary>
    /// Chooses the return-path host: the tenant's own host when its return-path CNAME is verified, otherwise the shared bounce domain.
    /// </summary>
    /// <param name="sendingDomain">The domain the message is attributed to, or null.</param>
    /// <param name="sharedBounceDomain">The operator's shared bounce domain.</param>
    public static ReturnPathChoice SelectReturnPath(DomainRecord? sendingDomain, string sharedBounceDomain)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sharedBounceDomain);
        if (sendingDomain is { ReturnPathVerified: true, ReturnPathHost: { } host } && !string.IsNullOrWhiteSpace(host))
        {
            return new ReturnPathChoice(Normalize(host), true, "tenant return-path host verified");
        }

        string reason = sendingDomain is null
            ? "no sending domain: shared bounce domain"
            : string.IsNullOrWhiteSpace(sendingDomain.ReturnPathHost)
                ? "no return-path host configured: shared bounce domain"
                : "return-path host not verified: shared bounce domain";
        return new ReturnPathChoice(Normalize(sharedBounceDomain), false, reason);
    }

    /// <summary>Collects the inputs for the VERP return address of one delivery.</summary>
    public static VerpInputs BuildVerpInputs(ClaimedDelivery delivery, ReturnPathChoice returnPath)
    {
        ArgumentNullException.ThrowIfNull(delivery);
        ArgumentNullException.ThrowIfNull(returnPath);
        return new VerpInputs(returnPath.Host, delivery.TenantId, delivery.MessageId, delivery.DeliveryId, delivery.Recipient);
    }

    private SenderRejection? Check(Guid tenantId, string domain, IReadOnlyList<DomainRecord> domains, string what, out DomainRecord? match, out bool temporaryFailure)
    {
        temporaryFailure = false;
        match = Find(tenantId, domain, domains);
        if (match is null)
        {
            return new SenderRejection(
                "sender_domain_not_registered", 550, "5.7.1",
                $"The {what} '{domain}' is not registered to this account. Add and verify the domain in the dashboard before sending from it.");
        }

        switch (match.Status)
        {
            case DomainStatus.Pending:
            case DomainStatus.Verifying:
                return new SenderRejection(
                    "sender_domain_not_verified", 550, "5.7.1",
                    $"The domain '{match.Name}' is not verified yet. Publish its DNS records and wait for verification to complete.");
            case DomainStatus.Failed:
                return new SenderRejection(
                    "sender_domain_verification_failed", 550, "5.7.1",
                    $"Verification of the domain '{match.Name}' failed and sending is blocked. Repair its DNS records and verify again.");
        }

        if (match.SendingPaused)
        {
            return new SenderRejection("sending_paused", 550, "5.7.1", $"Sending is paused for the domain '{match.Name}'.");
        }

        temporaryFailure = match.Status == DomainStatus.TemporaryFailure;
        return null;
    }

    /// <summary>Longest registered name of this tenant that equals <paramref name="domain"/> or (if allowed) is a parent of it.</summary>
    private DomainRecord? Find(Guid tenantId, string domain, IReadOnlyList<DomainRecord> domains)
    {
        DomainRecord? best = null;
        for (int i = 0; i < domains.Count; i++)
        {
            DomainRecord d = domains[i];
            if (d.TenantId != tenantId || (best is not null && d.Name.Length <= best.Name.Length))
            {
                continue;
            }

            if (string.Equals(d.Name, domain, StringComparison.OrdinalIgnoreCase)
                || (_options.AllowSubdomains
                    && domain.Length > d.Name.Length
                    && domain[domain.Length - d.Name.Length - 1] == '.'
                    && domain.EndsWith(d.Name, StringComparison.OrdinalIgnoreCase)))
            {
                best = d;
            }
        }

        return best;
    }

    private static SenderDecision Reject(SenderRejection rejection) => new(false, null, false, rejection);

    private static string Normalize(string host) => host.Trim().TrimEnd('.').ToLowerInvariant();
}
