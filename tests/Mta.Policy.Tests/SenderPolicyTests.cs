using Mta.Core;
using Mta.Storage;

namespace Mta.Policy.Tests;

public class SenderPolicyTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 12, 8, 30, 0, TimeSpan.Zero);
    private static readonly Guid TenantId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid OtherTenantId = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Tenant Acme = new(TenantId, "Acme", "acme", true, T0, false);

    private static DomainRecord Domain(string name, DomainStatus status = DomainStatus.Verified, bool paused = false, Guid? tenant = null, string? returnPath = null, bool returnPathVerified = false) =>
        new(Guid.NewGuid(), tenant ?? TenantId, name, status, returnPath, returnPathVerified, T0, T0, T0, 0, null, paused, null);

    private static EmailAddress Addr(string s) => EmailAddress.Parse(s);

    private readonly SenderPolicy _policy = new();

    [Fact]
    public void Verified_domain_is_allowed_and_attributed()
    {
        var d = Domain("example.com");
        var r = _policy.Evaluate(Acme, Addr("noreply@example.com"), "example.com", [d]);
        Assert.True(r.IsAllowed);
        Assert.Same(d, r.SendingDomain);
        Assert.False(r.ShowTemporaryFailureBanner);
        Assert.Null(r.Rejection);
    }

    [Theory]
    [InlineData(DomainStatus.Pending, "sender_domain_not_verified")]
    [InlineData(DomainStatus.Verifying, "sender_domain_not_verified")]
    [InlineData(DomainStatus.Failed, "sender_domain_verification_failed")]
    public void Unverified_or_failed_domains_block_with_a_clear_5_7_1(DomainStatus status, string code)
    {
        var r = _policy.Evaluate(Acme, Addr("a@example.com"), "example.com", [Domain("example.com", status)]);
        Assert.False(r.IsAllowed);
        Assert.Equal(code, r.Rejection!.ApiErrorCode);
        Assert.Equal(550, r.Rejection.SmtpCode);
        Assert.Equal("5.7.1", r.Rejection.EnhancedCode);
        Assert.False(r.Rejection.IsTemporary);
        Assert.Contains("example.com", r.Rejection.Message);
        Assert.StartsWith("5.7.1 ", r.Rejection.ToSmtpText());
    }

    [Fact]
    public void Temporary_failure_keeps_sending_with_a_banner()
    {
        var r = _policy.Evaluate(Acme, Addr("a@example.com"), "example.com", [Domain("example.com", DomainStatus.TemporaryFailure)]);
        Assert.True(r.IsAllowed);
        Assert.True(r.ShowTemporaryFailureBanner);
    }

    [Fact]
    public void Paused_domain_is_blocked_even_when_verified()
    {
        var r = _policy.Evaluate(Acme, Addr("a@example.com"), "example.com", [Domain("example.com", paused: true)]);
        Assert.False(r.IsAllowed);
        Assert.Equal("sending_paused", r.Rejection!.ApiErrorCode);
    }

    [Fact]
    public void Failed_and_paused_reports_the_verification_failure()
    {
        var r = _policy.Evaluate(Acme, Addr("a@example.com"), "example.com", [Domain("example.com", DomainStatus.Failed, paused: true)]);
        Assert.Equal("sender_domain_verification_failed", r.Rejection!.ApiErrorCode);
    }

    [Fact]
    public void Unknown_domain_is_rejected_with_an_api_code()
    {
        var r = _policy.Evaluate(Acme, Addr("a@unknown.org"), "unknown.org", [Domain("example.com")]);
        Assert.False(r.IsAllowed);
        Assert.Equal("sender_domain_not_registered", r.Rejection!.ApiErrorCode);
        Assert.Equal(550, r.Rejection.SmtpCode);
        Assert.Equal("5.7.1", r.Rejection.EnhancedCode);
        Assert.Null(r.SendingDomain);
    }

    [Fact]
    public void Another_tenants_domain_does_not_count()
    {
        var r = _policy.Evaluate(Acme, Addr("a@example.com"), "example.com", [Domain("example.com", tenant: OtherTenantId)]);
        Assert.Equal("sender_domain_not_registered", r.Rejection!.ApiErrorCode);
    }

    [Fact]
    public void Header_from_must_be_owned_even_if_the_envelope_sender_is()
    {
        var r = _policy.Evaluate(Acme, Addr("bounce@example.com"), "spoofed.org", [Domain("example.com")]);
        Assert.False(r.IsAllowed);
        Assert.Contains("From header", r.Rejection!.Message);
    }

    [Fact]
    public void Envelope_from_must_be_owned_by_default_and_can_be_relaxed()
    {
        var domains = new[] { Domain("example.com") };
        var strict = _policy.Evaluate(Acme, Addr("x@elsewhere.net"), "example.com", domains);
        Assert.False(strict.IsAllowed);
        Assert.Contains("envelope sender", strict.Rejection!.Message);

        var relaxed = new SenderPolicy(new SenderPolicyOptions { RequireEnvelopeFromDomainOwned = false });
        var ok = relaxed.Evaluate(Acme, Addr("x@elsewhere.net"), "example.com", domains);
        Assert.True(ok.IsAllowed);
        Assert.Equal("example.com", ok.SendingDomain!.Name);
    }

    [Fact]
    public void Missing_header_domain_falls_back_to_the_envelope_domain()
    {
        var d = Domain("example.com");
        var r = _policy.Evaluate(Acme, Addr("a@example.com"), null, [d]);
        Assert.True(r.IsAllowed);
        Assert.Same(d, r.SendingDomain);
        Assert.True(_policy.Evaluate(Acme, Addr("a@example.com"), "  ", [d]).IsAllowed);
    }

    [Fact]
    public void Subdomains_of_a_verified_domain_are_allowed_and_attributed_to_the_parent()
    {
        var parent = Domain("example.com");
        var r = _policy.Evaluate(Acme, Addr("a@mail.example.com"), "news.mail.example.com", [parent]);
        Assert.True(r.IsAllowed);
        Assert.Same(parent, r.SendingDomain);
    }

    [Fact]
    public void Lookalike_suffixes_are_not_subdomains()
    {
        var r = _policy.Evaluate(Acme, Addr("a@notexample.com"), "notexample.com", [Domain("example.com")]);
        Assert.False(r.IsAllowed);
        var r2 = _policy.Evaluate(Acme, Addr("a@example.com.evil.org"), "example.com.evil.org", [Domain("example.com")]);
        Assert.False(r2.IsAllowed);
    }

    [Fact]
    public void An_explicit_subdomain_record_overrides_its_parent()
    {
        var parent = Domain("example.com");
        var child = Domain("mail.example.com", DomainStatus.Pending);
        var r = _policy.Evaluate(Acme, Addr("a@mail.example.com"), "mail.example.com", [parent, child]);
        Assert.False(r.IsAllowed);
        Assert.Equal("sender_domain_not_verified", r.Rejection!.ApiErrorCode);

        var verifiedChild = Domain("mail.example.com");
        var ok = _policy.Evaluate(Acme, Addr("a@mail.example.com"), "mail.example.com", [parent, verifiedChild]);
        Assert.Same(verifiedChild, ok.SendingDomain);
    }

    [Fact]
    public void Subdomain_handling_can_be_turned_off()
    {
        var strict = new SenderPolicy(new SenderPolicyOptions { AllowSubdomains = false });
        Assert.False(strict.Evaluate(Acme, Addr("a@mail.example.com"), "mail.example.com", [Domain("example.com")]).IsAllowed);
        Assert.True(strict.Evaluate(Acme, Addr("a@example.com"), "example.com", [Domain("example.com")]).IsAllowed);
    }

    [Fact]
    public void Domain_matching_is_case_insensitive()
    {
        Assert.True(_policy.Evaluate(Acme, Addr("a@Example.COM"), "EXAMPLE.com", [Domain("example.com")]).IsAllowed);
    }

    [Fact]
    public void Banner_is_raised_if_either_domain_is_in_temporary_failure()
    {
        var domains = new[] { Domain("example.com"), Domain("other.com", DomainStatus.TemporaryFailure) };
        var r = _policy.Evaluate(Acme, Addr("a@other.com"), "example.com", domains);
        Assert.True(r.IsAllowed);
        Assert.True(r.ShowTemporaryFailureBanner);
    }

    [Fact]
    public void Disabled_tenant_is_rejected()
    {
        var r = _policy.Evaluate(Acme with { Enabled = false }, Addr("a@example.com"), "example.com", [Domain("example.com")]);
        Assert.Equal("tenant_disabled", r.Rejection!.ApiErrorCode);
    }

    [Fact]
    public void Null_envelope_sender_is_rejected_by_default_and_can_be_allowed()
    {
        var domains = new[] { Domain("example.com") };
        var r = _policy.Evaluate(Acme, EmailAddress.Null, "example.com", domains);
        Assert.Equal("null_sender_not_allowed", r.Rejection!.ApiErrorCode);

        var lenient = new SenderPolicy(new SenderPolicyOptions { AllowNullEnvelopeSender = true });
        Assert.True(lenient.Evaluate(Acme, EmailAddress.Null, "example.com", domains).IsAllowed);
        Assert.Equal("sender_required", lenient.Evaluate(Acme, EmailAddress.Null, null, domains).Rejection!.ApiErrorCode);
    }

    [Fact]
    public void Recipient_limit_is_a_temporary_452_so_clients_split_the_message()
    {
        var p = new SenderPolicy(new SenderPolicyOptions { MaxRecipientsPerMessage = 3 });
        Assert.Null(p.CheckRecipientCount(1));
        Assert.Null(p.CheckRecipientCount(3));
        var r = p.CheckRecipientCount(4)!;
        Assert.Equal("too_many_recipients", r.ApiErrorCode);
        Assert.Equal(452, r.SmtpCode);
        Assert.Equal("4.5.3", r.EnhancedCode);
        Assert.True(r.IsTemporary);
        Assert.Contains("3", r.Message);
        Assert.Null(_policy.CheckRecipientCount(100));
        Assert.NotNull(_policy.CheckRecipientCount(101));
    }

    [Fact]
    public void Invalid_options_are_rejected() =>
        Assert.Throws<ArgumentOutOfRangeException>(() => new SenderPolicy(new SenderPolicyOptions { MaxRecipientsPerMessage = 0 }));

    [Fact]
    public void Return_path_uses_the_verified_tenant_host_otherwise_the_shared_bounce_domain()
    {
        var dedicated = Domain("example.com", returnPath: "Bounces.Example.com.", returnPathVerified: true);
        var choice = SenderPolicy.SelectReturnPath(dedicated, "bounce.eggmail.example");
        Assert.True(choice.IsDedicated);
        Assert.Equal("bounces.example.com", choice.Host);

        var unverified = Domain("example.com", returnPath: "bounces.example.com", returnPathVerified: false);
        var c2 = SenderPolicy.SelectReturnPath(unverified, "Bounce.EggMail.example");
        Assert.False(c2.IsDedicated);
        Assert.Equal("bounce.eggmail.example", c2.Host);
        Assert.Contains("not verified", c2.Reason);

        var none = SenderPolicy.SelectReturnPath(Domain("example.com"), "bounce.eggmail.example");
        Assert.False(none.IsDedicated);
        Assert.Contains("no return-path host", none.Reason);

        var noDomain = SenderPolicy.SelectReturnPath(null, "bounce.eggmail.example");
        Assert.Equal("bounce.eggmail.example", noDomain.Host);

        var blank = Domain("example.com", returnPath: "  ", returnPathVerified: true);
        Assert.False(SenderPolicy.SelectReturnPath(blank, "bounce.eggmail.example").IsDedicated);
        Assert.Throws<ArgumentException>(() => SenderPolicy.SelectReturnPath(null, " "));
    }

    [Fact]
    public void Verp_inputs_come_from_the_delivery_and_the_chosen_host()
    {
        var delivery = new ClaimedDelivery
        {
            DeliveryId = Guid.NewGuid(),
            MessageId = Guid.NewGuid(),
            TenantId = TenantId,
            EnvelopeFrom = Addr("a@example.com"),
            Recipient = Addr("to@dest.example"),
            RecipientDomain = "dest.example",
            Attempt = 0,
            CreatedAt = T0,
            ExpiresAt = T0.AddDays(5),
            LeaseUntil = T0.AddMinutes(5),
        };
        var choice = SenderPolicy.SelectReturnPath(null, "bounce.eggmail.example");
        var verp = SenderPolicy.BuildVerpInputs(delivery, choice);
        Assert.Equal("bounce.eggmail.example", verp.Host);
        Assert.Equal(delivery.DeliveryId, verp.DeliveryId);
        Assert.Equal(delivery.MessageId, verp.MessageId);
        Assert.Equal(TenantId, verp.TenantId);
        Assert.Equal(delivery.Recipient, verp.Recipient);
    }
}
