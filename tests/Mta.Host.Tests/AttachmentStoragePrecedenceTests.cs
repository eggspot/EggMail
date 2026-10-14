using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Ingest;
using Mta.Host.Security;
using Mta.Host.Submission;
using Mta.Policy;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests;

/// <summary>
/// Whether the raw message with its attachments is kept (design section 5): the per-send flag, then the tenant's setting, then the global default,
/// behind the master switch; SMTP has no per-send flag. A tenant that chose "no" overrides a global "yes".
/// </summary>
public class AttachmentStoragePrecedenceTests : IAsyncLifetime
{
    private static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private InMemoryStorage _storage = null!;

    public async Task InitializeAsync()
    {
        _storage = new InMemoryStorage(new StorageOptions());
        await _storage.InitializeAsync(default);
        var now = DateTimeOffset.UtcNow;
        await _storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, now, false), default);
        await _storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantId, "example.org", DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
    }

    public async Task DisposeAsync() => await _storage.DisposeAsync();

    internal static byte[] MessageWithAttachment()
    {
        var m = new MimeMessage();
        m.From.Add(MailboxAddress.Parse("news@example.org"));
        m.To.Add(MailboxAddress.Parse("rcpt@dest.example"));
        m.Subject = "With a file";
        var body = new BodyBuilder { TextBody = "see attached" };
        body.Attachments.Add("a.bin", [1, 2, 3, 4], new ContentType("application", "octet-stream"));
        m.Body = body.ToMessageBody();
        using var ms = new MemoryStream();
        m.WriteTo(new FormatOptions { NewLineFormat = NewLineFormat.Dos }, ms);
        return ms.ToArray();
    }

    private async Task SetTenantAsync(bool? choice, bool legacyColumn = false)
    {
        if (choice is { } c)
        {
            await _storage.Config.SetSettingAsync(new SettingRecord(AttachmentStoragePolicy.StoreAttachmentsKey, TenantId, c ? "true" : "false", DateTimeOffset.UtcNow), default);
        }

        if (legacyColumn)
        {
            await _storage.Config.UpsertTenantAsync(new Tenant(TenantId, "Acme", "acme", true, DateTimeOffset.UtcNow, true), default);
        }
    }

    private SubmissionService NewSubmissionService(bool globalDefault, bool masterSwitch) => new(
        _storage, SystemClock.Instance, new SenderPolicy(),
        new StorageOptions { Content = new ContentOptions { AllowAttachmentStorage = masterSwitch, StoreAttachments = globalDefault } },
        new SubmissionOptions { MessageIdDomain = "egg.test" });

    private async Task<bool> IsRawRetainedAsync(MessageSource source, bool? perSendFlag, bool globalDefault, bool masterSwitch, SubmissionService? service = null)
    {
        SubmissionService submission = service ?? NewSubmissionService(globalDefault, masterSwitch);
        Tenant tenant = (await _storage.Config.GetTenantAsync(TenantId, default))!;
        SubmissionResult result = await submission.SubmitAsync(new SubmissionRequest
        {
            Tenant = tenant,
            Source = source,
            EnvelopeFrom = EmailAddress.Parse("news@example.org"),
            Recipients = [EmailAddress.Parse("rcpt@dest.example")],
            Message = MessageWithAttachment(),
            StoreAttachments = perSendFlag,
        }, default);
        Assert.True(result.IsAccepted, result.Detail);
        foreach (ClaimedDelivery d in await _storage.Deliveries.ClaimAsync("t", 10, DateTimeOffset.UtcNow.AddSeconds(1), TimeSpan.FromMinutes(1), default))
        {
            await _storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt { DeliveryId = d.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = DateTimeOffset.UtcNow, SmtpCode = 250 }, default);
        }

        return (await _storage.History.GetAsync(TenantId, result.MessageId, default))!.RawRetained;
    }

    [Theory]
    // source, per-send flag, tenant choice, global default, master switch -> kept
    [InlineData(MessageSource.Smtp, null, null, false, true, false)]    // nobody asked: not kept
    [InlineData(MessageSource.Smtp, null, null, true, true, true)]      // the tenant never chose: the global default applies
    [InlineData(MessageSource.Smtp, null, true, false, true, true)]     // SMTP uses the tenant's setting
    [InlineData(MessageSource.Smtp, null, false, true, true, false)]    // a tenant that chose "no" overrides a global "yes"
    [InlineData(MessageSource.Api, null, false, true, true, false)]     // the same on the API (this was `tenant || global`)
    [InlineData(MessageSource.Api, null, true, false, true, true)]
    [InlineData(MessageSource.Api, true, false, false, true, true)]     // the per-send flag beats the tenant's setting...
    [InlineData(MessageSource.Api, false, true, true, true, false)]     // ...in both directions
    [InlineData(MessageSource.Api, null, true, true, false, false)]     // the master switch decides first
    [InlineData(MessageSource.Smtp, null, true, true, false, false)]
    public async Task The_precedence_is_per_send_then_tenant_then_global_behind_the_master_switch(MessageSource source, bool? perSend, bool? tenantChoice, bool global, bool master, bool kept)
    {
        await SetTenantAsync(tenantChoice);
        Assert.Equal(kept, await IsRawRetainedAsync(source, perSend, global, master));
    }

    [Fact]
    public async Task A_tenant_that_only_has_the_older_column_set_to_true_counts_as_having_chosen_yes()
    {
        await SetTenantAsync(choice: null, legacyColumn: true);
        Assert.True(await IsRawRetainedAsync(MessageSource.Smtp, null, globalDefault: false, masterSwitch: true));
    }

    [Fact]
    public async Task A_row_that_says_no_beats_the_older_column_that_says_yes()
    {
        await SetTenantAsync(choice: false, legacyColumn: true);
        Assert.False(await IsRawRetainedAsync(MessageSource.Smtp, null, globalDefault: true, masterSwitch: true));
    }

    [Fact]
    public async Task The_tenant_row_is_cached_briefly_and_a_change_made_through_the_settings_service_shows_at_once()
    {
        SubmissionService service = NewSubmissionService(globalDefault: false, masterSwitch: true);
        Assert.False(await IsRawRetainedAsync(MessageSource.Smtp, null, false, true, service));   // nothing chosen: the default (off) applies, and the row (absent) is remembered

        await SetTenantAsync(choice: true);   // changed behind the cache, as another replica would
        Assert.False(await IsRawRetainedAsync(MessageSource.Smtp, null, false, true, service));

        AttachmentStoragePolicy.Bump();       // what SettingsService does after it writes the row
        Assert.True(await IsRawRetainedAsync(MessageSource.Smtp, null, false, true, service));
    }

    [Fact]
    public void TenantSetting_distinguishes_not_chosen_from_chosen_no()
    {
        var tenant = new Tenant(TenantId, "Acme", "acme", true, DateTimeOffset.UtcNow, false);
        Assert.Null(AttachmentStoragePolicy.TenantSetting(tenant, []));
        Assert.False(AttachmentStoragePolicy.TenantSetting(tenant, [new SettingRecord(AttachmentStoragePolicy.StoreAttachmentsKey, TenantId, "false", DateTimeOffset.UtcNow)]));
        Assert.Null(AttachmentStoragePolicy.TenantSetting(tenant, [new SettingRecord(AttachmentStoragePolicy.StoreAttachmentsKey, Guid.NewGuid(), "true", DateTimeOffset.UtcNow)]));   // another tenant's row
        Assert.Null(AttachmentStoragePolicy.TenantSetting(tenant, [new SettingRecord(AttachmentStoragePolicy.StoreAttachmentsKey, TenantId, "\"yes\"", DateTimeOffset.UtcNow)]));   // not a boolean: ignored
    }
}
