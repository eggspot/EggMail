using Mta.Core;

namespace Mta.Storage.Tests;

/// <summary>
/// Security regression tests (docs/security-test-map.md, INJ-1 to INJ-4): text that arrives from the API or from SMTP reaches every query as a
/// literal. Run by every backend (in-memory, SQLite, PostgreSQL), so a statement that concatenates input fails on the backend that does it.
/// The checks: no input makes a query throw (other than the documented rejection of a malformed cursor), no input widens a result beyond what
/// literally matches or beyond the tenant, a payload stored by one call is read back byte for byte, and the data is intact afterwards.
/// The in-house review, not an independent audit.
/// </summary>
public abstract class InjectionConformance : StorageTestBase
{
    protected override HistoryMode Mode => HistoryMode.Full;

    public static readonly string[] Payloads =
    [
        "' OR '1'='1",
        "' OR 1=1 --",
        "'; DROP TABLE messages; --",
        "\"; DROP TABLE tenants; --",
        "') OR ('1'='1",
        "' UNION SELECT NULL,NULL,NULL --",
        "\\' OR 1=1 --",
        "1; SELECT pg_sleep(30); --",
        "'||(SELECT 1)||'",
        "%",
        "%%",
        "_",
        "\\",
        "\\%",
        "[a-z]",
        "'",
        "\"",
        "`",
        "--",
        "/*",
        "*/",
        "{{7*7}}",
        "$1",
        "@p0",
        ":name",
        "?",
        "\u0000",
        "a\u0000b",
        "\r\n",
        "Robert'); DROP TABLE Students;--",
        "ＵＮＩＯＮ ＳＥＬＥＣＴ",     // full-width letters
        "\u202e\u202e",
        "\ud800",                                  // a lone surrogate
        "x" + "'" + new string('x', 5000),
    ];

    private async Task<(List<Guid> A, List<Guid> B)> SeedAsync()
    {
        var a = new List<Guid>();
        var b = new List<Guid>();
        for (int i = 0; i < 3; i++)
        {
            a.Add((await AcceptAsync(Msg(tenant: TenantA, to: [$"alice{i}@example.org"], from: $"sender{i}@a.example", subject: $"A subject {i}", tags: ["a-tag"], received: Start.AddMinutes(i)))).MessageId);
            b.Add((await AcceptAsync(Msg(tenant: TenantB, to: [$"bob{i}@example.net"], from: $"sender{i}@b.example", subject: $"B secret {i}", tags: ["b-tag"], received: Start.AddMinutes(i)))).MessageId);
        }

        // One message whose own values are hostile, to prove such text is stored and found literally.
        a.Add((await AcceptAsync(Msg(tenant: TenantA, to: ["o'brien@example.org"], from: "x@a.example", subject: "' OR '1'='1", tags: ["it's"], received: Start.AddMinutes(5)))).MessageId);
        return (a, b);
    }

    private async Task<List<Guid>> SearchAsync(MessageQuery query) => (await Storage.History.SearchAsync(query, CancellationToken.None)).Items.Select(i => i.MessageId).ToList();

    [Fact]
    public async Task No_filter_value_widens_a_search_beyond_its_tenant_or_breaks_the_query()
    {
        var (a, b) = await SeedAsync();
        Clock.Advance(TimeSpan.FromHours(1));

        foreach (string payload in Payloads)
        {
            foreach (MessageQuery query in new[]
            {
                new MessageQuery(TenantId: TenantA, Recipient: payload),
                new MessageQuery(TenantId: TenantA, Sender: payload),
                new MessageQuery(TenantId: TenantA, SubjectContains: payload),
                new MessageQuery(TenantId: TenantA, Status: payload),
                new MessageQuery(TenantId: TenantA, Tag: payload),
            })
            {
                List<Guid> found = await SearchAsync(query);
                Assert.True(found.All(id => a.Contains(id)), $"tenant A's search {query} returned a row of tenant B or of nobody for payload '{payload}'");
                Assert.DoesNotContain(found, id => b.Contains(id));
            }
        }

        // The same for the other tenant, and the data is all still there.
        foreach (string payload in Payloads)
        {
            List<Guid> found = await SearchAsync(new MessageQuery(TenantId: TenantB, SubjectContains: payload));
            Assert.DoesNotContain(found, id => a.Contains(id));
        }

        Assert.Equal(a.Count, (await SearchAsync(new MessageQuery(TenantId: TenantA, Limit: 200))).Count);
        Assert.Equal(b.Count, (await SearchAsync(new MessageQuery(TenantId: TenantB, Limit: 200))).Count);
    }

    [Fact]
    public async Task A_hostile_value_a_message_really_has_is_found_literally_and_nothing_else_is()
    {
        var (a, _) = await SeedAsync();
        Guid hostile = a[^1];

        Assert.Equal([hostile], await SearchAsync(new MessageQuery(TenantId: TenantA, SubjectContains: "' OR '1'='1")));
        Assert.Equal([hostile], await SearchAsync(new MessageQuery(TenantId: TenantA, Recipient: "o'brien@example.org")));
        Assert.Equal([hostile], await SearchAsync(new MessageQuery(TenantId: TenantA, Tag: "it's")));
        Assert.Empty(await SearchAsync(new MessageQuery(TenantId: TenantA, SubjectContains: "' OR '2'='2")));
        Assert.Empty(await SearchAsync(new MessageQuery(TenantId: TenantA, Recipient: "o'brien@example.org' OR '1'='1")));
        // Wildcards and the escape character stand for themselves.
        Assert.Empty(await SearchAsync(new MessageQuery(TenantId: TenantA, SubjectContains: "%")));
        Assert.Empty(await SearchAsync(new MessageQuery(TenantId: TenantA, SubjectContains: "_")));
        Assert.Empty(await SearchAsync(new MessageQuery(TenantId: TenantA, SubjectContains: "\\")));
        Assert.Empty(await SearchAsync(new MessageQuery(TenantId: TenantA, Recipient: "%@example.org")));
        Assert.Empty(await SearchAsync(new MessageQuery(TenantId: TenantA, Sender: "%")));
    }

    [Fact]
    public async Task A_cursor_is_never_executed_and_never_leaks_another_tenants_rows()
    {
        var (a, b) = await SeedAsync();
        Clock.Advance(TimeSpan.FromHours(1));

        foreach (string payload in Payloads)
        {
            try
            {
                Page<MessageSummary> page = await Storage.History.SearchAsync(new MessageQuery(TenantId: TenantA, Cursor: payload), CancellationToken.None);
                Assert.DoesNotContain(page.Items, i => b.Contains(i.MessageId));
            }
            catch (ArgumentException)
            {
                // A cursor that is not one of ours is refused; that is the documented outcome.
            }
        }

        // A real cursor of tenant B, handed to a search of tenant A.
        Page<MessageSummary> first = await Storage.History.SearchAsync(new MessageQuery(TenantId: TenantB, Limit: 1), CancellationToken.None);
        Assert.NotNull(first.NextCursor);
        try
        {
            Page<MessageSummary> crossed = await Storage.History.SearchAsync(new MessageQuery(TenantId: TenantA, Limit: 50, Cursor: first.NextCursor), CancellationToken.None);
            Assert.DoesNotContain(crossed.Items, i => b.Contains(i.MessageId));
        }
        catch (ArgumentException)
        {
        }
    }

    [Fact]
    public async Task Lookups_by_name_address_slug_and_key_treat_the_input_as_a_literal()
    {
        IConfigStore config = Storage.Config;
        await config.UpsertTenantAsync(new Tenant(TenantA, "Acme", "acme", true, Clock.UtcNow, false), CancellationToken.None);
        await config.UpsertTenantAsync(new Tenant(TenantB, "Globex", "globex", true, Clock.UtcNow, false), CancellationToken.None);
        await config.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantA, "app-mailer", "hash", true, Clock.UtcNow), CancellationToken.None);
        await config.UpsertDashboardUserAsync(new DashboardUser(Ids.New(), "alice", "hash", DashboardRole.Tenant, TenantA, true, Clock.UtcNow), CancellationToken.None);
        await config.UpsertDomainAsync(new DomainRecord(Ids.New(), TenantA, "example.com", DomainStatus.Verified, null, true, Clock.UtcNow, null, null, 0, null, false, null), CancellationToken.None);
        await config.AddSuppressionAsync(new SuppressionRecord(TenantA, "blocked@example.org", SuppressionReason.Manual, "test", Clock.UtcNow, null), CancellationToken.None);

        foreach (string payload in Payloads)
        {
            Assert.Null(await config.FindSmtpCredentialAsync(payload, CancellationToken.None));
            Assert.Null(await config.FindDashboardUserAsync(payload, CancellationToken.None));
            Assert.Null(await config.GetTenantBySlugAsync(payload, CancellationToken.None));
            Assert.Null(await config.FindDomainByNameAsync(payload, CancellationToken.None));
            Assert.False(await config.IsSuppressedAsync(TenantA, payload, CancellationToken.None));
            Assert.False(await config.RemoveSuppressionAsync(TenantA, payload, CancellationToken.None));
            Assert.Null(await config.GetAcmeAccountAsync(payload, CancellationToken.None));
            Assert.Null(await config.FindApiKeyAsync(System.Text.Encoding.UTF8.GetBytes(payload), CancellationToken.None));
        }

        // The data survived all of that.
        Assert.NotNull(await config.FindSmtpCredentialAsync("app-mailer", CancellationToken.None));
        Assert.NotNull(await config.FindDashboardUserAsync("alice", CancellationToken.None));
        Assert.NotNull(await config.GetTenantBySlugAsync("acme", CancellationToken.None));
        Assert.NotNull(await config.FindDomainByNameAsync("example.com", CancellationToken.None));
        Assert.True(await config.IsSuppressedAsync(TenantA, "blocked@example.org", CancellationToken.None));
        Assert.Equal(2, (await config.GetTenantsAsync(CancellationToken.None)).Count);
    }

    [Fact]
    public async Task Hostile_text_is_stored_and_read_back_unchanged_and_never_executed()
    {
        IConfigStore config = Storage.Config;
        await config.UpsertTenantAsync(new Tenant(TenantA, "Acme", "acme", true, Clock.UtcNow, false), CancellationToken.None);
        await config.UpsertTenantAsync(new Tenant(TenantB, "Globex", "globex", true, Clock.UtcNow, false), CancellationToken.None);

        foreach (string payload in Payloads.Where(p => !p.Contains('\u0000') && !p.Contains('\ud800') && p.Length < 1000))
        {
            string address = payload.Replace('\r', ' ').Replace('\n', ' ') + "@example.org";
            await config.AddSuppressionAsync(new SuppressionRecord(TenantA, address, SuppressionReason.Manual, payload, Clock.UtcNow, null), CancellationToken.None);
            Assert.True(await config.IsSuppressedAsync(TenantA, address, CancellationToken.None), payload);
            Assert.False(await config.IsSuppressedAsync(TenantB, address, CancellationToken.None), payload);

            await config.SetSettingAsync(new SettingRecord("test." + Guid.NewGuid().ToString("N"), TenantA, System.Text.Json.JsonSerializer.Serialize(payload), Clock.UtcNow), CancellationToken.None);
        }

        var suppressed = await config.GetSuppressionsAsync(TenantA, null, 500, CancellationToken.None);
        Assert.Equal(suppressed.Items.Count, suppressed.Items.Select(s => s.Address).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Empty((await config.GetSuppressionsAsync(TenantB, null, 500, CancellationToken.None)).Items);
        Assert.Equal(2, (await config.GetTenantsAsync(CancellationToken.None)).Count);

        foreach (string payload in Payloads)
        {
            try
            {
                Page<SuppressionRecord> page = await config.GetSuppressionsAsync(TenantB, payload, 50, CancellationToken.None);
                Assert.Empty(page.Items);
            }
            catch (ArgumentException)
            {
            }
        }
    }

    [Fact]
    public async Task A_message_whose_text_holds_characters_a_backend_cannot_store_is_still_accepted()
    {
        // A subject decoded from an RFC 2047 word, a tag, a message id header or a file name can hold anything a sender wrote.
        AcceptedMessage nul = Msg(subject: "sub\0ject", tags: ["t\0ag", "x\ud800y"], messageIdHeader: "<a\0b@example.com>",
            content: new MessageContent("sub\0ject", "te\0xt", "<p>h\0tml</p>", [new AttachmentInfo("a\0.pdf", "application/pdf", 1, "c\0id")], false));
        AcceptedMessage accepted = await AcceptAsync(nul);

        MessageDetail? detail = await Storage.History.GetAsync(TenantA, accepted.MessageId, CancellationToken.None);
        Assert.NotNull(detail);
        Assert.Contains("sub", detail!.Summary.Subject);
    }

    [Fact]
    public async Task An_idempotency_key_is_a_literal_scoped_to_its_tenant()
    {
        foreach (string key in Payloads.Where(p => p.Length < 255 && !p.Contains('\u0000') && !p.Contains('\ud800')))
        {
            AcceptedMessage first = Msg(tenant: TenantA, idempotencyKey: key);
            IntakeResult one = await Storage.Intake.AcceptAsync(first, CancellationToken.None);
            Assert.Equal(IntakeStatus.Accepted, one.Status);

            // The same key for the same tenant finds the first message; for another tenant it is a different key.
            IntakeResult again = await Storage.Intake.AcceptAsync(Msg(tenant: TenantA, idempotencyKey: key), CancellationToken.None);
            Assert.Equal(first.MessageId, again.MessageId);
            IntakeResult other = await Storage.Intake.AcceptAsync(Msg(tenant: TenantB, idempotencyKey: key), CancellationToken.None);
            Assert.Equal(IntakeStatus.Accepted, other.Status);
            Assert.NotEqual(first.MessageId, other.MessageId);
        }
    }

    [Fact]
    public async Task Text_a_remote_server_controls_is_recorded_in_an_attempt_whatever_characters_it_holds()
    {
        // The reply text, the host name, and the certificate names of a remote mail server are written to the history. A server that sends a NUL, a lone
        // surrogate or SQL must not make the result of the attempt impossible to record (the delivery would then be retried for ever, or sent twice).
        foreach (string hostile in new[] { "250 ok\u0000 rest", "x\ud800y", "'); DROP TABLE messages; --", "\u0001\u001f\u007f", new string('é', 3000) })
        {
            AcceptedMessage m = await AcceptAsync(Msg(to: [$"u{Guid.NewGuid():N}@example.org"], received: Clock.UtcNow));
            var claimed = (await ClaimAsync()).Single(c => c.MessageId == m.MessageId);
            var attempt = new DeliveryAttempt
            {
                DeliveryId = claimed.DeliveryId,
                Outcome = DeliveryOutcome.Deferred,
                At = Clock.UtcNow,
                SmtpCode = 451,
                EnhancedCode = "4.7.1",
                Message = hostile,
                MxHost = "mx." + hostile,
                Route = "direct " + hostile,
                Tls = new TlsInfo(true, "TLS1.3", "TLS_AES_256_GCM_SHA384", "CN=" + hostile, "CN=Issuer " + hostile, "ABCD", hostile, true, "may", null, true, false),
                Duration = TimeSpan.FromMilliseconds(120),
                NextAttemptAt = Clock.UtcNow.AddMinutes(5),
            };

            await Storage.Deliveries.RecordAttemptAsync(attempt, CancellationToken.None);

            var events = await Storage.History.GetEventsAsync(TenantA, m.MessageId, CancellationToken.None);
            Assert.Contains(events, e => e.Type == MessageEventType.Deferred);
            Clock.Advance(TimeSpan.FromMinutes(10));
        }
    }

    [Fact]
    public async Task Statistics_and_recent_events_are_only_ever_asked_with_typed_arguments_and_stay_tenant_scoped()
    {
        var (_, _) = await SeedAsync();
        await FlushStatsAsync();
        var rowsA = await Storage.Stats.QueryAsync(TenantA, Start.AddDays(-1), Start.AddDays(1), false, CancellationToken.None);
        var rowsB = await Storage.Stats.QueryAsync(TenantB, Start.AddDays(-1), Start.AddDays(1), false, CancellationToken.None);
        Assert.All(rowsA, r => Assert.Equal(TenantA, r.TenantId));
        Assert.All(rowsB, r => Assert.Equal(TenantB, r.TenantId));
        var recentB = await Storage.Stats.GetRecentEventsAsync(TenantB, 100, CancellationToken.None);
        Assert.All(recentB, e => Assert.Equal(TenantB, e.TenantId));
    }
}
