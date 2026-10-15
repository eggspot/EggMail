using System.Text;
using Mta.Core;
using Mta.Host.Submission;
using Mta.Policy;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Host.Tests;

/// <summary>
/// The submission path reuses its stored-message objects, parse buffers, content types and writer commands. These tests run it on the real SQLite writer with many
/// submissions at once, for two tenants, and read every message back: nothing of one message may appear in another, whatever the interleaving, and a
/// submission that fails or is cancelled must hand its objects back without leaving anything behind.
/// </summary>
public sealed class SubmissionAliasingTests : IAsyncLifetime
{
    private static readonly Guid TenantA = Guid.Parse("a0000000-0000-7000-8000-0000000000a1");
    private static readonly Guid TenantB = Guid.Parse("b0000000-0000-7000-8000-0000000000b2");

    private string _dir = "";
    private SqliteStorage _storage = null!;
    private SubmissionService _service = null!;
    private Tenant _a = null!;
    private Tenant _b = null!;

    public Task InitializeAsync() => InitializeAsync(writerQueueCapacity: null);

    private async Task InitializeAsync(int? writerQueueCapacity)
    {
        if (_storage is not null)
        {
            await _storage.DisposeAsync();
            TryDelete();
        }

        _dir = Path.Combine(Path.GetTempPath(), "eggmail-alias-" + Guid.NewGuid().ToString("N"));
        var sqlite = writerQueueCapacity is { } capacity
            ? new SqliteOptions { DataDirectory = _dir, SyncMode = SqliteSyncMode.Off, WriterQueueCapacity = capacity }
            : new SqliteOptions { DataDirectory = _dir, SyncMode = SqliteSyncMode.Off };
        var options = new StorageOptions { Sqlite = sqlite };
        _storage = SqliteStorage.Create(options);
        await _storage.InitializeAsync(default);
        var now = DateTimeOffset.UtcNow;
        _a = new Tenant(TenantA, "A", "a", true, now, false);
        _b = new Tenant(TenantB, "B", "b", true, now, false);
        foreach (var (tenant, domain) in new[] { (_a, "a.example"), (_b, "b.example") })
        {
            await _storage.Config.UpsertTenantAsync(tenant, default);
            await _storage.Config.UpsertDomainAsync(new DomainRecord(Ids.New(), tenant.Id, domain, DomainStatus.Verified, null, false, now, now, now, 0, null, false, null), default);
        }

        _service = new SubmissionService(_storage, SystemClock.Instance, new SenderPolicy(), options, new SubmissionOptions { MessageIdDomain = "egg.test" });
    }

    public async Task DisposeAsync()
    {
        await _storage.DisposeAsync();
        TryDelete();
    }

    private void TryDelete()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    private static SubmissionRequest Request(Tenant tenant, string fromDomain, string tag, string[] recipients, string? idempotencyKey = null)
    {
        string text = $"From: sender@{fromDomain}\r\nTo: {string.Join(", ", recipients)}\r\nSubject: Subject {tag}\r\nMessage-ID: <{tag}@{fromDomain}>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nBody of {tag} café {new string('x', tag.Length * 7)}\r\n";
        return new SubmissionRequest
        {
            Tenant = tenant,
            Source = MessageSource.Smtp,
            EnvelopeFrom = EmailAddress.Parse($"sender@{fromDomain}"),
            Recipients = recipients.Select(r => EmailAddress.Parse(r)).ToList(),
            Message = Encoding.UTF8.GetBytes(text),
            ReceivedHeader = Encoding.ASCII.GetBytes($"Received: from client.test ([127.0.0.1])\r\n\tby egg.test with ESMTPA id {tag};\r\n\tMon, 12 Oct 2026 08:00:00 +0000\r\n"),
            IdempotencyKey = idempotencyKey,
        };
    }

    [Fact]
    public async Task Truly_parallel_submissions_for_two_tenants_on_the_sqlite_writer_keep_every_message_apart()
    {
        const int count = 240;
        var expected = new (string Tag, Tenant Tenant, string[] Recipients)[count];
        for (int i = 0; i < count; i++)
        {
            var tenant = i % 2 == 0 ? _a : _b;
            string domain = i % 2 == 0 ? "a.example" : "b.example";
            expected[i] = ($"m{i}-{(i % 2 == 0 ? "a" : "b")}", tenant, Enumerable.Range(0, 1 + (i % 3)).Select(r => $"rcpt{i}-{r}@dest{i % 5}.example").ToArray());
            _ = domain;
        }

        using var start = new ManualResetEventSlim();
        var tasks = expected.Select(e => Task.Run(async () =>
        {
            start.Wait();
            string domain = e.Tenant.Id == TenantA ? "a.example" : "b.example";
            return await _service.SubmitAsync(Request(e.Tenant, domain, e.Tag, e.Recipients), default);
        })).ToArray();
        start.Set();
        var results = await Task.WhenAll(tasks);

        Assert.All(results, r => Assert.Equal(SubmissionStatus.Accepted, r.Status));
        Assert.Equal(count, results.Select(r => r.MessageId).Distinct().Count());
        var claimed = await _storage.Deliveries.ClaimAsync("test", 1000, DateTimeOffset.UtcNow.AddMinutes(1), TimeSpan.FromMinutes(1), default);
        Assert.Equal(expected.Sum(e => e.Recipients.Length), claimed.Count);

        for (int i = 0; i < count; i++)
        {
            var (tag, tenant, recipients) = expected[i];
            var id = results[i].MessageId;
            string domain = tenant.Id == TenantA ? "a.example" : "b.example";

            string raw = Encoding.UTF8.GetString((await _storage.Deliveries.GetRawAsync(id, default))!);
            Assert.StartsWith($"Received: from client.test ([127.0.0.1])\r\n\tby egg.test with ESMTPA id {tag};", raw, StringComparison.Ordinal);
            Assert.Contains($"Subject: Subject {tag}\r\n", raw, StringComparison.Ordinal);
            Assert.Contains($"Body of {tag} café {new string('x', tag.Length * 7)}\r\n", raw, StringComparison.Ordinal);
            Assert.Equal(1, raw.Split("Received: ").Length - 1);

            Assert.Equal(recipients.OrderBy(r => r), claimed.Where(c => c.MessageId == id).Select(c => c.Recipient.ToString()).OrderBy(r => r));
            Assert.All(claimed.Where(c => c.MessageId == id), c =>
            {
                Assert.Equal(tenant.Id, c.TenantId);
                Assert.Equal($"sender@{domain}", c.EnvelopeFrom.ToString());
                Assert.Equal(domain, c.SendingDomain);
            });

            var detail = (await _storage.History.GetAsync(tenant.Id, id, default))!;
            Assert.Equal($"Subject {tag}", detail.Content!.Subject);
            Assert.Equal($"Body of {tag} café {new string('x', tag.Length * 7)}\r\n", detail.Content.Text);
            Assert.Equal(recipients.Select(r => r.ToLowerInvariant()).OrderBy(r => r), detail.Recipients.OrderBy(r => r));
            Assert.Null(await _storage.History.GetAsync(tenant.Id == TenantA ? TenantB : TenantA, id, default));   // the other tenant cannot see it
        }
    }

    [Fact]
    public async Task A_submission_cancelled_while_the_writer_queue_is_full_leaves_nothing_behind_and_later_ones_are_unaffected()
    {
        await InitializeAsync(writerQueueCapacity: 2);
        var writer = _storage.Runtime.QueueWriter;
        var started = new ManualResetEventSlim();
        var release = new ManualResetEventSlim();
        Task blocked = writer.SubmitAsync((started, release), static (_, s) =>
        {
            s.started.Set();
            s.release.Wait();
            return 0;
        }).AsTask();
        Assert.True(started.Wait(TimeSpan.FromSeconds(10)));

        // Enough submissions to fill the queue and make more wait for space; then one that carries an idempotency key and gives up.
        var waiting = Enumerable.Range(0, 6).Select(i => _service.SubmitAsync(Request(_a, "a.example", $"wait{i}", [$"w{i}@dest.example"]), default).AsTask()).ToList();
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (writer.PendingCommands < 2 && DateTime.UtcNow < deadline)
        {
            await Task.Yield();
        }

        Assert.Equal(2, writer.PendingCommands);
        using var cts = new CancellationTokenSource();
        var cancelled = _service.SubmitAsync(Request(_a, "a.example", "cancelled", ["cancelled@dest.example"], idempotencyKey: "stale-key"), cts.Token).AsTask();
        Assert.False(cancelled.IsCompleted);
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await cancelled);

        release.Set();
        await blocked;
        var waited = await Task.WhenAll(waiting);
        Assert.All(waited, r => Assert.Equal(SubmissionStatus.Accepted, r.Status));

        // The objects the cancelled submission used went back to the pool: later submissions carry none of its values (not its key, so none is taken for a repeat).
        var later = new List<SubmissionResult>();
        for (int i = 0; i < 12; i++)
        {
            later.Add(await _service.SubmitAsync(Request(i % 2 == 0 ? _a : _b, i % 2 == 0 ? "a.example" : "b.example", $"later{i}", [$"l{i}@dest.example"]), default));
        }

        Assert.All(later, r => Assert.Equal(SubmissionStatus.Accepted, r.Status));
        var claimed = await _storage.Deliveries.ClaimAsync("test", 1000, DateTimeOffset.UtcNow.AddMinutes(1), TimeSpan.FromMinutes(1), default);
        Assert.DoesNotContain(claimed, c => c.Recipient.ToString() == "cancelled@dest.example");
        Assert.Equal(waited.Length + later.Count, claimed.Count);
        for (int i = 0; i < later.Count; i++)
        {
            string raw = Encoding.UTF8.GetString((await _storage.Deliveries.GetRawAsync(later[i].MessageId, default))!);
            Assert.Contains($"Subject: Subject later{i}\r\n", raw, StringComparison.Ordinal);
            Assert.DoesNotContain("cancelled", raw, StringComparison.Ordinal);
            Assert.Equal($"l{i}@dest.example", Assert.Single(claimed, c => c.MessageId == later[i].MessageId).Recipient.ToString());
        }

        // The key of the cancelled submission was never used: the same key is accepted now.
        var again = await _service.SubmitAsync(Request(_a, "a.example", "cancelled-retry", ["retry@dest.example"], idempotencyKey: "stale-key"), default);
        Assert.Equal(SubmissionStatus.Accepted, again.Status);
    }
}
