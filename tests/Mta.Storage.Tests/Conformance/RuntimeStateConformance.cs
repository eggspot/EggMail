using Mta.Core;

namespace Mta.Storage.Tests;

/// <summary>
/// The state the process used to keep in memory only (<see cref="IRuntimeStateStore"/>): per-record DNS check results, the TLS-RPT journal and the
/// sending counters. Identical on every backend; the restart behaviour of the file and server backends is tested next to them.
/// </summary>
public abstract class RuntimeStateConformance : StorageTestBase
{
    private IRuntimeStateStore State => Storage.Config;

    // Domain record checks

    [Fact]
    public async Task Domain_record_checks_are_replaced_as_a_set_and_read_back_in_key_order()
    {
        Guid domain = Ids.New();
        Guid other = Ids.New();
        Assert.Empty(await State.GetDomainRecordChecksAsync(domain, default));

        await State.ReplaceDomainRecordChecksAsync(domain, [
            new DomainRecordCheckRecord(domain, "TXT|egg202610._domainkey.example.com", "ok", "v=DKIM1; p=abc", Clock.UtcNow),
            new DomainRecordCheckRecord(domain, "CNAME|bounce.example.com", "missing", null, Clock.UtcNow),
            new DomainRecordCheckRecord(domain, "TXT|example.com", "invalid", "v=spf1 -all", Clock.UtcNow),
        ], default);
        await State.ReplaceDomainRecordChecksAsync(other, [new DomainRecordCheckRecord(other, "TXT|example.net", "ok", "x", Clock.UtcNow)], default);

        var checks = await State.GetDomainRecordChecksAsync(domain, default);
        Assert.Equal(["CNAME|bounce.example.com", "TXT|egg202610._domainkey.example.com", "TXT|example.com"], checks.Select(c => c.RecordKey));
        Assert.Equal(["missing", "ok", "invalid"], checks.Select(c => c.Status));
        Assert.Equal([null, "v=DKIM1; p=abc", "v=spf1 -all"], checks.Select(c => c.Found));
        Assert.All(checks, c => Assert.Equal((domain, Clock.UtcNow), (c.DomainId, c.CheckedAt)));

        // A new check replaces the whole set of that domain and leaves other domains alone.
        Clock.Advance(TimeSpan.FromMinutes(10));
        await State.ReplaceDomainRecordChecksAsync(domain, [new DomainRecordCheckRecord(domain, "TXT|example.com", "ok", "v=spf1 include:egg -all", Clock.UtcNow)], default);
        var replaced = Assert.Single(await State.GetDomainRecordChecksAsync(domain, default));
        Assert.Equal(("ok", "v=spf1 include:egg -all", Clock.UtcNow), (replaced.Status, replaced.Found, replaced.CheckedAt));
        Assert.Single(await State.GetDomainRecordChecksAsync(other, default));

        await State.ReplaceDomainRecordChecksAsync(domain, [], default);
        Assert.Empty(await State.GetDomainRecordChecksAsync(domain, default));
    }

    [Fact]
    public async Task Deleting_a_domain_deletes_its_record_checks()
    {
        Guid tenant = TenantA;
        var domain = new DomainRecord(Ids.New(), tenant, "example.com", DomainStatus.Verified, null, false, Clock.UtcNow, null, null, 0, null, false, null);
        await Storage.Config.UpsertDomainAsync(domain, default);
        await State.ReplaceDomainRecordChecksAsync(domain.Id, [new DomainRecordCheckRecord(domain.Id, "TXT|example.com", "ok", "x", Clock.UtcNow)], default);
        Assert.Single(await State.GetDomainRecordChecksAsync(domain.Id, default));

        await Storage.Config.DeleteDomainAsync(domain.Id, default);
        Assert.Empty(await State.GetDomainRecordChecksAsync(domain.Id, default));
    }

    // TLS-RPT journal

    private TlsRptBucketRecord Bucket(int day, string domain, string json = "{}", int attempts = 0, TimeSpan? age = null) =>
        new(Ids.New(), day, domain, json, attempts, Clock.UtcNow + (age ?? TimeSpan.Zero));

    [Fact]
    public async Task Tls_rpt_buckets_are_listed_for_completed_days_oldest_first_and_bounded()
    {
        var d100a = Bucket(100, "b.example", "{\"n\":1}", age: TimeSpan.FromSeconds(2));
        var d100b = Bucket(100, "a.example", "{\"n\":2}", age: TimeSpan.FromSeconds(3));
        var d100c = Bucket(100, "a.example", "{\"n\":3}", age: TimeSpan.FromSeconds(1));
        var d99 = Bucket(99, "z.example");
        var d101 = Bucket(101, "a.example");
        await State.AddTlsRptBucketsAsync([d100a, d100b, d101], default);
        await State.AddTlsRptBucketsAsync([d100c, d99], default);
        await State.AddTlsRptBucketsAsync([], default);

        var before101 = await State.GetTlsRptBucketsAsync(101, 100, default);
        Assert.Equal([d99.Id, d100c.Id, d100b.Id, d100a.Id], before101.Select(b => b.Id));
        Assert.Equal("{\"n\":3}", before101[1].DataJson);
        Assert.Equal((100, "a.example", 0, d100c.CreatedAt), (before101[1].Day, before101[1].PolicyDomain, before101[1].Attempts, before101[1].CreatedAt));

        Assert.Equal([d99.Id, d100c.Id], (await State.GetTlsRptBucketsAsync(101, 2, default)).Select(b => b.Id));
        Assert.Empty(await State.GetTlsRptBucketsAsync(99, 10, default));
        Assert.Equal(5, (await State.GetTlsRptBucketsAsync(1000, 10, default)).Count);
    }

    [Fact]
    public async Task Replacing_tls_rpt_buckets_deletes_the_given_ids_and_inserts_the_replacement_in_one_step()
    {
        var a = Bucket(100, "a.example", "{\"n\":1}");
        var b = Bucket(100, "a.example", "{\"n\":2}", age: TimeSpan.FromSeconds(1));
        var keep = Bucket(100, "b.example");
        await State.AddTlsRptBucketsAsync([a, b, keep], default);

        var merged = Bucket(100, "a.example", "{\"n\":3}", attempts: 1, age: TimeSpan.FromSeconds(5));
        await State.ReplaceTlsRptBucketsAsync([a.Id, b.Id, Ids.New()], merged, default);

        var left = await State.GetTlsRptBucketsAsync(101, 10, default);
        Assert.Equal([merged.Id, keep.Id], left.Select(x => x.Id));
        Assert.Equal((1, "{\"n\":3}"), (left[0].Attempts, left[0].DataJson));

        await State.ReplaceTlsRptBucketsAsync([merged.Id, keep.Id], null, default);
        Assert.Empty(await State.GetTlsRptBucketsAsync(101, 10, default));
        await State.ReplaceTlsRptBucketsAsync([], null, default);
    }

    // Sending counters

    private static SendingCounterRecord Counter(byte scope, Guid tenant, string domain, byte window, long index, long count) => new(scope, tenant, domain, window, index, count);

    [Fact]
    public async Task Sending_counters_add_up_deltas_from_every_writer_and_never_drop_below_zero()
    {
        long hour = Clock.UtcNow.ToUnixTimeSeconds() / 3600;
        long day = Clock.UtcNow.ToUnixTimeSeconds() / 86400;
        await State.AddSendingCountersAsync([
            Counter(0, Guid.Empty, "", 0, hour, 5),
            Counter(1, TenantA, "", 1, day, 7),
            Counter(2, Guid.Empty, "example.com", 1, day, 3),
        ], hour - 1, day - 1, default);
        // A second replica's deltas, a release (negative), and two deltas for one key in one call.
        await State.AddSendingCountersAsync([
            Counter(0, Guid.Empty, "", 0, hour, 4),
            Counter(1, TenantA, "", 1, day, -2),
            Counter(2, Guid.Empty, "example.com", 1, day, 1),
            Counter(2, Guid.Empty, "example.com", 1, day, 1),
        ], hour - 1, day - 1, default);

        var counters = await State.GetSendingCountersAsync(hour, day, default);
        long Of(byte scope, Guid tenant, string domain, byte window) => counters.Single(c => (c.Scope, c.TenantId, c.Domain, c.Window) == (scope, tenant, domain, window)).Count;
        Assert.Equal(9, Of(0, Guid.Empty, "", 0));
        Assert.Equal(5, Of(1, TenantA, "", 1));
        Assert.Equal(5, Of(2, Guid.Empty, "example.com", 1));
        Assert.Equal(3, counters.Count);

        await State.AddSendingCountersAsync([Counter(1, TenantA, "", 1, day, -100)], hour - 1, day - 1, default);
        Assert.Equal(0, (await State.GetSendingCountersAsync(hour, day, default)).Single(c => c.Scope == 1).Count);
        await State.AddSendingCountersAsync([Counter(1, TenantB, "", 1, day, -3)], hour - 1, day - 1, default); // a negative delta never creates a counter
        Assert.DoesNotContain(await State.GetSendingCountersAsync(hour, day, default), c => c.TenantId == TenantB);
    }

    [Fact]
    public async Task Reading_sending_counters_returns_only_the_requested_windows_and_writing_prunes_older_ones()
    {
        long hour = Clock.UtcNow.ToUnixTimeSeconds() / 3600;
        long day = Clock.UtcNow.ToUnixTimeSeconds() / 86400;
        await State.AddSendingCountersAsync([
            Counter(0, Guid.Empty, "", 0, hour - 3, 1),
            Counter(0, Guid.Empty, "", 0, hour - 1, 2),
            Counter(0, Guid.Empty, "", 0, hour, 3),
            Counter(0, Guid.Empty, "", 1, day - 2, 4),
            Counter(0, Guid.Empty, "", 1, day, 5),
        ], 0, 0, default);

        var current = await State.GetSendingCountersAsync(hour, day, default);
        Assert.Equal([3L, 5L], current.OrderBy(c => c.Window).Select(c => c.Count));
        Assert.Equal(5, (await State.GetSendingCountersAsync(0, 0, default)).Count);

        // Pruning: windows before the given hour and day are deleted by the next write (an empty delta list still prunes).
        await State.AddSendingCountersAsync([], hour - 1, day - 1, default);
        var kept = await State.GetSendingCountersAsync(0, 0, default);
        Assert.Equal([2L, 3L, 5L], kept.OrderBy(c => c.Window).ThenBy(c => c.WindowIndex).Select(c => c.Count));
    }
}
