using Mta.Core;
using Mta.Storage.Logic;
using Mta.Storage.Model;

namespace Mta.Storage.Tests;

public class StatsEngineTests
{
    private static readonly DateTimeOffset H = new(2026, 10, 12, 9, 0, 0, TimeSpan.Zero);
    private static readonly Guid T = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private static StatDelta Delta(string domain, long accepted, string sending = "s") =>
        new(new StatKey(H, T, sending, domain), [accepted, 0, 0, 0, 0, 0, 0, 0, 0]);

    private static StatsBucketer Bucketer(int topN, int cap, Func<DateTimeOffset, IEnumerable<(Guid, string, string)>>? existing = null) =>
        new(new RetentionOptions { RecipientDomainTopNHourly = topN, MaxSeriesPerHour = cap }, existing ?? (_ => []));

    [Fact]
    public void Aggregator_adds_concurrently_and_drains_atomically()
    {
        var agg = new StatsAggregator(new RetentionOptions(), new HistoryOptions());
        Parallel.For(0, 8, _ =>
        {
            for (int i = 0; i < 10_000; i++)
            {
                agg.Add(new StatKey(H, T, "s", "d"), StatCounter.Delivered, 1);
            }
        });

        var first = agg.Drain(H);
        Assert.Equal(80_000, first.Single().Counts[(int)StatCounter.Delivered]);
        Assert.Empty(agg.Drain(H));
    }

    [Fact]
    public void Aggregator_restores_deltas_after_a_failed_flush()
    {
        var agg = new StatsAggregator(new RetentionOptions(), new HistoryOptions());
        agg.Add(new StatKey(H, T, "s", "d"), StatCounter.Accepted, 5);
        var taken = agg.Drain(H);
        agg.Restore(taken);
        Assert.Equal(5, agg.Drain(H).Single().Counts[(int)StatCounter.Accepted]);
    }

    [Fact]
    public void Aggregator_normalizes_the_hour_and_a_missing_sending_domain()
    {
        var agg = new StatsAggregator(new RetentionOptions(), new HistoryOptions());
        agg.Add(new StatKey(H.AddMinutes(41), T, null!, "d"), StatCounter.Accepted, 1);
        var key = agg.Drain(H).Single().Key;
        Assert.Equal(H, key.HourStart);
        Assert.Equal("", key.SendingDomain);
    }

    [Fact]
    public void Aggregator_ring_is_bounded_and_ordered()
    {
        var agg = new StatsAggregator(new RetentionOptions(), new HistoryOptions { RecentEvents = 3 });
        for (int i = 0; i < 20; i++)
        {
            agg.AddRecent(new RecentEvent(H.AddSeconds(i), T, "delivered", "d", null));
        }

        var drained = agg.DrainRecent();
        Assert.True(drained.Count <= 6);
        Assert.Equal(H.AddSeconds(19), drained[^1].At);
        Assert.Empty(agg.DrainRecent());
    }

    [Fact]
    public void Aggregator_caps_memory_when_cardinality_explodes()
    {
        var agg = new StatsAggregator(new RetentionOptions { MaxSeriesPerHour = 10 }, new HistoryOptions());
        for (int i = 0; i < 10_000; i++)
        {
            agg.Add(new StatKey(H, T, "s", "d" + i), StatCounter.Accepted, 1);
        }

        var drained = agg.Drain(H);
        Assert.True(drained.Count <= 1025);
        Assert.Equal(10_000, drained.Sum(d => d.Counts[0]));
    }

    [Fact]
    public void Bucketer_keeps_the_biggest_domains_of_a_flush()
    {
        var b = Bucketer(2, 100);
        var result = b.Apply([Delta("small", 1), Delta("big", 100), Delta("mid", 50), Delta("tiny", 1)]);
        Assert.Equal(["big", "mid", "other"], result.Select(r => r.Key.RecipientDomain).Order(StringComparer.Ordinal));
        Assert.Equal(2, result.Single(r => r.Key.RecipientDomain == "other").Counts[0]);
    }

    [Fact]
    public void Bucketer_honours_series_already_in_the_store()
    {
        var b = Bucketer(1, 100, _ => [(T, "s", "old")]);
        var result = b.Apply([Delta("old", 1), Delta("new", 100)]);
        Assert.Equal(["old", "other"], result.Select(r => r.Key.RecipientDomain).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Bucketer_other_does_not_count_against_the_top_n()
    {
        var b = Bucketer(2, 100);
        var result = b.Apply([Delta("a", 3), Delta("b", 2), Delta("c", 1), Delta("d", 1)]);
        Assert.Equal(3, result.Count);
    }

    [Fact]
    public void Bucketer_with_zero_top_n_buckets_everything_as_other()
    {
        var result = Bucketer(0, 100).Apply([Delta("a", 3), Delta("b", 2)]);
        var only = Assert.Single(result);
        Assert.Equal("other", only.Key.RecipientDomain);
        Assert.Equal(5, only.Counts[0]);
    }

    [Fact]
    public void Rollup_ranks_by_total_volume_then_name_and_folds_the_rest()
    {
        StatRow Row(string domain, long accepted, long delivered = 0) => StatsRollup.ToRow(H, false, T, "s", domain, [accepted, delivered, 0, 0, 0, 0, 0, 0, 0]);
        var rows = StatsRollup.RollUpDay([Row("z", 5), Row("a", 5), Row("b", 4, 1), Row("c", 1), Row("other", 9)], H.AddHours(-9), 2);
        Assert.Equal(["a", "b", "other"], rows.Select(r => r.RecipientDomain).Order(StringComparer.Ordinal));
        var other = rows.Single(r => r.RecipientDomain == "other");
        Assert.Equal(5 + 1 + 9, other.Accepted);
        Assert.All(rows, r => Assert.True(r.Daily));
    }

    [Fact]
    public void Days_to_roll_cover_complete_days_only()
    {
        DateTimeOffset now = new(2026, 10, 12, 12, 30, 0, TimeSpan.Zero);
        int today = StorageTime.DayNumber(now);
        Assert.Equal((today - 3, today - 1), StatsRollup.DaysToRoll(now, null, today - 3));
        Assert.Equal((today, today - 1), StatsRollup.DaysToRoll(now, today - 1, null));

        // Just after midnight the previous day is still open for late flushes.
        DateTimeOffset justAfterMidnight = new(2026, 10, 12, 0, 30, 0, TimeSpan.Zero);
        Assert.Equal(today - 2, StatsRollup.DaysToRoll(justAfterMidnight, null, today - 2).Last);
    }

    [Fact]
    public void Retention_cutoffs_treat_zero_as_unlimited()
    {
        DateTimeOffset now = new(2026, 10, 12, 12, 30, 0, TimeSpan.Zero);
        Assert.Null(RetentionCutoffs.DayKeyCutoff(now, 0));
        Assert.Null(RetentionCutoffs.InstantCutoff(now, 0));
        Assert.Null(RetentionCutoffs.StatsCutoff(now, 0));
        Assert.Equal(StorageTime.DayNumber(now) - 7, RetentionCutoffs.DayKeyCutoff(now, 7));
        Assert.Equal(new DateTimeOffset(2026, 10, 5, 0, 0, 0, TimeSpan.Zero), RetentionCutoffs.StatsCutoff(now, 7));
    }
}

public class LogicTests
{
    [Theory]
    [InlineData("<Abc@Example.COM>", "abc@example.com")]
    [InlineData("  <abc@example.com>  ", "abc@example.com")]
    [InlineData("abc@example.com", "abc@example.com")]
    [InlineData("<abc@example.com> (a comment)", "abc@example.com")]
    [InlineData("<abc\r\n @example.com>", "abc@example.com")]
    [InlineData("<>", null)]
    [InlineData("   ", null)]
    [InlineData(null, null)]
    public void Message_id_keys_ignore_brackets_case_comments_and_folding(string? header, string? key) => Assert.Equal(key, MessageIdKey.Normalize(header));

    [Theory]
    [InlineData("ReturnPathHost", "return_path_host")]
    [InlineData("Id", "id")]
    [InlineData("SmtpCode", "smtp_code")]
    [InlineData("TlsJson", "tls_json")]
    [InlineData("MxHost", "mx_host")]
    [InlineData("KeyHash", "key_hash")]
    public void Snake_case_names(string pascal, string snake) => Assert.Equal(snake, StorageModel.SnakeCase(pascal));

    [Fact]
    public void Event_ids_increase_strictly_even_within_one_millisecond()
    {
        DateTimeOffset at = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);
        var ids = Enumerable.Range(0, 10_000).Select(_ => EventIds.Next(at)).ToList();
        for (int i = 1; i < ids.Count; i++)
        {
            Assert.True(string.CompareOrdinal(ids[i - 1].ToString(), ids[i].ToString()) < 0, $"event id {i} did not increase");
        }

        Assert.All(ids, id => Assert.Equal(7, id.Version));
        Assert.True(Ids.GetTimestamp(ids[0]) >= at);
    }

    [Fact]
    public void Uuid_v7_text_order_is_time_order()
    {
        var a = Ids.New(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var b = Ids.New(new DateTimeOffset(2026, 1, 1, 0, 0, 1, TimeSpan.Zero));
        var c = Ids.New(new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.True(string.CompareOrdinal(a.ToString("D").ToUpperInvariant(), b.ToString("D").ToUpperInvariant()) < 0);
        Assert.True(string.CompareOrdinal(b.ToString("D").ToUpperInvariant(), c.ToString("D").ToUpperInvariant()) < 0);
    }

    [Fact]
    public void Day_numbers_match_the_uuid_timestamp()
    {
        DateTimeOffset at = new(2026, 10, 12, 23, 59, 59, TimeSpan.Zero);
        Guid id = Ids.New(at);
        Assert.Equal(StorageTime.DayNumber(at), StorageTime.DayNumber(id));
        Assert.Equal(new DateTimeOffset(2026, 10, 12, 0, 0, 0, TimeSpan.Zero), StorageTime.DayStart(StorageTime.DayNumber(id)));
    }

    [Fact]
    public void Hour_start_truncates_negative_and_positive_instants()
    {
        Assert.Equal(new DateTimeOffset(2026, 10, 12, 9, 0, 0, TimeSpan.Zero), StorageTime.HourStart(new DateTimeOffset(2026, 10, 12, 9, 59, 59, 999, TimeSpan.Zero)));
        Assert.Equal(new DateTimeOffset(1969, 12, 31, 23, 0, 0, TimeSpan.Zero), StorageTime.HourStart(new DateTimeOffset(1969, 12, 31, 23, 30, 0, TimeSpan.Zero)));
    }

    [Fact]
    public void Message_status_transitions()
    {
        Assert.Equal("deferred", MessageStatus.Next("queued", 2, 0, 0, 0, null));
        Assert.Equal("queued", MessageStatus.Next("queued", 2, 1, 1, 0, "delivered"));
        Assert.Equal("delivered", MessageStatus.Next("queued", 2, 2, 2, 0, "delivered"));
        Assert.Equal("partial", MessageStatus.Next("queued", 2, 2, 1, 1, "bounced"));
        Assert.Equal("bounced", MessageStatus.Next("deferred", 2, 2, 0, 2, "bounced"));
        Assert.Equal("expired", MessageStatus.Next("deferred", 1, 1, 0, 0, "expired"));
        Assert.Equal("suppressed", MessageStatus.Next("queued", 1, 1, 0, 0, "suppressed"));
        Assert.Equal("delivered", MessageStatus.Next("delivered", 1, 1, 1, 0, null));
        Assert.Equal("delivered", MessageStatus.FinalKind(MessageEventType.Delivered));
        Assert.Null(MessageStatus.FinalKind(MessageEventType.Deferred));
    }

    [Fact]
    public void Truncation_never_splits_characters()
    {
        Assert.Equal("héllo", ContentRules.Truncate("héllo", 100, out bool t0));
        Assert.False(t0);
        string? cut = ContentRules.Truncate("ééééé", 5, out bool t1);
        Assert.Equal("éé", cut);
        Assert.True(t1);
        string? emoji = ContentRules.Truncate("a😀😀", 6, out _);
        Assert.Equal("a😀", emoji);
        Assert.Null(ContentRules.Truncate(null, 5, out bool t2));
        Assert.False(t2);
    }

    [Fact]
    public void Cursors_round_trip_and_reject_garbage()
    {
        Guid id = Ids.New();
        string cursor = Cursors.EncodeHistory(20_000, id);
        Assert.True(Cursors.TryDecodeHistory(cursor, out int day, out Guid back));
        Assert.Equal((20_000, id), (day, back));
        Assert.False(Cursors.TryDecodeHistory("###", out _, out _));
        Assert.False(Cursors.TryDecodeHistory(Cursors.Encode("no-colon"), out _, out _));
        Assert.False(Cursors.TryDecodeHistory(null, out _, out _));
        Assert.True(Cursors.TryDecode(Cursors.Encode("ü/+?"), out string s));
        Assert.Equal("ü/+?", s);
    }

    [Fact]
    public void Json_helpers_round_trip()
    {
        Assert.Equal(["a", "b\"c"], StorageJson.DeserializeStrings(StorageJson.SerializeStrings(["a", "b\"c"])));
        Assert.Empty(StorageJson.DeserializeStrings(null));
        var attachments = new[] { new AttachmentInfo("f.txt", "text/plain", 12, "cid") };
        Assert.Equal(attachments, StorageJson.DeserializeAttachments(StorageJson.SerializeAttachments(attachments)));
        var tls = new TlsInfo(true, "TLS1.2", "c", null, null, null, "x", false, "may", "p", true, true);
        Assert.Equal(tls, StorageJson.DeserializeTls(StorageJson.SerializeTls(tls)));
        Assert.Null(StorageJson.SerializeTls(null));
    }

    [Fact]
    public void Webhook_subscription_matching()
    {
        Assert.True(WebhookSubscriptions.Matches(["a", "b"], "b"));
        Assert.True(WebhookSubscriptions.Matches(["*"], "anything"));
        Assert.False(WebhookSubscriptions.Matches([], "a"));
        Assert.False(WebhookSubscriptions.Matches(["A"], "a"));
    }

    [Fact]
    public void Options_validation_enforces_the_retention_convention()
    {
        StorageOptionsValidation.Validate(new StorageOptions());
        StorageOptionsValidation.Validate(new StorageOptions { Retention = new RetentionOptions { MetadataDays = 0, StatsDailyDays = 0, WebhookOutboxDays = 0 } });
        Assert.Throws<ArgumentException>(() => StorageOptionsValidation.Validate(new StorageOptions { Retention = new RetentionOptions { WebhookAttemptLogDays = -1 } }));
        Assert.Throws<ArgumentException>(() => StorageOptionsValidation.Validate(new StorageOptions { Content = new ContentOptions { RetentionDays = 0 } }));
        Assert.Throws<ArgumentException>(() => StorageOptionsValidation.Validate(new StorageOptions { Content = new ContentOptions { RetentionDays = 31 } }));
        Assert.Throws<ArgumentException>(() => StorageOptionsValidation.Validate(new StorageOptions { Retention = new RetentionOptions { MaxSeriesPerHour = 0 } }));
        Assert.Equal(["Retention:MetadataDays", "Webhooks:OutboxRetentionDays"],
            StorageOptionsValidation.UnlimitedRetentionKnobs(new StorageOptions { Retention = new RetentionOptions { MetadataDays = 0, WebhookOutboxDays = 0 } }));
    }

    [Fact]
    public void Lease_rules()
    {
        DateTimeOffset now = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);
        var l1 = LeaseRules.Acquire(null, "n", "a", TimeSpan.FromMinutes(1), now)!;
        Assert.Equal(1, l1.FencingToken);
        Assert.Null(LeaseRules.Acquire(l1, "n", "b", TimeSpan.FromMinutes(1), now.AddSeconds(30)));
        Assert.Equal(1, LeaseRules.Acquire(l1, "n", "a", TimeSpan.FromMinutes(1), now.AddSeconds(30))!.FencingToken);
        Assert.Equal(2, LeaseRules.Acquire(l1, "n", "a", TimeSpan.FromMinutes(1), now.AddMinutes(2))!.FencingToken);
        Assert.Null(LeaseRules.Renew(l1, "a", 2, TimeSpan.FromMinutes(1), now));
        Assert.NotNull(LeaseRules.Renew(l1, "a", 1, TimeSpan.FromMinutes(1), now));
        Assert.True(LeaseRules.Release(l1, "a")!.LeaseUntil <= now);
        Assert.Null(LeaseRules.Release(l1, "b"));
    }

    [Fact]
    public void Attempt_planner_maps_outcomes()
    {
        var row = new DeliveryRowInfo(Ids.New(), Ids.New(), Ids.New(), "a@x.example", "x.example", "s.example", MessageSource.Api, 0, false);
        DateTimeOffset at = new(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);
        DeliveryAttempt A(DeliveryOutcome o, DateTimeOffset? next = null, SuppressionReason? s = null, bool dup = false) =>
            new() { DeliveryId = row.DeliveryId, Outcome = o, At = at, NextAttemptAt = next, Suppress = s, PossibleDuplicate = dup, SmtpCode = 550, EnhancedCode = "5.1.1", Message = "secret" };

        var delivered = AttemptPlanner.Plan(A(DeliveryOutcome.Delivered), row);
        Assert.True(delivered.IsFinal && delivered.Delivered && !delivered.Failed);
        Assert.Equal(StatCounter.Delivered, Assert.Single(delivered.Counters).Counter);
        Assert.Equal("delivered", delivered.Ring.Single().EventType);
        Assert.Equal("550 5.1.1", delivered.Ring.Single().Detail);

        var deferred = AttemptPlanner.Plan(A(DeliveryOutcome.Deferred, at.AddMinutes(1)), row);
        Assert.Equal(QueueRowAction.Reschedule, deferred.Action);
        Assert.False(deferred.IsFinal);
        Assert.Equal("550 5.1.1 secret", deferred.LastError);
        Assert.Throws<ArgumentException>(() => AttemptPlanner.Plan(A(DeliveryOutcome.Deferred), row));

        var complaint = AttemptPlanner.Plan(A(DeliveryOutcome.Failed, s: SuppressionReason.Complaint), row);
        Assert.Equal([StatCounter.HardBounce, StatCounter.Complained], complaint.Counters.Select(c => c.Counter));
        Assert.Equal([MessageEventType.Bounced, MessageEventType.Complained], complaint.Events.Select(e => e.Type));

        var aborted = AttemptPlanner.Plan(A(DeliveryOutcome.AbortedBySwitch, dup: true), row);
        Assert.Equal(QueueRowAction.Requeue, aborted.Action);
        Assert.True(aborted.SetPossibleDuplicate);
        Assert.Empty(aborted.Counters);
        Assert.Equal(["aborted_by_switch", "possible_duplicate"], aborted.Ring.Select(r => r.EventType));

        Assert.Empty(AttemptPlanner.Plan(A(DeliveryOutcome.Cancelled), row).Counters);
    }
}
