using System.Text;
using Mta.Core;
using Mta.TestSupport;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace Mta.Storage.Tests;

/// <summary>
/// Crash/restart loop over a real backend: a seeded random interleaving of the operations of a mail server (accept with and without idempotency keys, claim, record
/// delivered/deferred/bounced, lease expiry by jumping the clock, expiry sweeps, cancel, statistics, webhook outbox, configuration writes, maintenance) in which the storage is
/// repeatedly <b>killed</b> (the statistics buffer that lives only in memory is thrown away, in-flight writes are abandoned, nothing is flushed gracefully) and reopened over the
/// same files or database, against a model of what was acknowledged.
/// <para>
/// The contract it checks after every reopen and at the end, after the queue was drained with the virtual clock: no acknowledged message is lost; every recipient reaches exactly
/// one final state (one final history event, spool released only with the last recipient); a delivery whose holder died is claimable again (at once when the backend clears
/// the leases at start, after the lease otherwise) and is flagged <c>possible_duplicate</c> exactly when its previous holder never reported; a claim never hands out a delivery that
/// is not due, expired, final or still leased; an idempotency key accepted before a crash still deduplicates (same message id) until its lifetime passes; acknowledged
/// configuration writes are readable; webhook outbox rows are neither lost nor delivered twice. <b>Statistics are write-behind</b>: the stored count of every counter is exactly what was
/// flushed (a crash loses precisely the unflushed window, an increment is never counted twice); operations still in flight at the kill can add at most their own increments.
/// </para>
/// A failure prints the seed and the operation trace; replay with <c>EGGMAIL_ACCEL_SEED=&lt;seed&gt;</c>.
/// </summary>
public abstract class CrashLoopLifecycleConformance : StorageTestBase
{
    protected CrashLoopLifecycleConformance(ITestOutputHelper output) => Output = output;

    protected ITestOutputHelper Output { get; }

    /// <summary>The seed used when <c>EGGMAIL_ACCEL_SEED</c> is not set.</summary>
    protected virtual int DefaultSeed => 20261016;

    /// <summary>Steps of the loop at <c>EGGMAIL_ACCEL_SCALE=1</c>.</summary>
    protected virtual int BaseSteps => 260;

    /// <summary>True when the backend releases every lease at start (a single node: SQLite); false when a lease runs until it expires (PostgreSQL, several replicas).</summary>
    protected abstract bool ClearsLeasesOnStart { get; }

    /// <summary>True when a maintenance run also releases the expired leases of dead workers (flagging their deliveries); PostgreSQL does, SQLite releases them only at start.</summary>
    protected abstract bool MaintenanceReleasesExpiredLeases { get; }

    /// <summary>Throws away what the open storage holds only in memory (the write-behind statistics), as a killed process does.</summary>
    protected abstract void DiscardUnflushedStatistics();

    /// <summary>True while the storage is being reopened over the data it already has: the derived <c>CreateAsync</c> must not start from empty files then.</summary>
    protected bool Reopening { get; private set; }

    protected override StorageOptions BuildOptions() => new()
    {
        // Unlimited retention: the loop checks everything it ever did, and retention is covered by the retention lifecycle suites.
        Retention = new RetentionOptions { MetadataDays = 0, StatsHourlyDays = 0, StatsDailyDays = 0, WebhookOutboxDays = 0, WebhookAttemptLogDays = 0 },
    };

    /// <summary>Kills the storage (data stays) and opens another one over the same data.</summary>
    protected async Task KillAndReopenAsync()
    {
        DiscardUnflushedStatistics();
        Reopening = true;
        try
        {
            await OpenAsync(Options);
        }
        finally
        {
            Reopening = false;
        }
    }

    /// <summary>A graceful stop and start over the same data.</summary>
    protected async Task RestartGracefullyAsync()
    {
        Reopening = true;
        try
        {
            await OpenAsync(Options);
        }
        finally
        {
            Reopening = false;
        }
    }

    [Fact]
    public async Task Seeded_kills_and_reopens_lose_no_acknowledged_message_and_keep_every_promise_of_the_queue()
    {
        int seed = Accelerated.Seed(DefaultSeed);
        int steps = Accelerated.Scaled(BaseSteps);
        Output.WriteLine($"crash loop: seed {seed}, {steps} steps (replay: EGGMAIL_ACCEL_SEED={seed}; more steps: EGGMAIL_ACCEL_SCALE)");
        var run = new Run(this, seed);
        await run.ExecuteAsync(steps);
        Output.WriteLine($"crash loop: {run.Kills} kills, {run.Graceful} graceful restarts, {run.Accepted} messages accepted, {run.Claimed} claims, {run.DuplicatesFlagged} deliveries re-claimed after their holder died");
        Assert.True(run.Kills >= 5, "the loop did not crash often enough to mean anything");
    }

    private sealed class Rcpt
    {
        public required Guid DeliveryId { get; init; }
        public required Guid MessageId { get; init; }
        public required Guid Tenant { get; init; }
        public required string Address { get; init; }
        public required DateTimeOffset ExpiresAt { get; init; }
        public DateTimeOffset DueAt { get; set; }
        public bool Final { get; set; }
        public MessageEventType FinalType { get; set; }
        public bool Held { get; set; }
        public DateTimeOffset LeaseUntil { get; set; }
        public bool Lost { get; set; }
        public int Attempt { get; set; }
        public ClaimedDelivery? LastClaim { get; set; }
    }

    private sealed class Mdl
    {
        public required Guid Id { get; init; }
        public required Guid Tenant { get; init; }
        public required DateTimeOffset At { get; init; }
        public required List<Rcpt> Rcpts { get; init; }
        public string? Key { get; init; }
    }

    private sealed class OutboxEntry
    {
        public DateTimeOffset Due { get; set; }
        public DateTimeOffset HeldUntil { get; set; }
        public bool Done { get; set; }
    }

    private sealed class Run
    {
        private const int CounterCount = 9;
        private static readonly TimeSpan Lease = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan KeyLifetime = TimeSpan.FromHours(24);

        private readonly CrashLoopLifecycleConformance _t;
        private readonly Random _rng;
        private readonly int _seed;
        private readonly List<string> _trace = [];
        private int _step;
        private int _keySeq;
        private int _configSeq;

        private readonly List<Mdl> _messages = [];
        private readonly Dictionary<Guid, Rcpt> _byDelivery = [];
        private readonly Dictionary<Guid, Mdl> _byMessage = [];
        private readonly Dictionary<(Guid Tenant, string Key), Mdl> _keys = [];
        private readonly HashSet<Guid> _touched = [];
        private readonly List<ClaimedDelivery> _stale = [];
        private readonly HashSet<(Guid Tenant, string Address)> _suppressed = [];

        private readonly long[] _flushed = new long[CounterCount];
        private readonly long[] _pending = new long[CounterCount];
        private readonly long[] _uncertain = new long[CounterCount];

        private readonly Dictionary<Guid, OutboxEntry> _outbox = [];

        private readonly List<Tenant> _tenants = [];
        private readonly List<SmtpCredential> _credentials = [];
        private readonly List<(ApiKeyRecord Key, bool Revoked)> _apiKeys = [];
        private readonly List<DomainRecord> _domains = [];
        private readonly List<DkimKeyRecord> _dkimKeys = [];
        private readonly Dictionary<(Guid Tenant, string Address), bool> _manualSuppressions = [];
        private readonly Dictionary<string, string> _settings = [];
        private long _sendingCounter;
        private long _hour0;

        public Run(CrashLoopLifecycleConformance t, int seed)
        {
            _t = t;
            _seed = seed;
            _rng = new Random(seed);
        }

        public int Kills { get; private set; }

        public int Graceful { get; private set; }

        public int Accepted { get; private set; }

        public int Claimed { get; private set; }

        public int DuplicatesFlagged { get; private set; }

        private IStorage S => _t.Storage;

        private DateTimeOffset Now => _t.Clock.UtcNow;

        private static readonly string[] Pool = Enumerable.Range(0, 12).Select(i => $"user{i}@dest{i % 3}.example").ToArray();

        public async Task ExecuteAsync(int steps)
        {
            try
            {
                await _t.AddEndpointAsync(TenantA, true, "*");
                _hour0 = _t.Clock.UtcNow.ToUnixTimeSeconds() / 3600;
                for (_step = 0; _step < steps; _step++)
                {
                    await StepAsync();
                    if (_step % 40 == 39)
                    {
                        await VerifyAsync(full: false, "periodic");
                    }
                }

                await DrainAsync();
            }
            catch (Exception ex) when (ex is not XunitException { Data: { Count: > 0 } })
            {
                var sb = new StringBuilder();
                sb.AppendLine($"crash loop failed at step {_step} (seed {_seed}; replay with EGGMAIL_ACCEL_SEED={_seed}): {ex.GetType().Name}: {ex.Message}");
                sb.AppendLine("operation trace (last 150):");
                foreach (string line in _trace.Skip(Math.Max(0, _trace.Count - 150)))
                {
                    sb.AppendLine("  " + line);
                }

                var wrapped = new XunitException(sb.ToString(), ex);
                wrapped.Data["trace"] = true;
                throw wrapped;
            }
        }

        private void Note(string text) => _trace.Add($"#{_step} {Now:MM-dd HH:mm:ss} {text}");

        private static void Check(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private async Task StepAsync()
        {
            double roll = _rng.NextDouble();
            if (roll < 0.22)
            {
                await AcceptOpAsync();
            }
            else if (roll < 0.38)
            {
                await ClaimOpAsync();
            }
            else if (roll < 0.58)
            {
                await RecordOpAsync();
            }
            else if (roll < 0.63)
            {
                await StaleRecordOpAsync();
            }
            else if (roll < 0.70)
            {
                await ClockOpAsync();
            }
            else if (roll < 0.74)
            {
                await ExpirySweepOpAsync();
            }
            else if (roll < 0.77)
            {
                await ReleaseOpAsync();
            }
            else if (roll < 0.79)
            {
                await ExtendOpAsync();
            }
            else if (roll < 0.83)
            {
                await StatsOpAsync();
            }
            else if (roll < 0.88)
            {
                await WebhookOpAsync();
            }
            else if (roll < 0.90)
            {
                await CancelOpAsync();
            }
            else if (roll < 0.92)
            {
                await MaintenanceOpAsync();
            }
            else if (roll < 0.95)
            {
                await ConfigOpAsync();
            }
            else
            {
                await RestartOpAsync();
            }
        }

        // ---- Accept

        private AcceptedMessage BuildMessage(Guid tenant, string[] to, string? key)
        {
            TimeSpan? lifetime = _rng.Next(4) == 0 ? TimeSpan.FromHours(_rng.Next(1, 40)) : null;
            return _t.Msg(tenant: tenant, to: to, size: _rng.Next(200, 3000), idempotencyKey: key, lifetime: lifetime, subject: "m" + _rng.Next(1_000_000));
        }

        private Mdl Register(AcceptedMessage m, string[] to, string? key)
        {
            var rcpts = new List<Rcpt>();
            for (int i = 0; i < m.Recipients.Count; i++)
            {
                var r = new Rcpt
                {
                    DeliveryId = m.Recipients[i].DeliveryId,
                    MessageId = m.MessageId,
                    Tenant = m.TenantId,
                    Address = to[i],
                    ExpiresAt = m.ExpiresAt,
                    DueAt = m.ReceivedAt,
                };
                rcpts.Add(r);
                _byDelivery[r.DeliveryId] = r;
            }

            var msg = new Mdl { Id = m.MessageId, Tenant = m.TenantId, At = m.ReceivedAt, Rcpts = rcpts, Key = key };
            _messages.Add(msg);
            _byMessage[msg.Id] = msg;
            _touched.Add(msg.Id);
            if (key is not null)
            {
                _keys[(msg.Tenant, key)] = msg;
            }

            Accepted++;
            return msg;
        }

        private string[] PickRecipients()
        {
            int n = _rng.Next(1, 4);
            return Enumerable.Range(0, Pool.Length).OrderBy(_ => _rng.Next()).Take(n).Select(i => Pool[i]).ToArray();
        }

        private async Task AcceptOpAsync()
        {
            Guid tenant = _rng.Next(4) == 0 ? TenantB : TenantA;
            string[] to = PickRecipients();
            string? key = null;
            Mdl? original = null;
            if (_rng.NextDouble() < 0.4)
            {
                if (_keys.Count > 0 && _rng.NextDouble() < 0.5)
                {
                    var entry = _keys.ElementAt(_rng.Next(_keys.Count));
                    original = entry.Value;
                    tenant = original.Tenant;
                    key = entry.Key.Key;
                }
                else
                {
                    key = "k" + ++_keySeq;
                }
            }

            TimeSpan age = original is null ? TimeSpan.Zero : Now - original.At;
            if (original is not null && age >= KeyLifetime - TimeSpan.FromMinutes(1) && age <= KeyLifetime + TimeSpan.FromMinutes(1))
            {
                Note("accept skipped (idempotency key is at its lifetime boundary)");
                return;
            }

            AcceptedMessage m = BuildMessage(tenant, to, key);
            IntakeResult r = await S.Intake.AcceptAsync(m, default);
            if (original is not null && age < KeyLifetime)
            {
                Note($"accept duplicate key {key}");
                Check(r.Status == IntakeStatus.DuplicateIdempotencyKey, $"key {key} accepted {age} ago was accepted again");
                Check(r.MessageId == original.Id, "a duplicate key returned another message id");
                return;
            }

            Note($"accept {m.MessageId:N} to {string.Join(',', to)} key {key ?? "-"} expires {m.ExpiresAt:MM-dd HH:mm}");
            Check(r.Status == IntakeStatus.Accepted && r.MessageId == m.MessageId, $"accept answered {r.Status} for a new message (key {key}, age {age})");
            Register(m, to, key);
            _pending[(int)StatCounter.Accepted] += to.Length;
        }

        // ---- Claim

        private List<Rcpt> Eligible(DateTimeOffset now) =>
            _byDelivery.Values.Where(r => !r.Final && r.DueAt <= now && r.ExpiresAt > now && (!r.Held || r.LeaseUntil <= now)).ToList();

        private async Task<List<(ClaimedDelivery Claim, Rcpt Row)>> ClaimAsync(int max, bool exact)
        {
            DateTimeOffset now = Now;
            List<Rcpt> eligible = Eligible(now);
            IReadOnlyList<ClaimedDelivery> got = await _t.ClaimAsync(max, Lease, "worker-1");
            Note($"claim max {max}: {got.Count} of {eligible.Count} eligible: " + string.Join(' ', got.Select(c => $"{c.Recipient}@{c.MessageId.ToString("N")[^6..]}")));
            Check(got.Count <= max, "claim returned more than max");
            Check(got.Select(c => c.DeliveryId).Distinct().Count() == got.Count, "claim returned a delivery twice");
            Check(exact ? got.Count == Math.Min(max, eligible.Count) : got.Count <= eligible.Count, $"claim returned {got.Count}, expected {Math.Min(max, eligible.Count)} (eligible {eligible.Count})");
            var result = new List<(ClaimedDelivery, Rcpt)>();
            foreach (ClaimedDelivery c in got)
            {
                Check(_byDelivery.TryGetValue(c.DeliveryId, out Rcpt? r), $"claim returned an unknown delivery {c.DeliveryId}");
                Check(!r!.Final, $"claim returned the final delivery {r.Address} of {r.MessageId}");
                Check(r.DueAt <= now && r.ExpiresAt > now, $"claim returned a delivery that is not due or expired ({r.DueAt:o}, {r.ExpiresAt:o})");
                Check(!r.Held || r.LeaseUntil <= now, $"claim handed out {r.Address} of {r.MessageId} while its lease ({r.LeaseUntil:o}) was still running");
                if (r.Held)
                {
                    r.Lost = true;
                    if (r.LastClaim is not null)
                    {
                        _stale.Add(r.LastClaim);
                    }
                }

                Check(c.PossibleDuplicate == r.Lost, $"possible_duplicate was {c.PossibleDuplicate}, expected {r.Lost} for {r.Address} of {r.MessageId} (attempt {r.Attempt})");
                if (r.Lost)
                {
                    DuplicatesFlagged++;
                }

                Check(c.Attempt == r.Attempt && c.MessageId == r.MessageId && c.TenantId == r.Tenant && c.Recipient.ToString() == r.Address, "the claimed delivery differs from what was accepted");
                r.Held = true;
                r.LeaseUntil = now + Lease;
                r.LastClaim = c;
                _touched.Add(r.MessageId);
                Claimed++;
                result.Add((c, r));
            }

            return result;
        }

        private Task ClaimOpAsync()
        {
            bool all = _rng.Next(3) == 0;
            return ClaimAsync(all ? 10_000 : _rng.Next(1, 12), exact: true);
        }

        // ---- Record

        private async Task ApplyRecordAsync(Rcpt r, ClaimedDelivery claim, DeliveryOutcome outcome, DateTimeOffset? next, bool countAttempt, bool stale)
        {
            WebhookEventDraft draft = StorageTestBase.Draft("message." + outcome.ToString().ToLowerInvariant());
            SuppressionReason? suppress = outcome == DeliveryOutcome.Failed ? SuppressionReason.HardBounce : null;
            await _t.RecordAsync(claim, outcome, next, suppress, [draft], possibleDuplicate: claim.PossibleDuplicate, countAttempt: countAttempt);
            Note($"record {outcome} {r.Address} of {r.MessageId:N}{(stale ? " (stale holder)" : string.Empty)}{(next is { } n ? " next " + n.ToString("MM-dd HH:mm") : string.Empty)}");
            _touched.Add(r.MessageId);
            if (r.Final)
            {
                return;   // reported twice: harmless, nothing changes
            }

            if (r.Tenant == TenantA && (outcome != DeliveryOutcome.Deferred || countAttempt))   // a hold that sent nothing reports no event
            {
                _outbox[draft.EventId] = new OutboxEntry { Due = Now };
            }

            switch (outcome)
            {
                case DeliveryOutcome.Delivered:
                    Finish(r, MessageEventType.Delivered, StatCounter.Delivered);
                    break;
                case DeliveryOutcome.Failed:
                    Finish(r, MessageEventType.Bounced, StatCounter.HardBounce);
                    _suppressed.Add((r.Tenant, r.Address));
                    break;
                case DeliveryOutcome.Expired:
                    Finish(r, MessageEventType.Expired, StatCounter.Expired);
                    break;
                case DeliveryOutcome.Deferred:
                    r.Held = false;
                    r.DueAt = next!.Value;
                    if (countAttempt)
                    {
                        r.Attempt++;
                        _pending[(int)StatCounter.Deferred]++;
                    }

                    break;
                default:
                    throw new InvalidOperationException("unexpected outcome " + outcome);
            }
        }

        private void Finish(Rcpt r, MessageEventType type, StatCounter counter)
        {
            r.Final = true;
            r.FinalType = type;
            r.Held = false;
            _pending[(int)counter]++;
        }

        private async Task RecordOpAsync()
        {
            List<Rcpt> held = _byDelivery.Values.Where(r => r.Held && !r.Final && r.LastClaim is not null).ToList();
            if (held.Count == 0)
            {
                Note("record skipped (nothing held)");
                return;
            }

            Rcpt row = held[_rng.Next(held.Count)];
            double roll = _rng.NextDouble();
            if (roll < 0.55)
            {
                await ApplyRecordAsync(row, row.LastClaim!, DeliveryOutcome.Delivered, null, true, stale: false);
            }
            else if (roll < 0.80)
            {
                await ApplyRecordAsync(row, row.LastClaim!, DeliveryOutcome.Deferred, Now + TimeSpan.FromMinutes(_rng.Next(1, 120)), true, stale: false);
            }
            else if (roll < 0.90)
            {
                await ApplyRecordAsync(row, row.LastClaim!, DeliveryOutcome.Deferred, Now + TimeSpan.FromMinutes(_rng.Next(1, 30)), false, stale: false);
            }
            else
            {
                await ApplyRecordAsync(row, row.LastClaim!, DeliveryOutcome.Failed, null, true, stale: false);
            }
        }

        private async Task StaleRecordOpAsync()
        {
            if (_stale.Count == 0)
            {
                return;
            }

            ClaimedDelivery claim = _stale[_rng.Next(_stale.Count)];
            Rcpt row = _byDelivery[claim.DeliveryId];
            await ApplyRecordAsync(row, claim, DeliveryOutcome.Delivered, null, true, stale: true);
        }

        // ---- Time, leases, expiry

        private Task ClockOpAsync()
        {
            TimeSpan[] jumps = [TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(6), TimeSpan.FromMinutes(40), TimeSpan.FromHours(3), TimeSpan.FromHours(25), TimeSpan.FromDays(2), TimeSpan.FromDays(6)];
            TimeSpan by = _rng.NextDouble() < 0.6 ? jumps[_rng.Next(3)] : jumps[_rng.Next(jumps.Length)];
            // The virtual clock stays below the first of January 2028 even in long runs: advance less when far from the start.
            if (Now - Start > TimeSpan.FromDays(300))
            {
                by = TimeSpan.FromMinutes(6);
            }

            _t.Clock.Advance(by);
            Note($"clock +{by}");
            return Task.CompletedTask;
        }

        private async Task ExpirySweepOpAsync()
        {
            DateTimeOffset now = Now;
            var expected = _byDelivery.Values.Where(r => !r.Final && r.ExpiresAt <= now && (!r.Held || r.LeaseUntil <= now)).Select(r => r.DeliveryId).ToHashSet();
            IReadOnlyList<ClaimedDelivery> got = await S.Deliveries.ClaimExpiredAsync("reaper", 10_000, now, default);
            Note($"expiry sweep: {got.Count} of {expected.Count} expected");
            Check(got.Select(c => c.DeliveryId).ToHashSet().SetEquals(expected), $"the expiry sweep returned {got.Count} deliveries, expected {expected.Count}");
            foreach (ClaimedDelivery c in got)
            {
                Rcpt r = _byDelivery[c.DeliveryId];
                r.Held = false;
                await ApplyRecordAsync(r, c, DeliveryOutcome.Expired, null, true, stale: false);
            }

            // Swept deliveries are final: a second sweep finds nothing.
            Check((await S.Deliveries.ClaimExpiredAsync("reaper", 10_000, now, default)).Count == 0, "a second expiry sweep found deliveries again");
        }

        private async Task ReleaseOpAsync()
        {
            DateTimeOffset now = Now;
            if (_rng.NextDouble() < 0.7)
            {
                var expected = _byDelivery.Values.Where(r => !r.Final && r.Held && r.LeaseUntil <= now).ToList();
                QueueStats before = await S.Deliveries.GetQueueStatsAsync(default);
                int n = await S.Deliveries.ReleaseExpiredLeasesAsync(now, default);
                Note($"release expired leases: {n} (expected {expected.Count}); queue before: {before}");
                Check(n == expected.Count, $"ReleaseExpiredLeases released {n}, expected {expected.Count}: " + string.Join("; ", expected.Select(r => $"{r.Address} of {r.MessageId:N} lease until {r.LeaseUntil:o} attempt {r.Attempt}")));
                MarkExpiredLeasesReleased();
            }
            else
            {
                var held = _byDelivery.Values.Where(r => !r.Final && r.Held).ToList();
                int n = await S.Deliveries.ReleaseOwnedLeasesAsync("worker-1", default);
                Note($"graceful release of own leases: {n} (expected {held.Count})");
                Check(n == held.Count, $"ReleaseOwnedLeases released {n}, expected {held.Count}");
                foreach (Rcpt r in held)
                {
                    r.Held = false;
                }
            }
        }

        /// <summary>The leases that ran out belong to workers that never reported: released and flagged.</summary>
        private void MarkExpiredLeasesReleased()
        {
            DateTimeOffset now = Now;
            foreach (Rcpt r in _byDelivery.Values.Where(r => !r.Final && r.Held && r.LeaseUntil <= now).ToList())
            {
                r.Lost = true;
                r.Held = false;
                if (r.LastClaim is not null)
                {
                    _stale.Add(r.LastClaim);
                }
            }
        }

        private async Task ExtendOpAsync()
        {
            DateTimeOffset now = Now;
            var live = _byDelivery.Values.Where(r => !r.Final && r.Held && r.LeaseUntil > now).ToList();
            if (live.Count == 0)
            {
                return;
            }

            Rcpt r = live[_rng.Next(live.Count)];
            bool ok = await S.Deliveries.ExtendLeaseAsync(r.DeliveryId, "worker-1", now + Lease * 2, default);
            Note($"extend lease of {r.Address}: {ok}");
            Check(ok, "the holder could not extend its running lease");
            r.LeaseUntil = now + Lease * 2;
            Check(!await S.Deliveries.ExtendLeaseAsync(r.DeliveryId, "somebody-else", now + Lease * 3, default), "a stranger extended a lease");
        }

        // ---- Statistics

        private async Task StatsOpAsync()
        {
            long k = _rng.Next(1, 6);
            S.Stats.Add(new StatKey(Now, TenantA, "manual.example", "dest0.example"), StatCounter.Rejected, k);
            _pending[(int)StatCounter.Rejected] += k;
            if (_rng.NextDouble() < 0.6)
            {
                await FlushAsync();
            }
            else
            {
                Note($"stats +{k} rejected (unflushed)");
            }
        }

        private async Task FlushAsync()
        {
            await _t.FlushStatsAsync();
            for (int i = 0; i < CounterCount; i++)
            {
                _flushed[i] += _pending[i];
                _pending[i] = 0;
            }

            Note("stats flushed");
        }

        private async Task<long[]> StoredStatsAsync()
        {
            var rows = await S.Stats.QueryAsync(null, Start.AddDays(-2), Start.AddDays(2000), false, default);
            var sums = new long[CounterCount];
            foreach (StatRow row in rows)
            {
                sums[(int)StatCounter.Accepted] += row.Accepted;
                sums[(int)StatCounter.Delivered] += row.Delivered;
                sums[(int)StatCounter.Deferred] += row.Deferred;
                sums[(int)StatCounter.HardBounce] += row.HardBounce;
                sums[(int)StatCounter.SoftBounce] += row.SoftBounce;
                sums[(int)StatCounter.Expired] += row.Expired;
                sums[(int)StatCounter.Complained] += row.Complained;
                sums[(int)StatCounter.Rejected] += row.Rejected;
                sums[(int)StatCounter.Suppressed] += row.Suppressed;
            }

            return sums;
        }

        private async Task CheckStatsAsync(string when)
        {
            long[] stored = await StoredStatsAsync();
            for (int i = 0; i < CounterCount; i++)
            {
                long low = _flushed[i];
                long high = _flushed[i] + _uncertain[i];
                Check(stored[i] >= low && stored[i] <= high, $"{when}: statistics counter {(StatCounter)i} is {stored[i]}, expected {low}{(high != low ? ".." + high : string.Empty)} (flushed total; a crash loses only the unflushed window and never counts twice)");
                _flushed[i] = stored[i];
                _uncertain[i] = 0;
            }
        }

        // ---- Webhook outbox

        private async Task WebhookOpAsync()
        {
            DateTimeOffset now = Now;
            bool all = _rng.Next(3) == 0;
            int max = all ? 10_000 : _rng.Next(1, 10);
            var eligible = _outbox.Where(kv => !kv.Value.Done && kv.Value.Due <= now && kv.Value.HeldUntil <= now).Select(kv => kv.Key).ToHashSet();
            IReadOnlyList<WebhookOutboxItem> got = await S.Webhooks.ClaimDueAsync("dispatcher", max, now, Lease, default);
            Note($"webhook claim max {max}: {got.Count} of {eligible.Count} due");
            Check(got.Count == Math.Min(max, eligible.Count), $"the outbox claim returned {got.Count}, expected {Math.Min(max, eligible.Count)}");
            Check(got.All(i => eligible.Contains(i.EventId)) && got.Select(i => i.EventId).Distinct().Count() == got.Count, "the outbox claim returned an item twice, a finished item, or one that is not due or still leased");
            foreach (WebhookOutboxItem item in got)
            {
                OutboxEntry e = _outbox[item.EventId];
                e.HeldUntil = now + Lease;
                double roll = _rng.NextDouble();
                var attempt = new WebhookAttemptRecord(item.Id, now, roll < 0.7 ? 200 : 503, TimeSpan.FromMilliseconds(5), null, null);
                if (roll < 0.6)
                {
                    await S.Webhooks.CompleteAsync(item.Id, attempt, WebhookOutboxState.Delivered, null, default);
                    e.Done = true;
                }
                else if (roll < 0.8)
                {
                    DateTimeOffset next = now + TimeSpan.FromMinutes(_rng.Next(1, 60));
                    await S.Webhooks.CompleteAsync(item.Id, attempt, WebhookOutboxState.Pending, next, default);
                    e.Due = next;
                    e.HeldUntil = DateTimeOffset.MinValue;
                }
                else if (roll < 0.85)
                {
                    await S.Webhooks.CompleteAsync(item.Id, attempt, WebhookOutboxState.Failed, null, default);
                    e.Done = true;
                }

                // else: the dispatcher died holding it; the lease will run out (or the start releases it)
            }
        }

        // ---- Cancel

        private async Task CancelOpAsync()
        {
            var candidates = _messages.Where(m => m.Rcpts.Any(r => !r.Final) && m.Rcpts.All(r => !r.Held || r.Final)).ToList();
            if (candidates.Count == 0)
            {
                return;
            }

            Mdl m = candidates[_rng.Next(candidates.Count)];
            DateTimeOffset now = Now;
            var waiting = m.Rcpts.Where(r => !r.Final).ToList();
            CancelResult result = await S.Deliveries.CancelAsync(m.Tenant, m.Id, null, now, null, default);
            Note($"cancel {m.Id:N}: {result.Cancelled.Count} cancelled (expected {waiting.Count})");
            Check(result.Cancelled.OrderBy(a => a, StringComparer.Ordinal).SequenceEqual(waiting.Select(r => r.Address).OrderBy(a => a, StringComparer.Ordinal)), "cancel did not cancel exactly the waiting recipients");
            foreach (Rcpt r in waiting)
            {
                r.Final = true;
                r.FinalType = MessageEventType.Cancelled;
            }

            _touched.Add(m.Id);
        }

        private async Task MaintenanceOpAsync()
        {
            await FlushAsync();   // maintenance flushes the statistics buffer itself on some backends; flushing first keeps the model exact either way
            var reports = await S.Maintenance.RunAsync(Now, default);
            Note($"maintenance: {reports.Count} jobs");
            if (_t.MaintenanceReleasesExpiredLeases)
            {
                MarkExpiredLeasesReleased();
            }
        }

        // ---- Configuration

        private async Task ConfigOpAsync()
        {
            IConfigStore c = S.Config;
            DateTimeOffset now = Now;
            int kind = _rng.Next(7);
            int n = ++_configSeq;
            switch (kind)
            {
                case 0:
                {
                    var t = new Tenant(Ids.New(), "Tenant " + n, "tenant-" + n, true, now, false);
                    await c.UpsertTenantAsync(t, default);
                    _tenants.Add(t);
                    Note("config: tenant " + t.Slug);
                    break;
                }

                case 1:
                {
                    var cred = new SmtpCredential(Ids.New(), TenantA, "user-" + n, "hash-" + n, true, now);
                    await c.UpsertSmtpCredentialAsync(cred, default);
                    _credentials.Add(cred);
                    Note("config: smtp credential " + cred.UserName);
                    break;
                }

                case 2:
                {
                    byte[] hash = new byte[32];
                    _rng.NextBytes(hash);
                    var key = new ApiKeyRecord(Ids.New(), TenantA, "key" + n, "eg_" + n, hash, "send", now, null, null);
                    await c.AddApiKeyAsync(key, default);
                    bool revoke = _rng.Next(3) == 0;
                    if (revoke)
                    {
                        Check(await c.RevokeApiKeyAsync(TenantA, key.Id, now, default), "revoking a new key failed");
                    }

                    _apiKeys.Add((key, revoke));
                    Note($"config: api key {key.Name} revoked {revoke}");
                    break;
                }

                case 3:
                {
                    var domain = new DomainRecord(Ids.New(), TenantA, $"dom{n}.example", DomainStatus.Verified, null, false, now, now, now.AddDays(1), 0, null, false, null);
                    await c.UpsertDomainAsync(domain, default);
                    _domains.Add(domain);
                    var dkim = new DkimKeyRecord(Ids.New(), domain.Id, "s" + n, [1, 2, (byte)n], "PUBKEY" + n, now, true, null);
                    await c.AddDkimKeyAsync(dkim, default);
                    _dkimKeys.Add(dkim);
                    Note($"config: domain {domain.Name} with dkim key {dkim.Selector}");
                    break;
                }

                case 4:
                {
                    var key = (TenantB, $"manual{n % 5}@blocked.example");
                    if (_manualSuppressions.TryGetValue(key, out bool present) && present)
                    {
                        Check(await c.RemoveSuppressionAsync(key.Item1, key.Item2, default), "removing a suppression failed");
                        _manualSuppressions[key] = false;
                        Note("config: suppression removed " + key.Item2);
                    }
                    else
                    {
                        await c.AddSuppressionAsync(new SuppressionRecord(key.Item1, key.Item2, SuppressionReason.Manual, "crash loop", now, null), default);
                        _manualSuppressions[key] = true;
                        Note("config: suppression added " + key.Item2);
                    }

                    break;
                }

                case 5:
                {
                    string name = "setting" + (n % 4);
                    string json = "{\"v\":" + n + "}";
                    await c.SetSettingAsync(new SettingRecord(name, null, json, now), default);
                    _settings[name] = json;
                    Note("config: setting " + name);
                    break;
                }

                default:
                {
                    long delta = _rng.Next(1, 5);
                    await c.AddSendingCountersAsync([new SendingCounterRecord(1, TenantA, "", 0, _hour0, delta)], 0, 0, default);
                    _sendingCounter += delta;
                    Note("config: sending counter +" + delta);
                    break;
                }
            }
        }

        private async Task VerifyConfigAsync()
        {
            IConfigStore c = S.Config;
            var tenants = (await c.GetTenantsAsync(default)).Select(t => t.Id).ToHashSet();
            Check(_tenants.All(t => tenants.Contains(t.Id)), "an acknowledged tenant is gone");
            foreach (SmtpCredential cred in _credentials)
            {
                SmtpCredential? found = await c.FindSmtpCredentialAsync(cred.UserName, default);
                Check(found is not null && found.PasswordHash == cred.PasswordHash, $"SMTP credential {cred.UserName} is gone");
            }

            var keys = (await c.GetApiKeysAsync(TenantA, default)).ToDictionary(k => k.Id);
            foreach (var (key, revoked) in _apiKeys)
            {
                Check(keys.TryGetValue(key.Id, out ApiKeyRecord? found) && (found.RevokedAt is not null) == revoked, $"API key {key.Name} is gone or its revocation was lost");
                Check((await c.FindApiKeyAsync(key.KeyHash, default)) is not null, $"API key {key.Name} cannot be found by its hash");
            }

            foreach (DomainRecord d in _domains)
            {
                Check(await c.FindDomainByNameAsync(d.Name, default) is not null, $"domain {d.Name} is gone");
            }

            foreach (DkimKeyRecord k in _dkimKeys)
            {
                var stored = await c.GetDkimKeysAsync(k.DomainId, default);
                Check(stored.Any(s => s.Id == k.Id && s.Selector == k.Selector && s.PublicKeyBase64 == k.PublicKeyBase64), $"DKIM key {k.Selector} is gone");
            }

            foreach (var ((tenant, address), present) in _manualSuppressions)
            {
                Check(await c.IsSuppressedAsync(tenant, address, default) == present, $"suppression of {address} should be {(present ? "present" : "absent")}");
            }

            foreach (var (tenant, address) in _suppressed)
            {
                Check(await c.IsSuppressedAsync(tenant, address, default), $"{address} was hard bounced and must be suppressed");
            }

            var settings = (await c.GetSettingsAsync(null, default)).ToDictionary(s => s.Key, s => s.ValueJson);
            foreach (var (name, json) in _settings)
            {
                Check(settings.TryGetValue(name, out string? stored) && stored == json, $"setting {name} lost its value");
            }

            long counted = (await c.GetSendingCountersAsync(0, 0, default)).Where(s => s.Scope == 1 && s.TenantId == TenantA).Sum(s => s.Count);
            Check(counted == _sendingCounter, $"sending counters: {counted}, expected {_sendingCounter}");
        }

        // ---- Restart

        private async Task RestartOpAsync()
        {
            if (_rng.NextDouble() < 0.15)
            {
                Note("graceful restart");
                await FlushAsync();   // a graceful stop flushes the statistics
                await _t.RestartGracefullyAsync();
                Graceful++;
                AfterRestart(crashed: false);
                await VerifyAsync(full: true, "after a graceful restart");
                return;
            }

            // Writes still in flight when the process is killed.
            var inflight = new List<(AcceptedMessage Message, string[] To, string? Key, Task<IntakeResult> Task)>();
            int n = _rng.NextDouble() < 0.5 ? _rng.Next(1, 4) : 0;
            for (int i = 0; i < n; i++)
            {
                string[] to = PickRecipients();
                AcceptedMessage m = BuildMessage(_rng.Next(4) == 0 ? TenantB : TenantA, to, null);
                inflight.Add((m, to, null, S.Intake.AcceptAsync(m, default).AsTask()));
            }

            Note($"KILL with {n} writes in flight");
            long[] pendingAtKill = (long[])_pending.Clone();
            await _t.KillAndReopenAsync();
            Kills++;

            // What the in-flight writes did is decided now; acknowledged ones must exist, the others either exist whole or not at all.
            foreach (var (message, to, key, task) in inflight)
            {
                bool acked = false;
                try
                {
                    IntakeResult r = await task;
                    acked = r.Status == IntakeStatus.Accepted;
                }
                catch (Exception ex) when (ex is not XunitException)
                {
                    // abandoned: unknown outcome
                }

                bool exists = await S.Deliveries.GetRawAsync(message.MessageId, default) is not null;
                Check(!acked || exists, $"an acknowledged in-flight message {message.MessageId:N} was lost by the kill");
                if (exists)
                {
                    Note($"in-flight message {message.MessageId:N} survived (acknowledged: {acked})");
                    Register(message, to, key);
                    _uncertain[(int)StatCounter.Accepted] += to.Length;
                }
            }

            // The unflushed window is gone.
            for (int i = 0; i < CounterCount; i++)
            {
                _pending[i] = 0;
            }

            _ = pendingAtKill;
            AfterRestart(crashed: true);
            await VerifyAsync(full: Kills % 3 == 1, "after a kill");
        }

        private void AfterRestart(bool crashed)
        {
            // Whatever a worker held when the process died: its holder is gone.
            if (crashed)
            {
                foreach (Rcpt r in _byDelivery.Values.Where(r => !r.Final && r.Held))
                {
                    if (r.LastClaim is not null)
                    {
                        _stale.Add(r.LastClaim);
                    }

                    if (_t.ClearsLeasesOnStart)
                    {
                        r.Lost = true;
                        r.Held = false;
                    }
                }

                if (_t.ClearsLeasesOnStart)
                {
                    foreach (OutboxEntry e in _outbox.Values)
                    {
                        e.HeldUntil = DateTimeOffset.MinValue;
                    }
                }
            }
            else
            {
                // A graceful stop of the store alone releases nothing the workers hold; the engine would release its own leases first.
                foreach (Rcpt r in _byDelivery.Values.Where(r => !r.Final && r.Held))
                {
                    if (_t.ClearsLeasesOnStart)
                    {
                        r.Lost = true;
                        r.Held = false;
                    }
                }

                if (_t.ClearsLeasesOnStart)
                {
                    foreach (OutboxEntry e in _outbox.Values)
                    {
                        e.HeldUntil = DateTimeOffset.MinValue;
                    }
                }
            }
        }

        // ---- Verification

        private async Task VerifyAsync(bool full, string when)
        {
            DateTimeOffset now = Now;
            var nonFinal = _byDelivery.Values.Where(r => !r.Final).ToList();
            QueueStats q = await S.Deliveries.GetQueueStatsAsync(default);
            Check(q.Queued + q.Leased + q.Deferred == nonFinal.Count, $"{when}: the queue holds {q.Queued + q.Leased + q.Deferred} deliveries ({q}), the model {nonFinal.Count}: an acknowledged recipient is missing or a final one is still queued");
            int leased = nonFinal.Count(r => r.Held && r.LeaseUntil > now);
            Check(q.Leased == leased, $"{when}: {q.Leased} leased deliveries, expected {leased}");

            IEnumerable<Mdl> scope = full ? _messages : _messages.Where(m => _touched.Contains(m.Id));
            foreach (Mdl m in scope.ToList())
            {
                bool open = m.Rcpts.Any(r => !r.Final);
                byte[]? raw = await S.Deliveries.GetRawAsync(m.Id, default);
                Check(open == (raw is not null), $"{when}: message {m.Id:N} is {(open ? "open but its raw message is gone" : "final but its raw message is still stored")}");
                if (_t.IsFull)
                {
                    MessageDetail? detail = await S.History.GetAsync(m.Tenant, m.Id, default);
                    Check(detail is not null, $"{when}: history lost message {m.Id:N}");
                    Check(detail!.Recipients.OrderBy(a => a, StringComparer.Ordinal).SequenceEqual(m.Rcpts.Select(r => r.Address).OrderBy(a => a, StringComparer.Ordinal)), $"{when}: history of {m.Id:N} has other recipients than were accepted");
                    var events = await S.History.GetEventsAsync(m.Tenant, m.Id, default);
                    foreach (Rcpt r in m.Rcpts)
                    {
                        var finals = events.Where(e => e.Recipient == r.Address && e.Type is MessageEventType.Delivered or MessageEventType.Bounced or MessageEventType.Expired or MessageEventType.Suppressed or MessageEventType.Cancelled).ToList();
                        Check(finals.Count == (r.Final ? 1 : 0), $"{when}: {r.Address} of {m.Id:N} has {finals.Count} final events ({string.Join(',', finals.Select(f => f.Type))}), expected {(r.Final ? 1 : 0)}");
                        if (r.Final)
                        {
                            Check(finals[0].Type == r.FinalType, $"{when}: {r.Address} of {m.Id:N} ended as {finals[0].Type}, expected {r.FinalType}");
                        }
                    }
                }
            }

            if (!full)
            {
                _touched.Clear();
                if (when != "periodic")
                {
                    return;
                }

                await CheckStatsAsync(when);
                return;
            }

            _touched.Clear();
            await CheckStatsAsync(when);
            await VerifyConfigAsync();

            // An idempotency key accepted less than its lifetime ago still deduplicates after a restart.
            foreach (var ((tenant, key), m) in _keys.Where(k => now - k.Value.At < KeyLifetime - TimeSpan.FromMinutes(1)).Take(8).ToList())
            {
                AcceptedMessage again = _t.Msg(tenant: tenant, idempotencyKey: key);
                IntakeResult r = await S.Intake.AcceptAsync(again, default);
                Check(r.Status == IntakeStatus.DuplicateIdempotencyKey && r.MessageId == m.Id, $"{when}: idempotency key {key} no longer deduplicates");
            }

            // Nothing is claimable that should not be, and a delivery abandoned by a dead holder is claimable once its lease ran out.
            if (!_t.ClearsLeasesOnStart)
            {
                var stillLeased = nonFinal.Where(r => r.Held && r.LeaseUntil > now).Select(r => r.DeliveryId).ToHashSet();
                Check(stillLeased.Count == q.Leased, $"{when}: lease bookkeeping differs");
            }
        }

        // ---- Drain

        private async Task DrainAsync()
        {
            // Everything that is left reaches a final state with the virtual clock alone: leases run out, deferrals become due, lifetimes pass.
            for (int round = 0; round < 40 && _byDelivery.Values.Any(r => !r.Final); round++)
            {
                _t.Clock.Advance(Lease + TimeSpan.FromMinutes(2));
                if (round % 6 == 5)
                {
                    await ExpirySweepOpAsync();
                }

                var claimed = await ClaimAsync(10_000, exact: true);
                foreach (var (claim, row) in claimed)
                {
                    double roll = _rng.NextDouble();
                    if (round < 4 && roll < 0.3)
                    {
                        await ApplyRecordAsync(row, claim, DeliveryOutcome.Deferred, Now + TimeSpan.FromMinutes(_rng.Next(1, 8)), true, stale: false);
                    }
                    else if (roll < 0.9)
                    {
                        await ApplyRecordAsync(row, claim, DeliveryOutcome.Delivered, null, true, stale: false);
                    }
                    else
                    {
                        await ApplyRecordAsync(row, claim, DeliveryOutcome.Failed, null, true, stale: false);
                    }
                }
            }

            _t.Clock.Advance(TimeSpan.FromDays(7));
            await ExpirySweepOpAsync();
            Check(_byDelivery.Values.All(r => r.Final), "the drain left deliveries in the model that the store never handed out");
            await FlushAsync();
            await VerifyAsync(full: true, "after the drain");
            QueueStats q = await S.Deliveries.GetQueueStatsAsync(default);
            Check(q is { Queued: 0, Leased: 0, Deferred: 0, SpoolBytes: 0 }, $"the drained queue is not empty: {q}");

            // The outbox drains the same way and every event the engine reported came out exactly once.
            for (int round = 0; round < 30 && _outbox.Values.Any(e => !e.Done); round++)
            {
                _t.Clock.Advance(Lease + TimeSpan.FromHours(2));
                IReadOnlyList<WebhookOutboxItem> got = await S.Webhooks.ClaimDueAsync("dispatcher", 100_000, Now, Lease, default);
                var expected = _outbox.Where(kv => !kv.Value.Done).Select(kv => kv.Key).ToHashSet();
                Check(got.Select(i => i.EventId).ToHashSet().SetEquals(expected) && got.Count == expected.Count, $"the outbox drain returned {got.Count} items, expected {expected.Count}");
                foreach (WebhookOutboxItem item in got)
                {
                    await S.Webhooks.CompleteAsync(item.Id, new WebhookAttemptRecord(item.Id, Now, 200, TimeSpan.FromMilliseconds(1), null, null), WebhookOutboxState.Delivered, null, default);
                    _outbox[item.EventId].Done = true;
                }
            }

            Check((await S.Webhooks.ClaimDueAsync("dispatcher", 100_000, Now + TimeSpan.FromDays(30), Lease, default)).Count == 0, "the outbox still had items after the drain");
            Note("drained");
        }
    }
}
