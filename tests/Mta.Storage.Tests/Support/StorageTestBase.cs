using Mta.Core;

namespace Mta.Storage.Tests;

/// <summary>A controllable clock. Shared by every backend under test.</summary>
public sealed class TestClock : IClock
{
    private long _ticks;
    private long _stopwatch;

    public TestClock(DateTimeOffset start) => _ticks = start.UtcTicks;

    public DateTimeOffset UtcNow => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);

    public long Timestamp => Interlocked.Increment(ref _stopwatch);

    public void Set(DateTimeOffset value) => Interlocked.Exchange(ref _ticks, value.UtcTicks);

    public void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);
}

/// <summary>
/// Base class of every conformance suite. A backend plugs in by implementing <see cref="CreateAsync"/>; the same
/// facts then run against it. Suites that must behave identically under both history levels take the level from
/// <see cref="Mode"/>.
/// </summary>
public abstract class StorageTestBase : IAsyncLifetime
{
    /// <summary>The instant every test starts at (a Monday, mid-day, so hour and day boundaries are far away).</summary>
    public static readonly DateTimeOffset Start = new(2026, 10, 12, 12, 30, 0, TimeSpan.Zero);

    protected StorageTestBase()
    {
        Clock = new TestClock(Start);
    }

    protected TestClock Clock { get; }

    protected IStorage Storage { get; private set; } = null!;

    protected StorageOptions Options { get; private set; } = null!;

    protected virtual HistoryMode Mode => HistoryMode.Full;

    protected bool IsFull => Mode == HistoryMode.Full;

    /// <summary>Creates (but does not initialize) the storage under test. Must use <see cref="Clock"/>.</summary>
    protected abstract Task<IStorage> CreateAsync(StorageOptions options);

    /// <summary>Override to change options for a whole suite (the history mode is applied afterwards).</summary>
    protected virtual StorageOptions BuildOptions() => new();

    protected static readonly Guid TenantA = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    protected static readonly Guid TenantB = Guid.Parse("b0000000-0000-7000-8000-000000000002");

    public virtual async Task InitializeAsync()
    {
        StorageOptions o = BuildOptions();
        await OpenAsync(WithMode(o, Mode));
    }

    public virtual async Task DisposeAsync()
    {
        if (Storage is not null)
        {
            await Storage.DisposeAsync();
        }
    }

    /// <summary>Replaces the storage under test with one created from <paramref name="options"/> (disposing the old one).</summary>
    protected async Task OpenAsync(StorageOptions options)
    {
        if (Storage is not null)
        {
            await Storage.DisposeAsync();
        }

        Options = options;
        Storage = await CreateAsync(options);
        await Storage.InitializeAsync(CancellationToken.None);
    }

    protected static StorageOptions WithMode(StorageOptions o, HistoryMode mode) => new()
    {
        Backend = o.Backend,
        History = new HistoryOptions { Mode = mode, RecentEvents = o.History.RecentEvents },
        Retention = o.Retention,
        Sqlite = o.Sqlite,
        Postgres = o.Postgres,
        Content = o.Content,
        Queue = o.Queue,
    };

    protected StorageOptions Opts(
        RetentionOptions? retention = null,
        ContentOptions? content = null,
        int? recentEvents = null,
        QueueOptions? queue = null)
    {
        StorageOptions b = BuildOptions();
        return new StorageOptions
        {
            Backend = b.Backend,
            History = new HistoryOptions { Mode = Mode, RecentEvents = recentEvents ?? b.History.RecentEvents },
            Retention = retention ?? b.Retention,
            Sqlite = b.Sqlite,
            Postgres = b.Postgres,
            Content = content ?? b.Content,
            Queue = queue ?? b.Queue,
        };
    }

    // Builders

    private int _seq;

    protected AcceptedMessage Msg(
        Guid? tenant = null,
        string[]? to = null,
        string from = "sender@example.com",
        int size = 2048,
        string? subject = "Hello world",
        string? idempotencyKey = null,
        bool retainRaw = false,
        DateTimeOffset? received = null,
        TimeSpan? lifetime = null,
        string? sendingDomain = "example.com",
        MessageContent? content = null,
        bool noContent = false,
        MessageSource source = MessageSource.Api,
        string? messageIdHeader = null,
        string[]? tags = null,
        bool headersUtf8 = false)
    {
        DateTimeOffset at = received ?? Clock.UtcNow;
        string[] recipients = to ?? ["alice@example.org"];
        int n = Interlocked.Increment(ref _seq);
        byte[] raw = new byte[size];
        new Random(n).NextBytes(raw);
        return new AcceptedMessage
        {
            MessageId = Ids.New(at),
            TenantId = tenant ?? TenantA,
            Source = source,
            EnvelopeFrom = from.Length == 0 ? EmailAddress.Null : EmailAddress.Parse(from),
            Recipients = recipients.Select(r => new AcceptedRecipient(Ids.New(at), EmailAddress.Parse(r))).ToList(),
            Raw = raw,
            ReceivedAt = at,
            ExpiresAt = at + (lifetime ?? TimeSpan.FromDays(5)),
            IdempotencyKey = idempotencyKey,
            RemoteAddress = "203.0.113.9",
            Authenticated = "user",
            Content = noContent ? null : content ?? new MessageContent(subject, "plain body text", "<p>html body</p>", [new AttachmentInfo("a.pdf", "application/pdf", 1234, null)], false),
            RetainRaw = retainRaw,
            SendingDomain = sendingDomain,
            MessageIdHeader = messageIdHeader,
            Tags = tags,
            HeadersUtf8 = headersUtf8,
        };
    }

    protected async Task<AcceptedMessage> AcceptAsync(AcceptedMessage? message = null)
    {
        AcceptedMessage m = message ?? Msg();
        IntakeResult r = await Storage.Intake.AcceptAsync(m, CancellationToken.None);
        Assert.Equal(IntakeStatus.Accepted, r.Status);
        Assert.Equal(m.MessageId, r.MessageId);
        return m;
    }

    protected async Task<IReadOnlyList<ClaimedDelivery>> ClaimAsync(int max = 100, TimeSpan? lease = null, string owner = "worker-1", DateTimeOffset? now = null) =>
        await Storage.Deliveries.ClaimAsync(owner, max, now ?? Clock.UtcNow, lease ?? TimeSpan.FromMinutes(1), CancellationToken.None);

    protected DeliveryAttempt Attempt(
        ClaimedDelivery d,
        DeliveryOutcome outcome,
        DateTimeOffset? next = null,
        SuppressionReason? suppress = null,
        int? smtp = null,
        string? enhanced = null,
        string? message = null,
        IReadOnlyList<WebhookEventDraft>? events = null,
        bool possibleDuplicate = false,
        bool countAttempt = true) => new()
        {
            CountAttempt = countAttempt,
            DeliveryId = d.DeliveryId,
            Outcome = outcome,
            At = Clock.UtcNow,
            SmtpCode = smtp ?? (outcome == DeliveryOutcome.Delivered ? 250 : null),
            EnhancedCode = enhanced,
            Message = message,
            MxHost = "mx.example.org",
            Route = "direct",
            Tls = new TlsInfo(true, "TLS1.3", "TLS_AES_256_GCM_SHA384", "CN=mx.example.org", "CN=Test CA", "ABCD", null, true, "may", null, true, false),
            Duration = TimeSpan.FromMilliseconds(120),
            NextAttemptAt = next,
            PossibleDuplicate = possibleDuplicate,
            Suppress = suppress,
            WebhookEvents = events ?? [],
        };

    protected async Task RecordAsync(ClaimedDelivery d, DeliveryOutcome outcome, DateTimeOffset? next = null, SuppressionReason? suppress = null, IReadOnlyList<WebhookEventDraft>? events = null, int? smtp = null, string? enhanced = null, string? message = null, bool possibleDuplicate = false, bool countAttempt = true) =>
        await Storage.Deliveries.RecordAttemptAsync(Attempt(d, outcome, next, suppress, smtp, enhanced, message, events, possibleDuplicate, countAttempt), CancellationToken.None);

    protected async Task FlushStatsAsync() => await Storage.Stats.FlushAsync(CancellationToken.None);

    protected static WebhookEventDraft Draft(string type, string payload = "{}") => new(Ids.New(), type, payload);

    protected async Task<Guid> AddEndpointAsync(Guid tenant, bool enabled = true, params string[] types)
    {
        var ep = new WebhookEndpointRecord(Ids.New(), tenant, "https://hooks.example.com/" + Guid.NewGuid().ToString("N"), [1, 2, 3], types, enabled, null, null, Clock.UtcNow, null);
        await Storage.Config.UpsertWebhookEndpointAsync(ep, CancellationToken.None);
        return ep.Id;
    }
}
