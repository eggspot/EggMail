namespace Mta.Storage.Logic;

public static class StorageOptionsValidation
{
    /// <summary>Validates option ranges (decision 28: <c>0</c> = keep forever, negative invalid; decision O: content 6..30).</summary>
    /// <exception cref="ArgumentException">An option is out of range.</exception>
    public static void Validate(StorageOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        RetentionOptions r = options.Retention;
        NonNegative(r.MetadataDays, "Retention:MetadataDays");
        NonNegative(r.StatsHourlyDays, "Stats:HourlyRetentionDays");
        NonNegative(r.StatsDailyDays, "Stats:DailyRetentionDays");
        NonNegative(r.WebhookOutboxDays, "Webhooks:OutboxRetentionDays");
        NonNegative(r.WebhookAttemptLogDays, "Webhooks:AttemptLogDays");
        NonNegative(r.RecipientDomainTopNHourly, "Stats:RecipientDomainTopNHourly");
        NonNegative(r.RecipientDomainTopNDaily, "Stats:RecipientDomainTopNDaily");
        NonNegative(options.Inbound.RetentionDays, "Inbound:RetentionDays");
        NonNegative(options.Inbound.MaxRetentionDays, "Inbound:MaxRetentionDays");
        if (options.Inbound.MaxRetentionDays > 0 && (options.Inbound.RetentionDays == 0 || options.Inbound.RetentionDays > options.Inbound.MaxRetentionDays))
        {
            throw new ArgumentException("Inbound:RetentionDays must be between 1 and Inbound:MaxRetentionDays when a ceiling is set.");
        }
        if (r.MaxSeriesPerHour < 1)
        {
            throw new ArgumentException("Stats:MaxSeriesPerHour must be at least 1.");
        }

        if (options.Content.RetentionDays is < 6 or > 30)
        {
            throw new ArgumentException("Content:RetentionDays must be between 6 and 30 (no unlimited value, decision O).");
        }

        if (options.Content.MaxStoredBodyBytes < 0)
        {
            throw new ArgumentException("Content:MaxStoredBodyBytes must not be negative.");
        }

        NonNegative(options.History.RecentEvents, "History:RecentEvents");
        if (options.Queue.MaxLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentException("Queue:MaxLifetime must be positive.");
        }

        if (options.Queue.IdempotencyKeyLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentException("Queue:IdempotencyKeyLifetime must be positive.");
        }

        SqliteOptions s = options.Sqlite;
        if (s.WriterMaxBatch < 1 || s.WriterQueueCapacity < 1 || s.WriterBatchWindow < TimeSpan.Zero)
        {
            throw new ArgumentException("Sqlite writer batch/queue options must be positive.");
        }

        if (s.PressureQueueDepth < 1 || s.PressureQueueDuration < TimeSpan.Zero || s.PressureCommitP99 <= TimeSpan.Zero || s.PressureWindow <= TimeSpan.Zero)
        {
            throw new ArgumentException("Sqlite pressure thresholds must be positive (Sqlite:PressureQueueDuration may be zero).");
        }

        PostgresOptions pg = options.Postgres;
        if (pg.PressureSampleInterval < TimeSpan.FromSeconds(1) || pg.PressureWindow < pg.PressureSampleInterval || pg.PressureWindow.TotalSeconds > pg.PressureSampleInterval.TotalSeconds * PostgresOptions.MaxPressureSamples
            || pg.PressureWaitingPercent is < 1 or > 100)
        {
            throw new ArgumentException($"Postgres pressure options out of range (sample interval at least 1 s, window between one and {PostgresOptions.MaxPressureSamples} intervals, waiting percent 1 to 100).");
        }
    }

    private static void NonNegative(int value, string name)
    {
        if (value < 0)
        {
            throw new ArgumentException($"{name} must not be negative (0 means keep forever).");
        }
    }

    /// <summary>Names of retention knobs set to 0 (unlimited); surfaced as health warnings.</summary>
    public static IReadOnlyList<string> UnlimitedRetentionKnobs(StorageOptions options)
    {
        var list = new List<string>();
        Add(options.Retention.MetadataDays, "Retention:MetadataDays", list);
        Add(options.Retention.StatsHourlyDays, "Stats:HourlyRetentionDays", list);
        Add(options.Retention.StatsDailyDays, "Stats:DailyRetentionDays", list);
        Add(options.Retention.WebhookOutboxDays, "Webhooks:OutboxRetentionDays", list);
        Add(options.Retention.WebhookAttemptLogDays, "Webhooks:AttemptLogDays", list);
        Add(options.Inbound.RetentionDays, "Inbound:RetentionDays", list);
        return list;

        static void Add(int value, string name, List<string> into)
        {
            if (value == 0)
            {
                into.Add(name);
            }
        }
    }
}
