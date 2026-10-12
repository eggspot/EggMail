using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Mta.Storage.Model;

/// <summary>
/// Provider-specific parts of the model, kept out of the shared configuration (design §2.4): value conversions and
/// anything else a provider must decide (SQLite stores timestamps as UTC unix milliseconds so every comparison runs
/// server-side; PostgreSQL maps them to timestamptz).
/// </summary>
public interface IStorageModelHooks
{
    /// <summary>Called from <c>DbContext.ConfigureConventions</c>: register provider value conversions.</summary>
    void ConfigureConventions(ModelConfigurationBuilder configurationBuilder);

    /// <summary>Called at the end of <c>OnModelCreating</c>: provider-specific table/column tweaks.</summary>
    void OnModelBuilt(ModelBuilder modelBuilder);
}

/// <summary>Hooks that change nothing (the provider default mapping applies).</summary>
public sealed class NoModelHooks : IStorageModelHooks
{
    public static readonly NoModelHooks Instance = new();

    public void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
    }

    public void OnModelBuilt(ModelBuilder modelBuilder)
    {
    }
}

/// <summary>
/// The shared EF model, split into four parts (config, queue, stats, history). On SQLite each part is its own
/// context and its own database file; the PostgreSQL provider composes <see cref="ConfigureAll"/> into one context.
/// Table and column names are snake_case (see <see cref="ApplyColumnNaming"/>).
/// </summary>
public static class StorageModel
{
    /// <summary>
    /// Entity annotation requesting a <c>WITHOUT ROWID</c> table on SQLite (small rows whose primary key is the
    /// clustered order, used for range deletes by leading day). Other providers ignore it.
    /// </summary>
    public const string WithoutRowIdAnnotation = "Mta:WithoutRowId";

    public static void ConfigureAll(ModelBuilder modelBuilder)
    {
        ConfigureConfig(modelBuilder);
        ConfigureQueue(modelBuilder);
        ConfigureStats(modelBuilder);
        ConfigureHistory(modelBuilder);
    }

    public static void ConfigureConfig(ModelBuilder mb)
    {
        mb.Entity<TenantEntity>(e =>
        {
            e.ToTable("tenant").HasKey(x => x.Id);
            e.HasIndex(x => x.Slug).IsUnique();
        });
        mb.Entity<ApiKeyEntity>(e =>
        {
            e.ToTable("api_key").HasKey(x => x.Id);
            e.HasIndex(x => x.KeyHash).IsUnique();
            e.HasIndex(x => x.TenantId);
        });
        mb.Entity<SmtpCredentialEntity>(e =>
        {
            e.ToTable("smtp_credential").HasKey(x => x.Id);
            e.HasIndex(x => x.UserName).IsUnique();
            e.HasIndex(x => x.TenantId);
        });
        mb.Entity<DomainEntity>(e =>
        {
            e.ToTable("domain").HasKey(x => x.Id);
            e.HasIndex(x => x.Name).IsUnique();
            e.HasIndex(x => x.TenantId);
            e.HasIndex(x => x.NextCheckAt);
        });
        mb.Entity<DkimKeyEntity>(e =>
        {
            e.ToTable("dkim_key").HasKey(x => x.Id);
            e.HasIndex(x => x.DomainId);
        });
        mb.Entity<SuppressionEntity>(e =>
        {
            e.ToTable("suppression").HasKey(x => new { x.TenantId, x.Address });
        });
        mb.Entity<WebhookEndpointEntity>(e =>
        {
            e.ToTable("webhook_endpoint").HasKey(x => x.Id);
            e.HasIndex(x => x.TenantId);
        });
        mb.Entity<SettingEntity>(e =>
        {
            e.ToTable("setting").HasKey(x => new { x.TenantId, x.Key });
        });
        mb.Entity<TlsPolicyEntity>(e =>
        {
            e.ToTable("tls_policy").HasKey(x => x.Id);
            e.HasIndex(x => x.DomainPattern).IsUnique();
        });
        mb.Entity<RelayRouteEntity>(e =>
        {
            e.ToTable("relay_route").HasKey(x => x.Id);
        });
        mb.Entity<CertificateEntity>(e =>
        {
            e.ToTable("certificate").HasKey(x => x.Id);
            e.HasIndex(x => x.Name).IsUnique();
            e.HasIndex(x => x.Version);
        });
        mb.Entity<AcmeAccountEntity>(e =>
        {
            e.ToTable("acme_account").HasKey(x => x.Id);
            e.HasIndex(x => x.DirectoryUrl).IsUnique();
        });
        mb.Entity<AcmeRenewalEntity>(e =>
        {
            e.ToTable("acme_renewal").HasKey(x => x.CertificateName);
        });
        mb.Entity<LeaseEntity>(e =>
        {
            e.ToTable("lease").HasKey(x => x.Name);
        });
        mb.Entity<SwitchStateEntity>(e =>
        {
            e.ToTable("switch_state").HasKey(x => x.Id);
            e.Property(x => x.Id).ValueGeneratedNever();
        });
        mb.Entity<DataProtectionKey>(e =>
        {
            e.ToTable("data_protection_key");
        });
        ConfigureChunk<ConfigTransferChunkEntity>(mb, "transfer_chunk_config");
        ApplyColumnNaming(mb);
    }

    public static void ConfigureQueue(ModelBuilder mb)
    {
        mb.Entity<QueuedDeliveryEntity>(e =>
        {
            e.ToTable("delivery_queue").HasKey(x => x.Id);
            e.HasIndex(x => new { x.DueAt, x.Id });
            e.HasIndex(x => new { x.ExpiresAt, x.Id });
        });
        mb.Entity<SpoolMessageEntity>(e =>
        {
            e.ToTable("message_spool").HasKey(x => x.MessageId);
            e.HasIndex(x => x.AwaitingRetention).HasFilter("awaiting_retention = 1");
        });
        mb.Entity<WebhookOutboxEntity>(e =>
        {
            e.ToTable("webhook_outbox").HasKey(x => x.Id);
            e.HasIndex(x => x.NextAttemptAt).HasFilter("state = 0");
            e.HasIndex(x => x.FinishedAt).HasFilter("finished_at IS NOT NULL");
        });
        mb.Entity<IdempotencyKeyEntity>(e =>
        {
            e.ToTable("api_idempotency_key").HasKey(x => new { x.TenantId, x.IdempotencyKey });
            e.HasIndex(x => x.ExpiresAt);
        });
        ConfigureChunk<QueueTransferChunkEntity>(mb, "transfer_chunk_queue");
        ApplyColumnNaming(mb);
    }

    public static void ConfigureStats(ModelBuilder mb)
    {
        mb.Entity<StatAggregateEntity>(e =>
        {
            e.ToTable("stat_aggregate").HasKey(x => new { x.Daily, x.PeriodStart, x.TenantId, x.SendingDomain, x.RecipientDomain });
            e.HasAnnotation(WithoutRowIdAnnotation, true);
        });
        mb.Entity<StatMetaEntity>(e =>
        {
            e.ToTable("stat_meta").HasKey(x => x.Key);
        });
        mb.Entity<RecentEventEntity>(e =>
        {
            e.ToTable("recent_event").HasKey(x => x.Seq);
            e.Property(x => x.Seq).ValueGeneratedOnAdd();
        });
        mb.Entity<WebhookAttemptEntity>(e =>
        {
            e.ToTable("webhook_attempt").HasKey(x => x.Seq);
            e.Property(x => x.Seq).ValueGeneratedOnAdd();
            e.HasIndex(x => new { x.TenantId, x.EndpointId, x.Seq });
            e.HasIndex(x => x.At);
        });
        ConfigureChunk<StatsTransferChunkEntity>(mb, "transfer_chunk_stats");
        ApplyColumnNaming(mb);
    }

    public static void ConfigureHistory(ModelBuilder mb)
    {
        mb.Entity<MessageIndexEntity>(e =>
        {
            e.ToTable("message_index").HasKey(x => new { x.Day, x.MessageId });
            e.HasIndex(x => new { x.TenantId, x.Day, x.MessageId });
            e.HasAnnotation(WithoutRowIdAnnotation, true);
        });
        mb.Entity<MessageRecipientEntity>(e =>
        {
            e.ToTable("message_recipient").HasKey(x => new { x.Day, x.MessageId, x.Recipient });
            e.HasIndex(x => new { x.Recipient, x.Day, x.MessageId });
            e.HasAnnotation(WithoutRowIdAnnotation, true);
        });
        mb.Entity<MessageEventEntity>(e =>
        {
            e.ToTable("message_event").HasKey(x => new { x.Day, x.MessageId, x.EventId });
            e.HasAnnotation(WithoutRowIdAnnotation, true);
        });

        // Content and retained raw rows are large (up to MaxStoredBodyBytes / the whole message), so they stay ordinary
        // rowid tables with a (day, id) unique key: SQLite documents WITHOUT ROWID as a loss for big rows.
        mb.Entity<MessageContentEntity>(e =>
        {
            e.ToTable("message_content").HasKey(x => new { x.Day, x.MessageId });
        });
        mb.Entity<RetainedRawEntity>(e =>
        {
            e.ToTable("message_raw_retained").HasKey(x => new { x.Day, x.MessageId });
        });
        ConfigureChunk<HistoryTransferChunkEntity>(mb, "transfer_chunk_history");
        ApplyColumnNaming(mb);
    }

    private static void ConfigureChunk<T>(ModelBuilder mb, string table) where T : TransferChunkEntity =>
        mb.Entity<T>(e => e.ToTable(table).HasKey(x => new { x.SwitchId, x.ChunkId }));

    /// <summary>Renames every column to snake_case. Idempotent; called by each part.</summary>
    public static void ApplyColumnNaming(ModelBuilder mb)
    {
        foreach (var entity in mb.Model.GetEntityTypes())
        {
            if (entity.GetTableName() is null)
            {
                continue;
            }

            foreach (var property in entity.GetProperties())
            {
                property.SetColumnName(SnakeCase(property.Name));
            }
        }
    }

    /// <summary>PascalCase to snake_case (<c>ReturnPathHost</c> to <c>return_path_host</c>).</summary>
    public static string SnakeCase(string name)
    {
        var sb = new System.Text.StringBuilder(name.Length + 4);
        for (int i = 0; i < name.Length; i++)
        {
            char c = name[i];
            if (char.IsUpper(c))
            {
                if (i > 0 && (!char.IsUpper(name[i - 1]) || (i + 1 < name.Length && char.IsLower(name[i + 1]))))
                {
                    sb.Append('_');
                }

                sb.Append(char.ToLowerInvariant(c));
            }
            else
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }
}
