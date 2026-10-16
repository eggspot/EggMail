using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Mta.Storage.Model;

namespace Mta.Storage.Postgres;

/// <summary>
/// The single EF context of the PostgreSQL backend: all four model parts (config, queue, stats, history) composed with
/// <see cref="StorageModel.ConfigureAll"/>. On SQLite each part is its own context and file; here one database holds
/// everything, so one transaction can span them (design §4.2). EF is used for the configuration store and as the
/// schema's source of truth in tests; the hot paths use hand-written SQL on Npgsql (see <see cref="PostgresQueueStore"/>).
/// </summary>
public class PostgresDbContext : DbContext, IConfigDbSets, IQueueDbSets, IStatsDbSets, IHistoryDbSets
{
    private readonly IStorageModelHooks _hooks;

    public PostgresDbContext(DbContextOptions<PostgresDbContext> options, IStorageModelHooks hooks) : base(options) => _hooks = hooks;

    /// <summary>For the pooled read context: the hooks travel in the options (<see cref="ModelHooksOptionsExtensions.UseModelHooks{TContext}"/>).</summary>
    protected PostgresDbContext(DbContextOptions options) : base(options) => _hooks = options.HooksOf();

    public DbSet<TenantEntity> Tenants => Set<TenantEntity>();
    public DbSet<ApiKeyEntity> ApiKeys => Set<ApiKeyEntity>();
    public DbSet<SmtpCredentialEntity> SmtpCredentials => Set<SmtpCredentialEntity>();
    public DbSet<DomainEntity> Domains => Set<DomainEntity>();
    public DbSet<DkimKeyEntity> DkimKeys => Set<DkimKeyEntity>();
    public DbSet<SuppressionEntity> Suppressions => Set<SuppressionEntity>();
    public DbSet<WebhookEndpointEntity> WebhookEndpoints => Set<WebhookEndpointEntity>();
    public DbSet<SettingEntity> Settings => Set<SettingEntity>();
    public DbSet<TlsPolicyEntity> TlsPolicies => Set<TlsPolicyEntity>();
    public DbSet<RelayRouteEntity> RelayRoutes => Set<RelayRouteEntity>();
    public DbSet<CertificateEntity> Certificates => Set<CertificateEntity>();
    public DbSet<AcmeAccountEntity> AcmeAccounts => Set<AcmeAccountEntity>();
    public DbSet<AcmeRenewalEntity> AcmeRenewals => Set<AcmeRenewalEntity>();
    public DbSet<LeaseEntity> Leases => Set<LeaseEntity>();
    public DbSet<SwitchStateEntity> SwitchStates => Set<SwitchStateEntity>();
    public DbSet<InboundDomainSettingsEntity> InboundSettings => Set<InboundDomainSettingsEntity>();
    public DbSet<InboundRouteEntity> InboundRoutes => Set<InboundRouteEntity>();
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    public DbSet<QueuedDeliveryEntity> Deliveries => Set<QueuedDeliveryEntity>();
    public DbSet<SpoolMessageEntity> Spool => Set<SpoolMessageEntity>();
    public DbSet<WebhookOutboxEntity> WebhookOutbox => Set<WebhookOutboxEntity>();
    public DbSet<IdempotencyKeyEntity> IdempotencyKeys => Set<IdempotencyKeyEntity>();
    public DbSet<InboundMessageEntity> InboundMessages => Set<InboundMessageEntity>();
    public DbSet<InboundMessageRawEntity> InboundRaw => Set<InboundMessageRawEntity>();

    public DbSet<StatAggregateEntity> StatAggregates => Set<StatAggregateEntity>();
    public DbSet<StatMetaEntity> StatMeta => Set<StatMetaEntity>();
    public DbSet<RecentEventEntity> RecentEvents => Set<RecentEventEntity>();
    public DbSet<WebhookAttemptEntity> WebhookAttempts => Set<WebhookAttemptEntity>();

    public DbSet<MessageIndexEntity> MessageIndex => Set<MessageIndexEntity>();
    public DbSet<MessageRecipientEntity> MessageRecipients => Set<MessageRecipientEntity>();
    public DbSet<MessageEventEntity> MessageEvents => Set<MessageEventEntity>();
    public DbSet<MessageContentEntity> MessageContents => Set<MessageContentEntity>();
    public DbSet<RetainedRawEntity> RetainedRaw => Set<RetainedRawEntity>();

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder) => _hooks.ConfigureConventions(configurationBuilder);

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        StorageModel.ConfigureAll(modelBuilder);
        _hooks.OnModelBuilt(modelBuilder);
    }
}

/// <summary>A context EF can pool: EF builds pooled contexts from their options alone, so the hooks come from the options.</summary>
public sealed class PostgresReadContext(DbContextOptions<PostgresReadContext> options) : PostgresDbContext(options);
