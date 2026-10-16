using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Mta.Storage.Model;

// One context per model part (the SQLite layout: one file each). The PostgreSQL provider defines a single context
// that implements all four IXxxDbSets interfaces and calls StorageModel.ConfigureAll.

public interface IConfigDbSets : IDataProtectionKeyContext
{
    DbSet<TenantEntity> Tenants { get; }
    DbSet<ApiKeyEntity> ApiKeys { get; }
    DbSet<SmtpCredentialEntity> SmtpCredentials { get; }
    DbSet<DomainEntity> Domains { get; }
    DbSet<DkimKeyEntity> DkimKeys { get; }
    DbSet<SuppressionEntity> Suppressions { get; }
    DbSet<WebhookEndpointEntity> WebhookEndpoints { get; }
    DbSet<SettingEntity> Settings { get; }
    DbSet<TlsPolicyEntity> TlsPolicies { get; }
    DbSet<RelayRouteEntity> RelayRoutes { get; }
    DbSet<CertificateEntity> Certificates { get; }
    DbSet<AcmeAccountEntity> AcmeAccounts { get; }
    DbSet<AcmeRenewalEntity> AcmeRenewals { get; }
    DbSet<LeaseEntity> Leases { get; }
    DbSet<SwitchStateEntity> SwitchStates { get; }
    DbSet<InboundDomainSettingsEntity> InboundSettings { get; }
    DbSet<InboundRouteEntity> InboundRoutes { get; }
}

public interface IQueueDbSets
{
    DbSet<QueuedDeliveryEntity> Deliveries { get; }
    DbSet<SpoolMessageEntity> Spool { get; }
    DbSet<WebhookOutboxEntity> WebhookOutbox { get; }
    DbSet<IdempotencyKeyEntity> IdempotencyKeys { get; }
    DbSet<InboundMessageEntity> InboundMessages { get; }
    DbSet<InboundMessageRawEntity> InboundRaw { get; }
}

public interface IStatsDbSets
{
    DbSet<StatAggregateEntity> StatAggregates { get; }
    DbSet<StatMetaEntity> StatMeta { get; }
    DbSet<RecentEventEntity> RecentEvents { get; }
    DbSet<WebhookAttemptEntity> WebhookAttempts { get; }
}

public interface IHistoryDbSets
{
    DbSet<MessageIndexEntity> MessageIndex { get; }
    DbSet<MessageRecipientEntity> MessageRecipients { get; }
    DbSet<MessageEventEntity> MessageEvents { get; }
    DbSet<MessageContentEntity> MessageContents { get; }
    DbSet<RetainedRawEntity> RetainedRaw { get; }
}

/// <summary>A queue context that can be pooled (the inbound message reads), built from its options alone like <see cref="ConfigReadContext"/>.</summary>
public sealed class QueueReadContext(DbContextOptions<QueueReadContext> options) : QueueDbContext(options);

/// <summary>A config context that can be pooled: EF's pool constructs contexts from their options alone, so the hooks come from the options.</summary>
public sealed class ConfigReadContext(DbContextOptions<ConfigReadContext> options) : ConfigDbContext(options);

public class ConfigDbContext : DbContext, IConfigDbSets
{
    private readonly IStorageModelHooks _hooks;

    public ConfigDbContext(DbContextOptions<ConfigDbContext> options, IStorageModelHooks hooks) : base(options) => _hooks = hooks;

    /// <summary>For derived (pooled) contexts: the hooks travel in the options (<see cref="ModelHooksOptionsExtensions.UseModelHooks{TContext}"/>).</summary>
    protected ConfigDbContext(DbContextOptions options) : base(options) => _hooks = options.HooksOf();

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

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder) => _hooks.ConfigureConventions(configurationBuilder);

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        StorageModel.ConfigureConfig(modelBuilder);
        _hooks.OnModelBuilt(modelBuilder);
    }
}

public class QueueDbContext : DbContext, IQueueDbSets
{
    private readonly IStorageModelHooks _hooks;

    public QueueDbContext(DbContextOptions<QueueDbContext> options, IStorageModelHooks hooks) : base(options) => _hooks = hooks;

    /// <summary>For derived (pooled) contexts: the hooks travel in the options (<see cref="ModelHooksOptionsExtensions.UseModelHooks{TContext}"/>).</summary>
    protected QueueDbContext(DbContextOptions options) : base(options) => _hooks = options.HooksOf();

    public DbSet<QueuedDeliveryEntity> Deliveries => Set<QueuedDeliveryEntity>();
    public DbSet<SpoolMessageEntity> Spool => Set<SpoolMessageEntity>();
    public DbSet<WebhookOutboxEntity> WebhookOutbox => Set<WebhookOutboxEntity>();
    public DbSet<IdempotencyKeyEntity> IdempotencyKeys => Set<IdempotencyKeyEntity>();
    public DbSet<InboundMessageEntity> InboundMessages => Set<InboundMessageEntity>();
    public DbSet<InboundMessageRawEntity> InboundRaw => Set<InboundMessageRawEntity>();

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder) => _hooks.ConfigureConventions(configurationBuilder);

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        StorageModel.ConfigureQueue(modelBuilder);
        _hooks.OnModelBuilt(modelBuilder);
    }
}

public class StatsDbContext(DbContextOptions<StatsDbContext> options, IStorageModelHooks hooks) : DbContext(options), IStatsDbSets
{
    public DbSet<StatAggregateEntity> StatAggregates => Set<StatAggregateEntity>();
    public DbSet<StatMetaEntity> StatMeta => Set<StatMetaEntity>();
    public DbSet<RecentEventEntity> RecentEvents => Set<RecentEventEntity>();
    public DbSet<WebhookAttemptEntity> WebhookAttempts => Set<WebhookAttemptEntity>();

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder) => hooks.ConfigureConventions(configurationBuilder);

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        StorageModel.ConfigureStats(modelBuilder);
        hooks.OnModelBuilt(modelBuilder);
    }
}

public class HistoryDbContext(DbContextOptions<HistoryDbContext> options, IStorageModelHooks hooks) : DbContext(options), IHistoryDbSets
{
    public DbSet<MessageIndexEntity> MessageIndex => Set<MessageIndexEntity>();
    public DbSet<MessageRecipientEntity> MessageRecipients => Set<MessageRecipientEntity>();
    public DbSet<MessageEventEntity> MessageEvents => Set<MessageEventEntity>();
    public DbSet<MessageContentEntity> MessageContents => Set<MessageContentEntity>();
    public DbSet<RetainedRawEntity> RetainedRaw => Set<RetainedRawEntity>();

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder) => hooks.ConfigureConventions(configurationBuilder);

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        StorageModel.ConfigureHistory(modelBuilder);
        hooks.OnModelBuilt(modelBuilder);
    }
}
