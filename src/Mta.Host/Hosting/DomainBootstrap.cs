using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Domains;
using Mta.Policy;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>What <see cref="DomainBootstrap.RunAsync"/> did.</summary>
/// <param name="Registered">Domains registered by this run, with the text of the DNS records to create.</param>
/// <param name="AlreadyRegistered">Listed domains that were registered before (left alone).</param>
/// <param name="Skipped">Listed domains that could not be registered, with the reason.</param>
/// <param name="LeaseHeldElsewhere">Another replica was registering the domains at that moment; this one did nothing.</param>
public sealed record DomainBootstrapResult(
    IReadOnlyList<(string Domain, string Records)> Registered,
    IReadOnlyList<string> AlreadyRegistered,
    IReadOnlyList<(string Domain, string Reason)> Skipped,
    bool LeaseHeldElsewhere);

/// <summary>
/// <c>Domains:Bootstrap</c> (<c>EGGMAIL_DOMAINS</c>): registers the listed sending domains at start for the first tenant, so a new installation only has to name its
/// domain. Each new domain gets its DKIM key generated and the exact DNS records to create are written to the log, once, when it is registered; the same text is
/// available on demand (<c>mta domains records &lt;domain&gt;</c>, the dashboard, <c>GET /api/v1/domains/{id}/records</c>).
/// <para>The first tenant is the oldest one; when there is none, a tenant named <c>Default</c> is created (so the first administrator finds it when signing in). The
/// whole run happens under a lease of the config store, so replicas starting together register each domain once; running it again changes nothing.</para>
/// </summary>
public static class DomainBootstrap
{
    public const string LeaseName = "domains-bootstrap";
    public const string DefaultTenantName = "Default";
    public const string DefaultTenantSlug = "default";

    private static readonly TimeSpan LeaseDuration = TimeSpan.FromMinutes(2);

    public static async Task<DomainBootstrapResult> RunAsync(MtaConfig config, IStorage storage, ISecretProtector protector, IClock clock, IMtaLog log, CancellationToken ct)
    {
        var registered = new List<(string, string)>();
        var already = new List<string>();
        var skipped = new List<(string, string)>();
        List<string> names = config.Domains.Bootstrap.Select(n => DomainNames.TryNormalize(n, out string name) ? name : n.Trim()).Distinct(StringComparer.Ordinal).ToList();
        if (names.Count == 0)
        {
            return new DomainBootstrapResult(registered, already, skipped, false);
        }

        IConfigStore store = storage.Config;
        string owner = "domains-bootstrap-" + Guid.NewGuid().ToString("N");
        if (await store.TryAcquireLeaseAsync(LeaseName, owner, LeaseDuration, clock.UtcNow, ct).ConfigureAwait(false) is null)
        {
            log.Write(MtaLogLevel.Information, "domains", "Domains:Bootstrap is being applied by another replica; nothing to do here.");
            return new DomainBootstrapResult(registered, already, skipped, true);
        }

        try
        {
            Tenant tenant = await EnsureTenantAsync(store, clock, log, ct).ConfigureAwait(false);
            DomainRecordOptions recordOptions = EggMailApiExtensions.DomainRecordOptionsFrom(config);
            var schedule = new VerificationSchedule();
            foreach (string name in names)
            {
                try
                {
                    if (!DomainNames.TryNormalize(name, out _))
                    {
                        skipped.Add((name, "not a valid domain name"));
                        log.Write(MtaLogLevel.Error, "domains", $"Domains:Bootstrap entry '{name}' is not a valid domain name; skipped.");
                        continue;
                    }

                    DomainRecord? existing = await store.FindDomainByNameAsync(name, ct).ConfigureAwait(false);
                    if (existing is not null)
                    {
                        if (existing.TenantId == tenant.Id)
                        {
                            already.Add(name);
                        }
                        else
                        {
                            skipped.Add((name, "registered by another tenant"));
                            log.Write(MtaLogLevel.Warning, "domains", $"Domains:Bootstrap: {name} is already registered by another tenant; left alone.");
                        }

                        continue;
                    }

                    if ((await store.GetDomainsAsync(tenant.Id, ct).ConfigureAwait(false)).Count >= config.Api.MaxDomainsPerTenant)
                    {
                        skipped.Add((name, "tenant domain limit reached"));
                        log.Write(MtaLogLevel.Warning, "domains", $"Domains:Bootstrap: {name} skipped, the tenant already has {config.Api.MaxDomainsPerTenant} domains (Api:MaxDomainsPerTenant).");
                        continue;
                    }

                    RegisteredDomain created = await DomainRegistration.RegisterAsync(store, protector, schedule, recordOptions, tenant.Id, name, clock.UtcNow, ct).ConfigureAwait(false);
                    string records = DomainRecordsReport.Render(created.Domain.Name, DomainRecordPlanner.Plan(created.Domain.Name, [new DomainDkimKey(created.Key.Selector, created.Key.PublicKeyBase64)], recordOptions));
                    registered.Add((name, records));
                    log.Write(MtaLogLevel.Information, "domains", $"Registered {name} for tenant '{tenant.Name}'.");
                    foreach (string line in records.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                    {
                        log.Write(MtaLogLevel.Information, "domains", line.TrimEnd('\r'));
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    skipped.Add((name, ex.Message));
                    log.Write(MtaLogLevel.Error, "domains", $"Domains:Bootstrap: registering {name} failed: {ex.Message}");
                }
            }
        }
        finally
        {
            await store.ReleaseLeaseAsync(LeaseName, owner, CancellationToken.None).ConfigureAwait(false);
        }

        return new DomainBootstrapResult(registered, already, skipped, false);
    }

    /// <summary>The oldest tenant, or a new tenant named <c>Default</c> when there is none.</summary>
    private static async Task<Tenant> EnsureTenantAsync(IConfigStore store, IClock clock, IMtaLog log, CancellationToken ct)
    {
        Tenant? first = (await store.GetTenantsAsync(ct).ConfigureAwait(false)).OrderBy(t => t.CreatedAt).ThenBy(t => t.Id).FirstOrDefault();
        if (first is not null)
        {
            return first;
        }

        var tenant = new Tenant(Ids.New(clock.UtcNow), DefaultTenantName, DefaultTenantSlug, Enabled: true, clock.UtcNow, StoreAttachments: false);
        try
        {
            await store.UpsertTenantAsync(tenant, ct).ConfigureAwait(false);
            log.Write(MtaLogLevel.Information, "domains", $"Created the tenant '{DefaultTenantName}' for the domains of Domains:Bootstrap (there was no tenant yet).");
            return tenant;
        }
        catch (StorageConflictException)
        {
            // Someone created a tenant with that slug between the read and the write (the lease only covers this feature): use theirs.
            return (await store.GetTenantsAsync(ct).ConfigureAwait(false)).OrderBy(t => t.CreatedAt).ThenBy(t => t.Id).First();
        }
    }
}

/// <summary>The text that tells an operator which DNS records to create for a domain: what the log, the <c>mta domains records</c> command and the API show.</summary>
public static class DomainRecordsReport
{
    public static string Render(string domain, IReadOnlyList<ExpectedDomainRecord> records) =>
        $"DNS records to create for {domain}. Add them at your DNS provider, then check them in the dashboard (Domains > {domain} > Check DNS).\n\n"
        + ZoneFile.Render(domain, records);
}
