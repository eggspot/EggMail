using Mta.Core;
using Mta.Host.Domains;
using Mta.Policy;
using Mta.Storage;
using StoredDkimKey = Mta.Storage.DkimKeyRecord;

namespace Mta.Host.Api;

/// <summary>What registering a domain created: the domain row and its first (signing) DKIM key.</summary>
public sealed record RegisteredDomain(DomainRecord Domain, StoredDkimKey Key);

/// <summary>
/// Registers a sending domain for a tenant: an RSA-2048 DKIM key and the domain row in <see cref="DomainStatus.Pending"/>. The one place that does it, for
/// <c>POST /api/v1/domains</c> and for the start-up registration of <c>Domains:Bootstrap</c>.
/// </summary>
public static class DomainRegistration
{
    /// <summary>
    /// Creates the key and then the domain. The key goes in first: a domain without a key would verify without DKIM if the process died in between, while an
    /// orphan key is harmless. Throws <see cref="StorageConflictException"/> (after removing the orphan key) when the name is registered meanwhile.
    /// </summary>
    public static async Task<RegisteredDomain> RegisterAsync(
        IConfigStore config, ISecretProtector protector, VerificationSchedule schedule, DomainRecordOptions recordOptions, Guid tenantId, string name, DateTimeOffset now, CancellationToken ct)
    {
        var domain = new DomainRecord(
            Ids.New(now),
            tenantId,
            name,
            DomainStatus.Pending,
            string.IsNullOrWhiteSpace(recordOptions.BounceDomain) ? null : DomainRecordPlanner.ReturnPathHost(name, recordOptions),
            ReturnPathVerified: false,
            now,
            LastCheckedAt: null,
            NextCheckAt: schedule.FirstCheckAt(now),
            ConsecutiveFailures: 0,
            TemporaryFailureSince: null,
            SendingPaused: false,
            LastError: null);
        StoredDkimKey key = await DomainVerificationService.CreateKeyAsync(domain.Id, DomainVerificationService.NextSelector([], now), protector, now, active: true).ConfigureAwait(false);

        await config.AddDkimKeyAsync(key, ct).ConfigureAwait(false);
        try
        {
            await config.UpsertDomainAsync(domain, ct).ConfigureAwait(false);
            Mta.Host.Submission.DomainChangeSignal.Bump();
        }
        catch (StorageConflictException)
        {
            await config.DeleteDomainAsync(domain.Id, CancellationToken.None).ConfigureAwait(false); // removes the orphan key
            Mta.Host.Submission.DomainChangeSignal.Bump();
            throw;
        }

        return new RegisteredDomain(domain, key);
    }
}
