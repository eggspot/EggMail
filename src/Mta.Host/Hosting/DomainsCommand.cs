using Mta.Core;
using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Host.Domains;
using Mta.Host.Switching;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>
/// <c>mta domains records DOMAIN</c> prints the DNS records to create for a registered domain in zone-file syntax; <c>mta domains check DOMAIN</c> looks
/// them up in DNS and prints each record's status with what was found next to what is expected (nothing is saved; the server's own check does that).
/// Both read the store, so with SQLite the server must be stopped (one process owns the data directory); a running server shows the same in the
/// dashboard, in <c>GET /api/v1/domains/{id}/records</c> and, for a domain registered by <c>Domains:Bootstrap</c>, in its log.
/// </summary>
public static class DomainsCommand
{
    private const string Usage = "Usage: mta domains records DOMAIN | mta domains check DOMAIN   (the usual configuration options follow, for example --Sqlite:DataDirectory=/data)";

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error)
    {
        string? verb = args.FirstOrDefault();
        string? domainArgument = args.Skip(1).FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal));
        if (verb is not ("records" or "check") || domainArgument is null)
        {
            error.WriteLine(Usage);
            return 64;
        }

        if (!DomainNames.TryNormalize(domainArgument, out string name))
        {
            error.WriteLine($"'{domainArgument}' is not a valid domain name.");
            return 64;
        }

        var loaded = ConfigLoader.Load(ConfigLoader.Build(args.Skip(1).Where(a => a != domainArgument).ToArray()));
        if (!loaded.IsValid)
        {
            foreach (string e in loaded.Errors)
            {
                error.WriteLine("configuration error: " + e);
            }

            return 2;
        }

        DataDirectoryLock? directoryLock = null;
        try
        {
            directoryLock = loaded.Config.Storage.Backend == StorageBackend.Sqlite ? DataDirectoryLock.Acquire(loaded.Config.Storage.Sqlite.DataDirectory) : null;
        }
        catch (IOException ex)
        {
            error.WriteLine(ex.Message + " Stop the server first, or read the records in the dashboard or with GET /api/v1/domains/{id}/records.");
            return 3;
        }

        using (directoryLock)
        {
            await using var storage = StorageFactory.Create(loaded.Config.Storage, SystemClock.Instance, NullMtaLog.Instance);
            await storage.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
            DomainRecord? domain = await storage.Config.FindDomainByNameAsync(name, CancellationToken.None).ConfigureAwait(false);
            if (domain is null)
            {
                error.WriteLine($"{name} is not registered. Add it in the dashboard, with POST /api/v1/domains, or list it in Domains:Bootstrap (EGGMAIL_DOMAINS).");
                return 1;
            }

            var keys = await storage.Config.GetDkimKeysAsync(domain.Id, CancellationToken.None).ConfigureAwait(false);
            DomainRecordOptions recordOptions = EggMailApiExtensions.DomainRecordOptionsFrom(loaded.Config);
            var plan = DomainVerificationService.PlanRecords(domain, keys, SystemClock.Instance.UtcNow, recordOptions, new ApiOptions().DkimRetirementGrace);
            if (verb == "records")
            {
                output.Write(DomainRecordsReport.Render(name, plan));
                return 0;
            }

            var dns = EggMailRuntime.CreateDns(loaded.Config);
            DomainCheckResult result = await new DomainChecker(dns).CheckAsync(plan, CancellationToken.None).ConfigureAwait(false);
            foreach (DomainRecordCheck check in result.Records)
            {
                string word = DomainVerificationService.StatusWord(check.Status).ToUpperInvariant();
                output.WriteLine($"{word,-9} {DomainRecordPurposes.Label(check.Expected.Purpose),-13} {(check.Expected.Required ? "required   " : "recommended")} {check.Expected.Type} {check.Expected.Host}");
                if (check.Status is not (DomainRecordStatus.Ok or DomainRecordStatus.Pending))
                {
                    output.WriteLine($"          expected: {check.Expected.Value}");
                    output.WriteLine($"          found:    {check.Found ?? "(nothing)"}");
                }
            }

            output.WriteLine(result.Result switch
            {
                Mta.Policy.VerificationCheckResult.AllRecordsOk => $"{name}: every required record is published; the domain can send once the server has verified it.",
                Mta.Policy.VerificationCheckResult.DnsTemporaryFailure => $"{name}: DNS did not answer; try again.",
                _ => $"{name}: {result.Error}.",
            });
            return result.Result == Mta.Policy.VerificationCheckResult.AllRecordsOk ? 0 : 1;
        }
    }
}
