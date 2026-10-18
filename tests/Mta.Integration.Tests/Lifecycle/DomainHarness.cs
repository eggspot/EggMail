using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Mta.Core;
using Mta.Delivery;
using Mta.Dkim;
using Mta.Host.Api;
using Mta.Host.Domains;
using Mta.Policy;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Integration.Tests.Lifecycle;

internal sealed class LifecycleProtector : ISecretProtector
{
    public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => [.. Encoding.UTF8.GetBytes(purpose + "|"), .. plaintext.ToArray()];

    public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose)
    {
        byte[] prefix = Encoding.UTF8.GetBytes(purpose + "|");
        if (!protectedData.StartsWith(prefix))
        {
            throw new System.Security.Cryptography.CryptographicException("wrong purpose");
        }

        return protectedData[prefix.Length..].ToArray();
    }
}

/// <summary>
/// One tenant with one registered sending domain over a <see cref="HostBackend"/>, the real <see cref="DomainVerificationService"/> and DKIM signer provider, a virtual
/// clock and a DNS that the test (playing the customer) changes. <see cref="Rebind"/> rebuilds the services over the backend's current storage after a restart.
/// </summary>
internal sealed class DomainHarness
{
    public const string DomainName = "customer.example";
    public static readonly Guid TenantId = Guid.Parse("a0000000-0000-7000-8000-000000000001");

    private readonly ApiOptions _api;
    private readonly VerificationScheduleOptions _scheduleOptions;
    private readonly DomainRecordOptions _recordOptions = new() { BounceDomain = "bounces.egg.test" };

    private DomainHarness(HostBackend backend, VirtualClock clock, ApiOptions api, VerificationScheduleOptions scheduleOptions)
    {
        Backend = backend;
        Clock = clock;
        _api = api;
        _scheduleOptions = scheduleOptions;
    }

    public HostBackend Backend { get; }

    public VirtualClock Clock { get; }

    public LifecycleDns Dns { get; } = new();

    public LifecycleProtector Protector { get; } = new();

    public DomainVerificationService Service { get; private set; } = null!;

    public ConfigDkimSignerProvider Signers { get; private set; } = null!;

    public IConfigStore Config => Backend.Storage.Config;

    public Guid DomainId { get; private set; }

    public int Checks { get; private set; }

    public static async Task<DomainHarness> CreateAsync(HostBackend backend, VirtualClock clock, ApiOptions? api = null, VerificationScheduleOptions? schedule = null)
    {
        var h = new DomainHarness(backend, clock, api ?? new ApiOptions { VerificationPollInterval = TimeSpan.FromHours(1) }, schedule ?? new VerificationScheduleOptions());
        h.Rebind();
        await h.Config.UpsertTenantAsync(new Tenant(TenantId, "Customer", "customer", true, clock.UtcNow, false), default);
        var registered = await DomainRegistration.RegisterAsync(h.Config, h.Protector, h.Service.Schedule, h._recordOptions, TenantId, DomainName, clock.UtcNow, default);
        h.DomainId = registered.Domain.Id;
        return h;
    }

    public void Rebind()
    {
        Signers?.Dispose();
        Service = new DomainVerificationService(Backend.Storage, new DomainChecker(Dns), new VerificationSchedule(_scheduleOptions), _recordOptions, _api, Clock, NullLogger<DomainVerificationService>.Instance);
        Signers = new ConfigDkimSignerProvider(Config, Protector, Clock, cacheTtl: TimeSpan.Zero);
    }

    public async Task<DomainRecord> DomainAsync() => (await Config.GetDomainAsync(DomainId, default))!;

    public async Task<IReadOnlyList<Mta.Storage.DkimKeyRecord>> KeysAsync() => await Config.GetDkimKeysAsync(DomainId, default);

    public async Task<IReadOnlyList<ExpectedDomainRecord>> PlanAsync() => Service.PlanRecords(await DomainAsync(), await KeysAsync(), Clock.UtcNow, inboundEnabled: false);

    /// <summary>The customer publishes the records of the plan: the DKIM keys that are listed and the return path CNAME (not the advice).</summary>
    public async Task PublishAsync(bool dkim = true, bool returnPath = true, string? onlySelector = null)
    {
        foreach (ExpectedDomainRecord r in await PlanAsync())
        {
            if (r.Purpose == DomainRecordPurpose.Dkim && dkim && (onlySelector is null || r.Host.StartsWith(onlySelector + "._domainkey.", StringComparison.Ordinal)))
            {
                Dns.SetTxt(r.Host, r.Value);
            }
            else if (r.Purpose == DomainRecordPurpose.ReturnPath && returnPath)
            {
                Dns.SetCname(r.Host, r.Value);
            }
        }
    }

    /// <summary>The customer removes every DKIM record that the plan no longer lists (what the dashboard tells them to do).</summary>
    public async Task RemoveUnlistedDkimAsync(IEnumerable<string> everPublishedHosts)
    {
        var listed = (await PlanAsync()).Where(r => r.Purpose == DomainRecordPurpose.Dkim).Select(r => r.Host).ToHashSet(StringComparer.Ordinal);
        foreach (string host in everPublishedHosts.Where(h => !listed.Contains(h)))
        {
            Dns.Remove(host);
        }
    }

    /// <summary>One pass of the scheduler at the current virtual time.</summary>
    public async Task<int> TickAsync()
    {
        int n = await Service.RunDueChecksAsync(default);
        Checks += n;
        return n;
    }

    /// <summary>Moves virtual time forward in steps, running the scheduler at each step; <paramref name="afterStep"/> is the place for invariants.</summary>
    public async Task AdvanceAsync(TimeSpan total, TimeSpan step, Func<Task>? afterStep = null)
    {
        DateTimeOffset end = Clock.UtcNow + total;
        while (Clock.UtcNow < end)
        {
            Clock.Advance(step > end - Clock.UtcNow ? end - Clock.UtcNow : step);
            await TickAsync();
            if (afterStep is not null)
            {
                await afterStep();
            }
        }
    }

    /// <summary>A small message of the domain, signed with the signer the delivery engine would use now (null if the domain has no signing key).</summary>
    public async Task<byte[]?> SignAsync(string tag)
    {
        DkimSigner? signer = await Signers.GetSignerAsync(DomainName, default);
        if (signer is null)
        {
            return null;
        }

        return SignWith(signer, tag);
    }

    public byte[] SignWith(DkimSigner signer, string tag)
    {
        byte[] raw = Encoding.ASCII.GetBytes(
            $"From: sender@{DomainName}\r\nTo: rcpt@example.net\r\nSubject: {tag}\r\nDate: {Clock.UtcNow:R}\r\nMessage-ID: <{tag}@{DomainName}>\r\n\r\nBody of {tag}\r\n");
        byte[] rented = signer.SignPrepended(raw, out int length);
        try
        {
            return rented.AsSpan(0, length).ToArray();
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(rented);
        }
    }

    public async Task<DkimStatus> VerifyAsync(byte[] message)
    {
        var verifier = new DkimVerifier(Dns, new DkimVerifierOptions { Clock = Clock, MinimumKeyBits = 1024 });
        var results = await verifier.VerifyAsync(message);
        return results.Count == 0 ? DkimStatus.None : results[0].Status;
    }
}
