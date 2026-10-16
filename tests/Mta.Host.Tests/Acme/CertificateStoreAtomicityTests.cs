using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Tests.Api;
using Mta.Host.Tls;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests.Acme;

/// <summary>
/// The certificate set a replica serves changes in one step: a renewal replaces the row of the certificate in the store and the poller swaps the whole set, so
/// a handshake sees the old certificate or the new one, never a half-loaded one, and a replacement that cannot be loaded never takes the working certificate out
/// of service. The readers here run against a writer that keeps replacing the row; they count what they saw, nothing is timed.
/// </summary>
public class CertificateStoreAtomicityTests : IAsyncLifetime
{
    private const string Host = "mx.swap.test";
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 10, 15, 8, 0, 0, TimeSpan.Zero));
    private readonly TestProtector _protector = new();
    private readonly HttpListLog _log = new();
    private readonly InMemoryStorage _storage;
    private readonly Guid _rowId = Ids.New();

    public CertificateStoreAtomicityTests() => _storage = new InMemoryStorage(new StorageOptions(), _clock);

    public async Task InitializeAsync() => await _storage.InitializeAsync(default);

    public async Task DisposeAsync() => await _storage.DisposeAsync();

    private IConfigStore Config => _storage.Config;

    private DatabaseCertificateProvider Provider() => new(Config, _protector, Host, new TlsSection(), _clock, _log);

    /// <summary>A row for the ACME certificate called "default" with a fresh key; the same row id for every version, as a renewal replaces it.</summary>
    private CertificateRecord Version(TimeSpan lifetime, string host = Host, TimeSpan? age = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=" + host, key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(host);
        request.CertificateExtensions.Add(san.Build());
        using var certificate = request.CreateSelfSigned(_clock.UtcNow - (age ?? TimeSpan.FromMinutes(5)), _clock.UtcNow + lifetime);
        return new CertificateRecord(_rowId, "default", [host], certificate.NotBefore.ToUniversalTime(), certificate.NotAfter.ToUniversalTime(), certificate.ExportCertificatePem(),
            _protector.Protect(key.ExportPkcs8PrivateKey(), SecretPurposes.TlsPrivateKey), "acme", certificate.Thumbprint, Active: true, Version: 1, CreatedAt: _clock.UtcNow);
    }

    private static string ServedThumbprint(DatabaseCertificateProvider provider, string name = Host) => provider.GetContext(name)!.TargetCertificate.Thumbprint;

    [Fact]
    public async Task A_renewed_row_is_served_after_the_next_reload_and_not_before()
    {
        var first = Version(TimeSpan.FromDays(90));
        await Config.UpsertCertificateAsync(first, default);
        var provider = Provider();
        await provider.InitializeAsync(default);
        Assert.Equal(first.Thumbprint, ServedThumbprint(provider));
        var second = Version(TimeSpan.FromDays(90));

        await Config.UpsertCertificateAsync(second, default);
        Assert.Equal(first.Thumbprint, ServedThumbprint(provider)); // the store has it, this replica has not looked yet
        await provider.ReloadAsync(force: false, default);

        Assert.Equal(second.Thumbprint, ServedThumbprint(provider));
        Assert.Equal(1, provider.Count); // the row was replaced: the old certificate is not served next to the new one
    }

    [Fact]
    public async Task A_reload_without_a_new_store_version_keeps_the_very_same_loaded_set()
    {
        await Config.UpsertCertificateAsync(Version(TimeSpan.FromDays(90)), default);
        var provider = Provider();
        await provider.InitializeAsync(default);
        var before = provider.GetContext(Host);

        await provider.ReloadAsync(force: false, default);

        Assert.Same(before, provider.GetContext(Host));
    }

    [Fact]
    public async Task Readers_during_many_swaps_only_ever_see_one_of_the_valid_certificates_with_its_key()
    {
        var a = Version(TimeSpan.FromDays(90));
        var b = Version(TimeSpan.FromDays(80));
        await Config.UpsertCertificateAsync(a, default);
        var provider = Provider();
        await provider.InitializeAsync(default);
        var allowed = new HashSet<string> { a.Thumbprint, b.Thumbprint };
        var offences = new System.Collections.Concurrent.ConcurrentBag<string>();
        using var done = new CancellationTokenSource();
        long reads = 0;

        var readers = Enumerable.Range(0, 2).Select(_ => Task.Run(async () =>
        {
            while (!done.IsCancellationRequested)
            {
                await Task.Yield(); // readers interleave with the writer instead of starving it on a small machine

                var context = provider.GetContext(Host);
                if (context is null)
                {
                    offences.Add("no context");
                    continue;
                }

                var target = context.TargetCertificate;
                if (!allowed.Contains(target.Thumbprint))
                {
                    offences.Add("unknown certificate " + target.Thumbprint);
                }

                if (!target.HasPrivateKey)
                {
                    offences.Add("certificate without key");
                }

                if (provider.GetCertificate(Host) is not { HasPrivateKey: true })
                {
                    offences.Add("leaf without key");
                }

                Interlocked.Increment(ref reads);
            }
        })).ToList();

        for (int i = 0; i < 24; i++)
        {
            await Config.UpsertCertificateAsync(i % 2 == 0 ? b : a, default);
            await provider.ReloadAsync(force: false, default);
            await Task.Yield();
        }

        await done.CancelAsync();
        await Task.WhenAll(readers);

        Assert.Empty(offences);
        Assert.True(Interlocked.Read(ref reads) > 0);
        Assert.Contains(ServedThumbprint(provider), allowed);
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("empty")]
    [InlineData("truncated")]
    [InlineData("other-key")]
    public async Task A_replacement_that_cannot_be_loaded_leaves_the_working_certificate_in_service_even_next_to_other_certificates(string damage)
    {
        var good = Version(TimeSpan.FromDays(90));
        await Config.UpsertCertificateAsync(CertificateMaterial.CreateSelfSigned(Host, _protector, _clock.UtcNow), default); // another active certificate: the set does not become empty
        await Config.UpsertCertificateAsync(good, default);
        var provider = Provider();
        await provider.InitializeAsync(default);
        Assert.Equal(good.Thumbprint, ServedThumbprint(provider));
        var damaged = damage switch
        {
            "garbage" => good with { ChainPem = "not a certificate" },
            "empty" => good with { ChainPem = "" },
            "truncated" => good with { ChainPem = good.ChainPem[..(good.ChainPem.Length / 2)] },
            _ => good with { ChainPem = Version(TimeSpan.FromDays(90)).ChainPem }, // a certificate for another key than the stored one
        };

        await Config.UpsertCertificateAsync(damaged, default);
        await provider.ReloadAsync(force: false, default);

        Assert.Equal(good.Thumbprint, ServedThumbprint(provider));
        Assert.Contains(_log.Lines, l => l.StartsWith("Error tls: certificate 'default' is unusable and was skipped; the certificate of that name loaded before stays in use", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_replacement_that_cannot_be_loaded_and_is_the_only_certificate_keeps_the_previous_set()
    {
        var good = Version(TimeSpan.FromDays(90));
        await Config.UpsertCertificateAsync(good, default);
        var provider = Provider();
        await provider.InitializeAsync(default);
        Assert.False(provider.UsingSelfSignedOnly);

        await Config.UpsertCertificateAsync(good with { ChainPem = "garbage" }, default);
        await provider.ReloadAsync(force: false, default);

        Assert.Equal(good.Thumbprint, ServedThumbprint(provider));
    }

    [Fact]
    public async Task A_replacement_that_is_expired_is_not_served_and_with_nothing_else_the_previous_set_stays()
    {
        var good = Version(TimeSpan.FromDays(90));
        await Config.UpsertCertificateAsync(good, default);
        var provider = Provider();
        await provider.InitializeAsync(default);
        _clock.Advance(TimeSpan.FromDays(100)); // the stored certificate is now expired, as a replacement the CA backdated would be

        await Config.UpsertCertificateAsync(Version(TimeSpan.FromDays(-1), age: TimeSpan.FromDays(3)), default);
        await provider.ReloadAsync(force: false, default);

        Assert.Equal(good.Thumbprint, ServedThumbprint(provider));
        Assert.Contains(_log.Lines, l => l.Contains("not serving it", StringComparison.Ordinal) || l.Contains("keeping the previous set", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_store_that_is_down_during_a_reload_leaves_the_loaded_set_serving()
    {
        var good = Version(TimeSpan.FromDays(90));
        await Config.UpsertCertificateAsync(good, default);
        var (faulty, control) = FaultyConfig.Wrap(Config);
        var provider = new DatabaseCertificateProvider(faulty, _protector, Host, new TlsSection(), _clock, _log);
        await provider.InitializeAsync(default);
        control.Fail(nameof(IConfigStore.GetCertificateVersionAsync));

        await Assert.ThrowsAsync<InvalidOperationException>(() => provider.ReloadAsync(force: false, default));

        Assert.Equal(good.Thumbprint, ServedThumbprint(provider));
        control.Fail(nameof(IConfigStore.GetCertificatesAsync));
        await Config.UpsertCertificateAsync(Version(TimeSpan.FromDays(90)), default); // a new version exists, but reading the rows fails
        await Assert.ThrowsAsync<InvalidOperationException>(() => provider.ReloadAsync(force: false, default));
        Assert.Equal(good.Thumbprint, ServedThumbprint(provider));
    }

    [Fact]
    public async Task A_store_that_fails_while_the_renewal_service_stores_the_certificate_changes_nothing_a_replica_serves()
    {
        using var rig = new AcmeServiceRig();
        var (faulty, control) = FaultyConfig.Wrap(rig.Config);
        var service = rig.Service(config: faulty);
        Assert.True(await service.CheckOnceAsync(default));
        var provider = new DatabaseCertificateProvider(rig.Config, rig.Protector, AcmeServiceRig.Host, new TlsSection(), rig.Clock, rig.Log);
        await provider.InitializeAsync(default);
        string served = ServedThumbprint(provider, AcmeServiceRig.Host);
        rig.Clock.Advance(TimeSpan.FromDays(70));
        control.Fail(nameof(IConfigStore.UpsertCertificateAsync));

        Assert.False(await service.CheckOnceAsync(default));
        await provider.ReloadAsync(force: false, default);

        Assert.Equal(served, ServedThumbprint(provider, AcmeServiceRig.Host));
    }
}
