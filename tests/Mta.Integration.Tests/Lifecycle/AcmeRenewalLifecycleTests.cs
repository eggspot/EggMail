using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Tls;
using Mta.Storage;
using Mta.TestSupport;

namespace Mta.Integration.Tests.Lifecycle;

/// <summary>
/// The certificate renewal service over more than a year of virtual time with 90-day certificates, on the SQLite files and on PostgreSQL. The CA is an
/// in-process runner (<see cref="ScriptedCa"/>) that signs self-signed certificates whose validity follows the virtual clock and fails, or publishes renewal
/// windows, as the scenario says. It is NOT a real CA: nothing here proves that a real CA, Certes or the challenge flow works (the Pebble tests in
/// <c>Acme/</c> cover those); it proves the timing, back-off, lease and storage behaviour of <see cref="AcmeRenewalService"/> and of the hot reload of
/// <see cref="DatabaseCertificateProvider"/> when time runs for months.
/// </summary>
internal static class AcmeLifecycleScenarios
{
    internal const string Host = "mx.lifecycle.example";
    internal static readonly TimeSpan Lifetime = TimeSpan.FromDays(90);
    /// <summary>A daily check (the longest the CA's advice is trusted): a tick costs a handful of queries, and a year is 365 of them.</summary>
    internal static readonly TimeSpan CheckInterval = TimeSpan.FromDays(1);
    internal static readonly DateTimeOffset Start = new(2026, 10, 12, 8, 0, 0, TimeSpan.Zero);

    internal sealed class Protector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => [.. Encoding.UTF8.GetBytes(purpose + "|"), .. plaintext.ToArray()];

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose)
        {
            byte[] prefix = Encoding.UTF8.GetBytes(purpose + "|");
            return protectedData.StartsWith(prefix) ? protectedData[prefix.Length..].ToArray() : throw new CryptographicException("wrong purpose");
        }
    }

    private sealed class NoDns : IDnsChallengeProvider
    {
        public ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken) => ValueTask.FromResult("handle");

        public ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    internal enum Ari
    {
        /// <summary>The directory has no renewal information: the lifetime rule decides.</summary>
        None,

        /// <summary>The CA suggests the window from day 45 to day 47 of a 90-day certificate.</summary>
        MidLife,

        /// <summary>The CA says "renew now" for every certificate, always (a window in the past).</summary>
        AlwaysNow,

        /// <summary>The renewal information endpoint answers 503.</summary>
        Failing,
    }

    internal sealed record Order(DateTimeOffset At, bool Succeeded);

    internal sealed class ScriptedCa(IClock clock) : IAcmeOrderRunner
    {
        public bool Reachable { get; set; } = true;

        public Ari Mode { get; set; } = Ari.None;

        public List<Order> Orders { get; } = [];

        public List<DateTimeOffset> Issued { get; } = [];

        public int InfoRequests { get; private set; }

        /// <summary>Awaited inside an order, so a test can hold an order open while another replica looks at the lease.</summary>
        public Func<Task>? InsideOrder { get; set; }

        public List<string?> ReplacedChains { get; } = [];

        public async Task<AcmeIssuedCertificate> IssueAsync(AcmeOrderRequest request, IDnsChallengeProvider dns, CancellationToken cancellationToken)
        {
            if (InsideOrder is { } inside)
            {
                await inside();
            }

            if (!Reachable)
            {
                Orders.Add(new Order(clock.UtcNow, false));
                throw new AcmeException("the CA is unreachable (scripted outage)", transient: true);
            }

            Orders.Add(new Order(clock.UtcNow, true));
            Issued.Add(clock.UtcNow);
            ReplacedChains.Add(request.ReplacesCertificatePem);
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest("CN=" + request.Domains[0], key, HashAlgorithmName.SHA256);
            var san = new SubjectAlternativeNameBuilder();
            foreach (string name in request.Domains)
            {
                san.AddDnsName(name);
            }

            req.CertificateExtensions.Add(san.Build());
            using X509Certificate2 cert = req.CreateSelfSigned(clock.UtcNow.AddMinutes(-5), clock.UtcNow + Lifetime);
            return new AcmeIssuedCertificate(cert.ExportCertificatePem(), key.ExportPkcs8PrivateKey(), "-----BEGIN PRIVATE KEY-----\nQUNNRQ==\n-----END PRIVATE KEY-----", "https://ca.example/acct/1", cert.NotAfter.ToUniversalTime());
        }

        public Task<AcmeRenewalInfo?> GetRenewalInfoAsync(string directoryUrl, string certificateChainPem, CancellationToken cancellationToken)
        {
            InfoRequests++;
            switch (Mode)
            {
                case Ari.Failing:
                    throw new AcmeException("ACME server error: 503", transient: true);
                case Ari.AlwaysNow:
                    return Task.FromResult<AcmeRenewalInfo?>(new AcmeRenewalInfo(clock.UtcNow.AddHours(-2), clock.UtcNow.AddHours(-1), null, null));
                case Ari.MidLife:
                    using (var cert = X509Certificate2.CreateFromPem(certificateChainPem))
                    {
                        DateTimeOffset notBefore = cert.NotBefore.ToUniversalTime();
                        return Task.FromResult<AcmeRenewalInfo?>(new AcmeRenewalInfo(notBefore.AddDays(45), notBefore.AddDays(47), null, null));
                    }

                default:
                    return Task.FromResult<AcmeRenewalInfo?>(null);
            }
        }
    }

    internal sealed class Report
    {
        public required ScriptedCa Ca { get; init; }

        /// <summary>Every tick: when it was, the NotAfter of the certificate in the store then (null before the first one).</summary>
        public List<(DateTimeOffset At, DateTimeOffset? NotAfter)> Ticks { get; } = [];

        public int CertificateRows { get; set; }

        public int MaxCertificateRows { get; set; }

        public int Restarts { get; set; }
    }

    internal static AcmeSection Section(bool useRenewalInfo) => new()
    {
        Enabled = true,
        Email = "ops@lifecycle.example",
        Domains = [Host],
        PropagationDelay = TimeSpan.Zero,
        UseRenewalInfo = useRenewalInfo,
        DirectoryUrl = "https://ca.example/dir",
        CheckInterval = CheckInterval,
    };

    /// <summary>
    /// What the renewal loop of the host does, without the real timer: check, then wait for <c>NextCheckDelayAsync</c> (the check interval, or the back-off of a
    /// failed order when that is sooner). The storage is closed and reopened every <paramref name="restartEvery"/> days, as a restarting process would.
    /// </summary>
    internal static async Task<Report> RunAsync(RuntimeStateBackend backend, VirtualClock clock, ScriptedCa ca, int days, Func<DateTimeOffset, bool>? reachable = null, int restartEvery = 0, int seed = 7)
    {
        var report = new Report { Ca = ca };
        var random = new Random(seed);
        var protector = new Protector();
        IStorage storage = await backend.OpenAsync(clock);
        AcmeRenewalService service = Create(storage, protector, ca, clock, random, ca.Mode != Ari.None);
        DateTimeOffset end = clock.UtcNow.AddDays(days);
        DateTimeOffset nextRestart = restartEvery > 0 ? clock.UtcNow.AddDays(restartEvery) : DateTimeOffset.MaxValue;
        try
        {
            while (clock.UtcNow < end)
            {
                if (reachable is not null)
                {
                    ca.Reachable = reachable(clock.UtcNow);
                }

                if (clock.UtcNow >= nextRestart)
                {
                    await storage.DisposeAsync();
                    storage = await backend.OpenAsync(clock);
                    service = Create(storage, protector, ca, clock, random, ca.Mode != Ari.None);
                    nextRestart = clock.UtcNow.AddDays(restartEvery);
                    report.Restarts++;
                }

                await service.CheckOnceAsync(default);
                var rows = await storage.Config.GetCertificatesAsync(default);
                report.CertificateRows = rows.Count;
                report.MaxCertificateRows = Math.Max(report.MaxCertificateRows, rows.Count);
                report.Ticks.Add((clock.UtcNow, rows.Where(c => c.Active).Select(c => (DateTimeOffset?)c.NotAfter).DefaultIfEmpty(null).Max()));
                clock.Advance(await service.NextCheckDelayAsync(default));
            }
        }
        finally
        {
            await storage.DisposeAsync();
        }

        return report;
    }

    private static AcmeRenewalService Create(IStorage storage, ISecretProtector protector, ScriptedCa ca, IClock clock, Random random, bool useRenewalInfo) =>
        new(storage.Config, protector, ca, new NoDns(), Section(useRenewalInfo), clock, random: random.NextDouble);

    /// <summary>The lifetime rule (no renewal information) over 430 days with a CA outage of five days exactly when the second renewal is due.</summary>
    public static async Task LifetimeRuleRenewsOnScheduleAndSurvivesAnOutageAsync(RuntimeStateBackend backend)
    {
        var clock = new VirtualClock(Start);
        var ca = new ScriptedCa(clock) { Mode = Ari.None };
        DateTimeOffset outageStart = Start.AddDays(118);
        DateTimeOffset outageEnd = Start.AddDays(123);
        int days = 430 * Math.Min(Accelerated.Scale, 2);   // two cycles more when scaled
        Report report = await RunAsync(backend, clock, ca, days, at => at < outageStart || at >= outageEnd, restartEvery: 40);

        // Never expired while the CA could be asked, and never without a certificate after the first order.
        foreach (var (at, notAfter) in report.Ticks)
        {
            Assert.NotNull(notAfter);
            Assert.True(at < notAfter, $"the certificate expired at {notAfter:u}, seen at {at:u}");
        }

        // Renewals: the first order, then one each 60 days (a third of the 90 left) apart; the one due in the outage is late by at most the outage plus a back-off.
        Assert.Equal(Start, ca.Issued[0]);
        for (int i = 1; i < ca.Issued.Count; i++)
        {
            TimeSpan gap = ca.Issued[i] - ca.Issued[i - 1];
            // The rule renews when a third of the lifetime (90 days and 5 minutes) is left, noticed at the next daily check.
            Assert.True(gap >= TimeSpan.FromDays(60) - TimeSpan.FromMinutes(5) && gap <= TimeSpan.FromDays(60) + CheckInterval + TimeSpan.FromDays(5) + CheckInterval,
                $"renewal {i} came {gap.TotalDays:F2} days after the one before it");
        }

        int expectedSuccesses = 1 + (int)((days - 1) / 60.0);
        Assert.InRange(ca.Issued.Count, expectedSuccesses - 1, expectedSuccesses);

        // The back-off during the outage is 10, 20, 40, 80, 160, 320 minutes, then 6 hours: each failed order waits exactly that long.
        var failures = ca.Orders.Where(o => !o.Succeeded).ToList();
        Assert.NotEmpty(failures);
        Assert.All(failures, f => Assert.InRange(f.At, outageStart, outageEnd));
        for (int i = 1; i < failures.Count; i++)
        {
            Assert.Equal(AcmeRenewalService.Backoff(i), failures[i].At - failures[i - 1].At);
        }

        // The first order after the outage is the next one the back-off allowed (no later than a day after the CA came back), and it succeeded.
        Order afterOutage = ca.Orders.First(o => o.At >= outageEnd);
        Assert.True(afterOutage.Succeeded);
        Assert.True(afterOutage.At - outageEnd <= AcmeRenewalSchedule.ErrorCheckInterval + TimeSpan.FromMinutes(1), $"{afterOutage.At - outageEnd} after the CA returned");

        // No renewal storm: the orders over 430 days are the renewals plus the failures of one outage, nothing else.
        Assert.True(ca.Orders.Count <= expectedSuccesses + 25, $"{ca.Orders.Count} orders in {days} days");
        Assert.Equal(1, report.MaxCertificateRows);   // a renewal replaces the row, it does not pile up
        Assert.True(report.Restarts >= days / 40 - 1);

        // Every order after the first named the certificate it renews (ARI "replaces").
        Assert.Null(ca.ReplacedChains[0]);
        Assert.All(ca.ReplacedChains.Skip(1), chain => Assert.NotNull(chain));
    }

    /// <summary>An outage that outlasts the certificate: it expires inside the outage and the first order after the CA returns replaces it.</summary>
    public static async Task AnOutageLongerThanTheCertificateEndsWithinTheBackoffCapAfterTheCaReturnsAsync(RuntimeStateBackend backend)
    {
        var clock = new VirtualClock(Start);
        var ca = new ScriptedCa(clock) { Mode = Ari.None };
        DateTimeOffset outageStart = Start.AddDays(58);
        DateTimeOffset outageEnd = Start.AddDays(93);   // the renewal is due on day 60 and the certificate (90 days) expires on day 90, both inside it
        Report report = await RunAsync(backend, clock, ca, 130, at => at < outageStart || at >= outageEnd, restartEvery: 45);

        bool expiredSeen = false;
        foreach (var (at, notAfter) in report.Ticks)
        {
            if (notAfter is { } until && at >= until)
            {
                expiredSeen = true;
                // Expired only while the CA is away and for at most one back-off cap after its return.
                Assert.True(at >= Start.AddDays(90) && at <= outageEnd + AcmeRenewalSchedule.ErrorCheckInterval + CheckInterval, $"expired certificate seen at {at:u}");
            }
        }

        Assert.True(expiredSeen, "the scenario never let the certificate expire, so it proved nothing about an outage");
        // The order failures in the 33 days from the due date to the end of the outage are bounded by the 6-hour cap: 4 a day at most after the first day.
        int failed = ca.Orders.Count(o => !o.Succeeded);
        Assert.InRange(failed, 80, 33 * 4 + 8);
        Assert.True(ca.Orders.Last(o => !o.Succeeded).At < outageEnd);
        Assert.Equal(1, report.MaxCertificateRows);
        // After recovery the service is back on the normal 60-day cycle from the new certificate.
        DateTimeOffset recovered = ca.Issued.First(i => i >= outageEnd);
        Assert.True(recovered - outageEnd <= AcmeRenewalSchedule.ErrorCheckInterval + CheckInterval);
        Assert.Contains(report.Ticks, t => t.At > recovered + TimeSpan.FromDays(10) && t.NotAfter > t.At);
    }

    /// <summary>With the CA's own window (day 45 to 47), renewals come inside it, earlier than the lifetime rule would, and the same seed gives the same run.</summary>
    public static async Task RenewalInformationWindowIsHonouredAndDeterministicAsync(RuntimeStateBackend backend, bool repeatForDeterminism)
    {
        List<TimeSpan> Run(Report r) => [.. r.Ca.Issued.Skip(1).Select((at, i) => at - r.Ca.Issued[i])];

        var clock = new VirtualClock(Start);
        var ca = new ScriptedCa(clock) { Mode = Ari.MidLife };
        Report first = await RunAsync(backend, clock, ca, 330, seed: 11);
        List<TimeSpan> gaps = Run(first);
        Assert.True(gaps.Count >= 6, $"{gaps.Count} renewals in 330 days");
        // The window starts 45 days after notBefore (5 minutes before the issue) and ends 47 days after it; the service renews at a random time inside,
        // noticed at a check that is at most a day late, and a check can find it up to the check interval early (it looks ahead by one interval).
        Assert.All(gaps, g => Assert.InRange(g, TimeSpan.FromDays(45) - CheckInterval - TimeSpan.FromMinutes(5), TimeSpan.FromDays(47) + CheckInterval));
        Assert.True(gaps.Distinct().Count() > 1, "the position inside the window never varied");   // the seeded random is used, not a constant
        Assert.True(first.Ca.InfoRequests >= gaps.Count);
        Assert.Equal(1, first.MaxCertificateRows);

        if (repeatForDeterminism)
        {
            await using RuntimeStateBackend again = backend.Name == "sqlite" ? RuntimeStateBackend.Sqlite() : await RuntimeStateBackend.PostgresAsync();
            var clock2 = new VirtualClock(Start);
            var ca2 = new ScriptedCa(clock2) { Mode = Ari.MidLife };
            Report second = await RunAsync(again, clock2, ca2, 330, seed: 11);
            Assert.Equal(first.Ca.Issued, second.Ca.Issued);   // the same seed, the same days to the second
        }
    }

    /// <summary>
    /// A CA that always says "renew now" cannot make the server renew a young certificate: the minimum age (a twentieth of the lifetime, 4.5 days) holds, so a
    /// year of that is about 80 orders and not thousands.
    /// </summary>
    public static async Task AnImpatientCaCannotCauseARenewalStormAsync(RuntimeStateBackend backend)
    {
        var clock = new VirtualClock(Start);
        var ca = new ScriptedCa(clock) { Mode = Ari.AlwaysNow };
        int days = 120;
        Report report = await RunAsync(backend, clock, ca, days);
        TimeSpan minimumAge = AcmeRenewalSchedule.MinimumAge(Lifetime + TimeSpan.FromMinutes(5));
        Assert.InRange(minimumAge, TimeSpan.FromDays(4.5), TimeSpan.FromDays(4.51));   // a twentieth of the lifetime
        for (int i = 1; i < ca.Issued.Count; i++)
        {
            Assert.True(ca.Issued[i] - ca.Issued[i - 1] >= minimumAge - TimeSpan.FromMinutes(5), $"renewal {i} came {(ca.Issued[i] - ca.Issued[i - 1]).TotalDays:F2} days after the previous");
        }

        Assert.True(ca.Issued.Count <= days / 4.4 + 2, $"{ca.Issued.Count} orders in {days} days");
        Assert.True(ca.Issued.Count >= days / 5.5, $"only {ca.Issued.Count} orders: the CA's 'now' was not followed");
    }

    /// <summary>A renewal information endpoint that keeps failing does not stop renewals: the lifetime rule decides, and the CA is asked at the back-off pace, not at every check.</summary>
    public static async Task FailingRenewalInformationFallsBackToTheLifetimeRuleAsync(RuntimeStateBackend backend)
    {
        var clock = new VirtualClock(Start);
        var ca = new ScriptedCa(clock) { Mode = Ari.Failing };
        Report report = await RunAsync(backend, clock, ca, 200);
        // Issued at day 0, then by the lifetime rule at about day 60 and 120 and 180.
        Assert.Equal(4, ca.Issued.Count);
        for (int i = 1; i < ca.Issued.Count; i++)
        {
            Assert.InRange(ca.Issued[i] - ca.Issued[i - 1], TimeSpan.FromDays(60) - TimeSpan.FromMinutes(5), TimeSpan.FromDays(60) + CheckInterval);
        }

        // Asked at the exponential pace of server errors (5 minutes up to 6 hours): between 4 and 5 times a day once settled, not every check (that would be the same), and
        // never more often than every 5 minutes in the first hours.
        Assert.True(ca.InfoRequests <= 200 * 4 + 100, $"{ca.InfoRequests} requests for renewal information in 200 days");
        Assert.True(report.Ticks.Count > 0);
    }

    /// <summary>Two replicas on one database: while one holds the lease and orders, the other does nothing; a replica that died holding the lease blocks renewal for 20 minutes only.</summary>
    public static async Task OnlyOneReplicaRenewsAndADeadLeaseExpiresAsync(RuntimeStateBackend backend)
    {
        var clock = new VirtualClock(Start);
        var ca = new ScriptedCa(clock);
        var protector = new Protector();
        IStorage a = await backend.OpenAsync(clock);
        IStorage b = backend.Name == "postgres" ? await backend.OpenAsync(clock) : a;   // SQLite is one process on one set of files
        try
        {
            var first = new AcmeRenewalService(a.Config, protector, ca, new NoDns(), Section(useRenewalInfo: false), clock);
            var second = new AcmeRenewalService(b.Config, protector, ca, new NoDns(), Section(useRenewalInfo: false), clock);
            Assert.True(await first.CheckOnceAsync(default));

            // Day 60: due. Replica one starts the order and is held up inside it (the CA is slow); replica two checks meanwhile.
            clock.Advance(TimeSpan.FromDays(60));
            var inside = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            ca.InsideOrder = async () =>
            {
                inside.TrySetResult();
                await release.Task;
            };
            Task<bool> renewing = first.CheckOnceAsync(default);
            await inside.Task;
            ca.InsideOrder = null;
            bool secondOrdered = await second.CheckOnceAsync(default);
            Assert.False(secondOrdered, string.Join(";", ca.Orders.Select(o => o.At.ToString("u") + o.Succeeded)));
            Assert.Single(ca.Issued);   // the second replica ordered nothing: the first holds the lease
            release.SetResult();
            Assert.True(await renewing);
            Assert.Equal(2, ca.Issued.Count);

            // The new certificate is not due: neither replica orders. Day 120: due again, but a dead replica holds the lease (its fencing token and owner are not ours).
            Assert.False(await second.CheckOnceAsync(default));
            clock.Advance(TimeSpan.FromDays(60));
            LeaseRecord? dead = await a.Config.TryAcquireLeaseAsync("acme-renew:default", "replica-that-died", AcmeRenewalService.LeaseDuration, clock.UtcNow, default);
            Assert.NotNull(dead);
            Assert.False(await second.CheckOnceAsync(default));
            Assert.False(await first.CheckOnceAsync(default));
            Assert.Equal(2, ca.Issued.Count);

            clock.Advance(AcmeRenewalService.LeaseDuration - TimeSpan.FromSeconds(1));
            Assert.False(await second.CheckOnceAsync(default));
            clock.Advance(TimeSpan.FromSeconds(1));
            Assert.True(await second.CheckOnceAsync(default));
            Assert.Equal(3, ca.Issued.Count);
            Assert.Single(await b.Config.GetCertificatesAsync(default));
        }
        finally
        {
            await a.DisposeAsync();
            if (!ReferenceEquals(a, b))
            {
                await b.DisposeAsync();
            }
        }
    }

    /// <summary>The certificate provider (what serves TLS) follows renewals by polling the version in the database, with no restart, across a year.</summary>
    public static async Task TheCertificateProviderPicksUpEachRenewalWithoutARestartAsync(RuntimeStateBackend backend)
    {
        var clock = new VirtualClock(Start);
        var ca = new ScriptedCa(clock);
        var protector = new Protector();
        IStorage storage = await backend.OpenAsync(clock);
        try
        {
            var service = new AcmeRenewalService(storage.Config, protector, ca, new NoDns(), Section(useRenewalInfo: false), clock);
            var provider = new DatabaseCertificateProvider(storage.Config, protector, Host, new TlsSection(), clock);
            await provider.InitializeAsync(default);   // the first run: a self-signed placeholder
            Assert.True(provider.UsingSelfSignedOnly);

            var seen = new List<DateTimeOffset>();
            DateTimeOffset end = clock.UtcNow.AddDays(400);
            while (clock.UtcNow < end)
            {
                bool issued = await service.CheckOnceAsync(default);
                await provider.ReloadAsync(force: false, default);   // what the polling loop does each PollInterval
                CertificateInfo served = provider.Describe().OrderBy(c => c.Source == "selfsigned" ? 1 : 0).First();
                var stored = Assert.Single(await storage.Config.GetCertificatesAsync(default), c => c.Source == "acme" && c.Active);
                if (issued)
                {
                    seen.Add(clock.UtcNow);
                }

                Assert.Equal("acme", served.Source);   // the ACME certificate wins over the self-signed placeholder from the first order on
                Assert.Equal(stored.Thumbprint, served.Thumbprint);
                Assert.True(served.NotAfter.ToUniversalTime() > clock.UtcNow.UtcDateTime);
                clock.Advance(await service.NextCheckDelayAsync(default));
            }

            Assert.True(seen.Count >= 7, $"{seen.Count} renewals in 400 days");
            Assert.False(provider.UsingSelfSignedOnly);
        }
        finally
        {
            await storage.DisposeAsync();
        }
    }
}

[Collection("Runtime")]
public class AcmeRenewalLifecycleOnSqlite
{
    [Fact]
    public async Task Lifecycle_lifetime_rule_renews_on_schedule_and_survives_an_outage()
    {
        await using RuntimeStateBackend backend = RuntimeStateBackend.Sqlite();
        await AcmeLifecycleScenarios.LifetimeRuleRenewsOnScheduleAndSurvivesAnOutageAsync(backend);
    }

    [Fact]
    public async Task Lifecycle_an_outage_longer_than_the_certificate_ends_within_the_backoff_cap_after_the_CA_returns()
    {
        await using RuntimeStateBackend backend = RuntimeStateBackend.Sqlite();
        await AcmeLifecycleScenarios.AnOutageLongerThanTheCertificateEndsWithinTheBackoffCapAfterTheCaReturnsAsync(backend);
    }

    [Fact]
    public async Task Lifecycle_renewal_information_window_is_honoured_and_deterministic()
    {
        await using RuntimeStateBackend backend = RuntimeStateBackend.Sqlite();
        await AcmeLifecycleScenarios.RenewalInformationWindowIsHonouredAndDeterministicAsync(backend, repeatForDeterminism: true);
    }

    [Fact]
    public async Task Lifecycle_an_impatient_CA_cannot_cause_a_renewal_storm()
    {
        await using RuntimeStateBackend backend = RuntimeStateBackend.Sqlite();
        await AcmeLifecycleScenarios.AnImpatientCaCannotCauseARenewalStormAsync(backend);
    }

    [Fact]
    public async Task Lifecycle_failing_renewal_information_falls_back_to_the_lifetime_rule()
    {
        await using RuntimeStateBackend backend = RuntimeStateBackend.Sqlite();
        await AcmeLifecycleScenarios.FailingRenewalInformationFallsBackToTheLifetimeRuleAsync(backend);
    }

    [Fact]
    public async Task Lifecycle_only_one_replica_renews_and_a_dead_lease_expires()
    {
        await using RuntimeStateBackend backend = RuntimeStateBackend.Sqlite();
        await AcmeLifecycleScenarios.OnlyOneReplicaRenewsAndADeadLeaseExpiresAsync(backend);
    }

    [Fact]
    public async Task Lifecycle_the_certificate_provider_picks_up_each_renewal_without_a_restart()
    {
        await using RuntimeStateBackend backend = RuntimeStateBackend.Sqlite();
        await AcmeLifecycleScenarios.TheCertificateProviderPicksUpEachRenewalWithoutARestartAsync(backend);
    }
}

[Collection("Runtime")]
public class AcmeRenewalLifecycleOnPostgres
{
    [PostgresFact]
    public async Task Lifecycle_lifetime_rule_renews_on_schedule_and_survives_an_outage()
    {
        await using RuntimeStateBackend backend = await RuntimeStateBackend.PostgresAsync();
        await AcmeLifecycleScenarios.LifetimeRuleRenewsOnScheduleAndSurvivesAnOutageAsync(backend);
    }

    [PostgresFact]
    public async Task Lifecycle_an_outage_longer_than_the_certificate_ends_within_the_backoff_cap_after_the_CA_returns()
    {
        await using RuntimeStateBackend backend = await RuntimeStateBackend.PostgresAsync();
        await AcmeLifecycleScenarios.AnOutageLongerThanTheCertificateEndsWithinTheBackoffCapAfterTheCaReturnsAsync(backend);
    }

    [PostgresFact]
    public async Task Lifecycle_renewal_information_window_is_honoured()
    {
        await using RuntimeStateBackend backend = await RuntimeStateBackend.PostgresAsync();
        await AcmeLifecycleScenarios.RenewalInformationWindowIsHonouredAndDeterministicAsync(backend, repeatForDeterminism: false);
    }

    [PostgresFact]
    public async Task Lifecycle_an_impatient_CA_cannot_cause_a_renewal_storm()
    {
        await using RuntimeStateBackend backend = await RuntimeStateBackend.PostgresAsync();
        await AcmeLifecycleScenarios.AnImpatientCaCannotCauseARenewalStormAsync(backend);
    }

    [PostgresFact]
    public async Task Lifecycle_failing_renewal_information_falls_back_to_the_lifetime_rule()
    {
        await using RuntimeStateBackend backend = await RuntimeStateBackend.PostgresAsync();
        await AcmeLifecycleScenarios.FailingRenewalInformationFallsBackToTheLifetimeRuleAsync(backend);
    }

    [PostgresFact]
    public async Task Lifecycle_only_one_replica_renews_and_a_dead_lease_expires()
    {
        await using RuntimeStateBackend backend = await RuntimeStateBackend.PostgresAsync();
        await AcmeLifecycleScenarios.OnlyOneReplicaRenewsAndADeadLeaseExpiresAsync(backend);
    }

    [PostgresFact]
    public async Task Lifecycle_the_certificate_provider_picks_up_each_renewal_without_a_restart()
    {
        await using RuntimeStateBackend backend = await RuntimeStateBackend.PostgresAsync();
        await AcmeLifecycleScenarios.TheCertificateProviderPicksUpEachRenewalWithoutARestartAsync(backend);
    }
}
