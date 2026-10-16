using Certes;
using Mta.Host.Tls;

namespace Mta.Host.Tests.Acme;

/// <summary>
/// The real <see cref="CertesOrderRunner"/> in front of a <see cref="MockAcmeServer"/>, with a recording pause (the waits the runner asked for, none of them real)
/// and recording DNS and HTTP-01 providers. One rig per test.
/// </summary>
internal sealed class AcmeRig : IDisposable
{
    public AcmeRig(Func<DateTimeOffset>? now = null)
    {
        Ca = new MockAcmeServer(now);
        Log = new HttpListLog();
        Runner = new CertesOrderRunner(Ca, Log, (delay, ct) =>
        {
            ct.ThrowIfCancellationRequested();
            lock (Pauses)
            {
                Pauses.Add(delay);
            }

            return Task.CompletedTask;
        });
    }

    public MockAcmeServer Ca { get; }

    public HttpListLog Log { get; }

    public CertesOrderRunner Runner { get; }

    public RecordingDnsProvider Dns { get; } = new();

    public RecordingHttpPublisher Http { get; } = new();

    /// <summary>The waits the runner asked for, in order.</summary>
    public List<TimeSpan> Pauses { get; } = [];

    /// <summary>The account key the next order uses (null: register a new account); set when the runner reports a new account.</summary>
    public string? AccountKeyPem { get; set; }

    public AcmeOrderRequest Order(AcmeChallengeType challenge = AcmeChallengeType.Dns01, string[]? names = null, string? replaces = null, string? eabKeyId = null, string? eabHmacKey = null,
        TimeSpan? propagation = null, Func<AcmeAccountCreated, CancellationToken, Task>? accountCreated = null) =>
        new(MockAcmeServer.DirectoryUrl, "ops@mock.test", names ?? ["mx.mock.test"], AccountKeyPem, propagation ?? TimeSpan.Zero, accountCreated ?? RememberAccount, replaces, challenge, Http,
            "default", eabKeyId, eabHmacKey);

    private Task RememberAccount(AcmeAccountCreated created, CancellationToken ct)
    {
        AccountKeyPem = created.AccountKeyPem;
        return Task.CompletedTask;
    }

    /// <summary>Runs one order; validated for real against the records (DNS-01) or answers (HTTP-01) the order publishes.</summary>
    public Task<AcmeIssuedCertificate> IssueAsync(AcmeChallengeType challenge = AcmeChallengeType.Dns01, string[]? names = null, CancellationToken ct = default)
    {
        Ca.Validator = challenge == AcmeChallengeType.Dns01 ? MockChallengeValidators.Dns(Dns) : MockChallengeValidators.Http(Http);
        return Runner.IssueAsync(Order(challenge, names), Dns, ct);
    }

    public static string NewAccountKeyPem() => KeyFactory.NewKey(KeyAlgorithm.ES256).ToPem();

    public void Dispose() => Ca.Dispose();
}
