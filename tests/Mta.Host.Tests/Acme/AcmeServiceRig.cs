using System.Net;
using System.Reflection;
using System.Text.Json.Nodes;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Tests.Api;
using Mta.Host.Tls;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests.Acme;

/// <summary>
/// The renewal service as a process runs it (real <see cref="CertesOrderRunner"/>, the real certificate and account bookkeeping over a config store) in front of the
/// scriptable <see cref="MockAcmeServer"/>, with a fake clock the mock CA's certificates follow. Several services share one rig (they are the replicas).
/// </summary>
internal sealed class AcmeServiceRig : IDisposable
{
    public const string Host = "mx.service.test";

    public AcmeServiceRig()
    {
        Clock = new TestClock(new DateTimeOffset(2026, 10, 15, 8, 0, 0, TimeSpan.Zero));
        Ca = new MockAcmeServer(() => Clock.UtcNow);
        Storage = new InMemoryStorage(new StorageOptions(), Clock);
        Ca.Validator = MockChallengeValidators.Dns(Dns);
    }

    public TestClock Clock { get; }

    public MockAcmeServer Ca { get; }

    public InMemoryStorage Storage { get; }

    public HttpListLog Log { get; } = new();

    public RecordingDnsProvider Dns { get; } = new();

    public List<TimeSpan> Pauses { get; } = [];

    public TestProtector Protector { get; } = new();

    public IConfigStore Config => Storage.Config;

    /// <summary>A runner as a freshly started process would build it: no state of its own, the CA reached through the mock, waits recorded and not slept.</summary>
    public CertesOrderRunner NewRunner() => new(Ca, Log, (delay, _) =>
    {
        lock (Pauses)
        {
            Pauses.Add(delay);
        }

        return Task.CompletedTask;
    });

    public AcmeSection Options(bool useRenewalInfo = false, string[]? domains = null, AcmeChallengeMode challenge = AcmeChallengeMode.Dns01, string? eabKeyId = null, string? eabKey = null) => new()
    {
        Enabled = true,
        Email = "ops@service.test",
        Domains = [.. domains ?? [Host]],
        DirectoryUrl = MockAcmeServer.DirectoryUrl,
        UseRenewalInfo = useRenewalInfo,
        PropagationDelay = TimeSpan.Zero,
        Challenge = challenge,
        EabKeyId = eabKeyId,
        EabHmacKey = eabKey,
    };

    /// <summary>One replica: its own owner id and runner over the shared store and clock.</summary>
    public AcmeRenewalService Service(AcmeSection? options = null, IDnsChallengeProvider? dns = null, IConfigStore? config = null, double random = 0.5, IHttpChallengePublisher? http = null) =>
        new(config ?? Config, Protector, NewRunner(), dns ?? Dns, options ?? Options(), Clock, Log, () => random, http);

    public async Task<CertificateRecord> OnlyCertificateAsync() => Assert.Single(await Config.GetCertificatesAsync(default));

    public async Task<AcmeRenewalRecord> RenewalAsync(string name = "default") => Assert.Single(await Config.GetAcmeRenewalsAsync(default), r => r.CertificateName == name);

    public void Dispose()
    {
        Ca.Dispose();
        Storage.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    /// <summary>An ARI answer the mock CA serves: the window and an optional <c>Retry-After</c>.</summary>
    public static Func<string, HttpResponseMessage> Window(DateTimeOffset start, DateTimeOffset end, int? retryAfterSeconds = null) => _ =>
    {
        var response = MockAcmeServer.Json(HttpStatusCode.OK, new JsonObject
        {
            ["suggestedWindow"] = new JsonObject { ["start"] = start.ToString("o"), ["end"] = end.ToString("o") },
        });
        if (retryAfterSeconds is not null)
        {
            response.Headers.TryAddWithoutValidation("Retry-After", retryAfterSeconds.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        return response;
    };
}

/// <summary>A DNS provider that stops in <c>CreateTxtAsync</c> until the test lets it go: an order that is in flight at the CA while the test does other things.</summary>
internal sealed class GatedDnsProvider(IDnsChallengeProvider inner) : IDnsChallengeProvider
{
    private readonly TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Completes when the order has arrived at the first record.</summary>
    public Task Reached => _reached.Task;

    public void Release() => _release.TrySetResult();

    public async ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken)
    {
        _reached.TrySetResult();
        await _release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        return await inner.CreateTxtAsync(fqdn, value, cancellationToken).ConfigureAwait(false);
    }

    public ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken) => inner.DeleteTxtAsync(handle, cancellationToken);
}

/// <summary>Forwards every call to the real config store and fails the n-th call of a method on demand (the database going away at the worst moment).</summary>
public class FaultyConfig : DispatchProxy
{
    private IConfigStore _inner = null!;
    private readonly Dictionary<string, int> _failuresLeft = [];

    internal static (IConfigStore Store, FaultyConfig Control) Wrap(IConfigStore inner)
    {
        var proxy = Create<IConfigStore, FaultyConfig>();
        var control = (FaultyConfig)(object)proxy;
        control._inner = inner;
        return (proxy, control);
    }

    /// <summary>The next <paramref name="times"/> calls of <paramref name="method"/> throw.</summary>
    public void Fail(string method, int times = 1)
    {
        lock (_failuresLeft)
        {
            _failuresLeft[method] = times;
        }
    }

    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        lock (_failuresLeft)
        {
            if (_failuresLeft.TryGetValue(targetMethod!.Name, out int left) && left > 0)
            {
                _failuresLeft[targetMethod.Name] = left - 1;
                throw new InvalidOperationException("the database is unavailable");
            }
        }

        try
        {
            return targetMethod!.Invoke(_inner, args);
        }
        catch (TargetInvocationException ex)
        {
            throw ex.InnerException ?? ex;
        }
    }
}
