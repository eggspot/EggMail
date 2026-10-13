using System.Text.Json;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Secrets;
using Mta.Host.Tls;
using Mta.Storage;

namespace Mta.Integration.Tests.Acme;

/// <summary>The directory's endpoints (so tests can count the requests a client makes to each).</summary>
internal sealed record AcmeEndpoints(string NewAccount, string NewOrder)
{
    public static async Task<AcmeEndpoints> FetchAsync(string directoryUrl, HttpMessageHandler transport)
    {
        using var http = Pebble.NewClient(transport);
        using var doc = JsonDocument.Parse(await http.GetStringAsync(directoryUrl));
        return new AcmeEndpoints(doc.RootElement.GetProperty("newAccount").GetString()!, doc.RootElement.GetProperty("newOrder").GetString()!);
    }
}

/// <summary>
/// One ACME test's world: a config store (SQLite or PostgreSQL), the real Data Protection based secret protector over that store, a clock
/// the test controls, and the real <see cref="CertesOrderRunner"/> talking to the test CA through a request-recording transport.
/// </summary>
internal sealed class AcmeHarness : IAsyncDisposable
{
    private readonly Func<Task>? _cleanup;
    private readonly SocketsHttpHandler _transport = Pebble.CreateTransport();

    private AcmeHarness(IStorage storage, string directoryUrl, Func<Task>? cleanup)
    {
        Storage = storage;
        DirectoryUrl = directoryUrl;
        _cleanup = cleanup;
        Secrets = SecretsFactory.Create(new SecretsSection(), storage.Config);
        Http = new RecordingHandler(_transport);
    }

    public IStorage Storage { get; }

    public string DirectoryUrl { get; }

    public ISecretProtector Secrets { get; }

    public AdvanceableClock Clock { get; } = new(DateTimeOffset.UtcNow);

    public RecordingLog Log { get; } = new();

    /// <summary>All requests of every runner this harness made (an instance per "process start" is built by <see cref="CreateService"/>).</summary>
    public RecordingHandler Http { get; }

    public AcmeEndpoints Endpoints { get; private set; } = null!;

    public static async Task<AcmeHarness> CreateAsync(IStorage storage, Func<Task>? cleanup = null, string? directoryUrl = null)
    {
        await storage.InitializeAsync(default);
        var harness = new AcmeHarness(storage, directoryUrl ?? Pebble.Directory, cleanup);
        if (directoryUrl is null)
        {
            harness.Endpoints = await AcmeEndpoints.FetchAsync(harness.DirectoryUrl, harness._transport);
        }

        return harness;
    }

    /// <summary>A renewal service as a freshly started process would build it: its own runner (no cached state), the shared store and clock.</summary>
    public AcmeRenewalService CreateService(IDnsChallengeProvider dns, IEnumerable<string> domains, RecordingHandler? http = null, IAcmeOrderRunner? runner = null) =>
        new(Storage.Config, Secrets, runner ?? new CertesOrderRunner(http ?? Http), dns, Section(domains), Clock, Log);

    public AcmeSection Section(IEnumerable<string> domains) => new()
    {
        Enabled = true,
        DirectoryUrl = DirectoryUrl,
        Email = "ops@acme-test.example",
        Domains = [.. domains],
        PropagationDelay = TimeSpan.Zero,
    };

    public async ValueTask DisposeAsync()
    {
        Http.Dispose();
        _transport.Dispose();
        await Storage.DisposeAsync();
        if (_cleanup is not null)
        {
            await _cleanup();
        }
    }
}
