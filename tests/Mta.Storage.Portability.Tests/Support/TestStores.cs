using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Mta.Core;
using Mta.Storage.InMemory;
using Mta.Storage.Portability;
using Mta.Storage.Sqlite;
using Mta.Storage.Transfer;

namespace Mta.Storage.Portability.Tests;

public enum StoreKind
{
    InMemory,
    Sqlite,
    Postgres,
}

/// <summary><see cref="ISecretProtector"/> over a standalone Data Protection key ring, like each deployment's own ring.</summary>
public sealed class RingProtector : ISecretProtector
{
    private readonly IDataProtectionProvider _provider;

    private RingProtector(IDataProtectionProvider provider) => _provider = provider;

    public static RingProtector Create(string directory, X509Certificate2? certificate = null)
    {
        Directory.CreateDirectory(directory);
        return new RingProtector(DataProtectionProvider.Create(new DirectoryInfo(directory), b =>
        {
            b.SetApplicationName("EggMail");
            if (certificate is not null)
            {
                b.ProtectKeysWithCertificate(certificate);
            }
        }));
    }

    public static X509Certificate2 NewCertificate()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=test ring", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var temp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return X509CertificateLoader.LoadPkcs12(temp.Export(X509ContentType.Pfx, "x"), "x", X509KeyStorageFlags.Exportable);
    }

    public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => _provider.CreateProtector(purpose).Protect(plaintext.ToArray());

    public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose) => _provider.CreateProtector(purpose).Unprotect(protectedData.ToArray());
}

/// <summary>One store under test (in-memory, or SQLite in its own directory) with its own secret protector.</summary>
public sealed class TestStore : IAsyncDisposable
{
    private readonly StorageOptions _options;
    private readonly Func<StorageOptions, IStorage>? _reopen;
    private readonly IAsyncDisposable? _owned;

    private TestStore(StoreKind kind, string root, string name, IStorage storage, StorageOptions options, RingProtector protector, bool protectedAtRest, Func<StorageOptions, IStorage>? reopen = null, IAsyncDisposable? owned = null)
    {
        _reopen = reopen;
        _owned = owned;
        Kind = kind;
        Root = root;
        Name = name;
        Storage = storage;
        _options = options;
        Protector = protector;
        ProtectedAtRest = protectedAtRest;
    }

    public StoreKind Kind { get; }

    public string Root { get; }

    public string Name { get; }

    public IStorage Storage { get; private set; }

    public RingProtector Protector { get; }

    public bool ProtectedAtRest { get; }

    public string? DataDirectory => Kind == StoreKind.Sqlite ? System.IO.Path.Combine(Root, Name) : null;

    public StorageOptions Options => _options;

    public IStorageTransfer Transfer => Storage.Transfer!;

    public SwitchEndpoint Endpoint => new() { Storage = Storage, Secrets = Protector, Options = _options, KeysProtectedAtRest = ProtectedAtRest };

    public static async Task<TestStore> CreateAsync(StoreKind kind, HistoryMode history, string root, string name, bool certificateRing = true, SqliteSyncMode sync = SqliteSyncMode.Off, Func<StorageOptions, StorageOptions>? tweak = null)
    {
        string dir = System.IO.Path.Combine(root, name);
        StorageOptions options = new()
        {
            Backend = kind == StoreKind.Sqlite ? StorageBackend.Sqlite : StorageBackend.InMemory,
            History = new HistoryOptions { Mode = history },
            Sqlite = new SqliteOptions { DataDirectory = dir, SyncMode = sync, StatsFlushInterval = TimeSpan.Zero, WriterBatchWindow = TimeSpan.Zero },
            Content = new ContentOptions { StoreAttachments = true, AllowAttachmentStorage = true },
        };
        if (tweak is not null)
        {
            options = tweak(options);
        }

        IStorage storage = kind == StoreKind.Sqlite ? SqliteStorage.Create(options) : new InMemoryStorage(options, SystemClock.Instance, null, TimeSpan.Zero);
        await storage.InitializeAsync(CancellationToken.None);
        RingProtector ring = RingProtector.Create(System.IO.Path.Combine(root, name + "-ring"), certificateRing ? RingProtector.NewCertificate() : null);
        return new TestStore(kind, root, name, storage, options, ring, certificateRing);
    }

    /// <summary>Wraps a storage created by a test project that knows the backend (PostgreSQL), with its own secret ring. <paramref name="owned"/> is disposed last (drops the database).</summary>
    public static async Task<TestStore> WrapAsync(StoreKind kind, IStorage storage, StorageOptions options, string root, string name, Func<StorageOptions, IStorage> reopen, IAsyncDisposable? owned, bool certificateRing = true)
    {
        await storage.InitializeAsync(CancellationToken.None);
        RingProtector ring = RingProtector.Create(System.IO.Path.Combine(root, name + "-ring"), certificateRing ? RingProtector.NewCertificate() : null);
        return new TestStore(kind, root, name, storage, options, ring, certificateRing, reopen, owned);
    }

    /// <summary>Closes the store and opens it again over the same data (not in-memory): what a restart does.</summary>
    public async Task ReopenAsync()
    {
        if (Kind == StoreKind.InMemory)
        {
            throw new InvalidOperationException("An in-memory store does not survive a restart.");
        }

        await Storage.DisposeAsync();
        Storage = _reopen is not null ? _reopen(_options) : SqliteStorage.Create(_options);
        await Storage.InitializeAsync(CancellationToken.None);
    }

    public async ValueTask DisposeAsync()
    {
        await Storage.DisposeAsync();
        if (_owned is not null)
        {
            await _owned.DisposeAsync();
        }
    }
}

/// <summary>Fills a store through its public APIs: configuration with real protected secrets, mail in every state, history over several days.</summary>
public static class Seed
{
    public static readonly Guid TenantA = Guid.Parse("a0000000-0000-7000-8000-000000000001");
    public static readonly Guid TenantB = Guid.Parse("b0000000-0000-7000-8000-000000000002");

    public static readonly byte[] DkimPlain = Enumerable.Range(0, 64).Select(i => (byte)(i * 7 + 3)).ToArray();

    public sealed record Seeded(Guid DomainId, Guid[] QueuedMessageIds, Guid[] QueuedDeliveryIds, string IdempotencyKey, Guid IdempotencyMessageId);

    public const string CountedDomain = "example.com";

    public static async Task<Seeded> PopulateAsync(IStorage storage, ISecretProtector secrets, int queued = 6, int deliveredPerDay = 2, int days = 3)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        IConfigStore c = storage.Config;
        Guid domainId = Ids.New();
        await c.UpsertTenantAsync(new Tenant(TenantA, "Acme", "acme", true, now, true), default);
        await c.UpsertTenantAsync(new Tenant(TenantB, "Beta", "beta", true, now, false), default);
        await c.UpsertDomainAsync(new DomainRecord(domainId, TenantA, "example.com", DomainStatus.Verified, "bounces.example.com", true, now, now, now.AddHours(1), 0, null, false, null), default);
        await c.AddDkimKeyAsync(new DkimKeyRecord(Ids.New(), domainId, "egg1", secrets.Protect(DkimPlain, SecretPurposes.DkimKey), "PUBLICKEYBASE64", now, true, null), default);
        await c.AddApiKeyAsync(new ApiKeyRecord(Ids.New(), TenantA, "ci", "egg_ab12", SHA256.HashData("api-key"u8), "send,read", now, null, null), default);
        await c.UpsertSmtpCredentialAsync(new SmtpCredential(Ids.New(), TenantA, "acme-user", "pbkdf2$1000$salt$hash", true, now), default);
        for (int i = 0; i < 25; i++)
        {
            await c.AddSuppressionAsync(new SuppressionRecord(TenantA, $"gone{i}@example.org", SuppressionReason.HardBounce, "550 5.1.1 unknown", now, null), default);
        }

        await c.SetSettingAsync(new SettingRecord("limits.perMinute", null, "120", now), default);
        await c.SetSettingAsync(new SettingRecord("brand.name", TenantA, "\"Acme\"", now), default);
        await c.UpsertTlsPolicyAsync(new TlsPolicyRecord(Ids.New(), "*.partner.example", TlsLevel.Verify), default);
        await c.UpsertRelayRouteAsync(new RelayRouteRecord(Ids.New(), "relay1", "relay.example.net", 587, "StartTls", "u", secrets.Protect("relay-pass"u8, SecretPurposes.RelayPassword), 10, true, ["partner.example"]), default);
        await c.UpsertCertificateAsync(new CertificateRecord(Ids.New(), "default", ["mail.example.com"], now.AddDays(-1), now.AddDays(89), "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", secrets.Protect("cert-private-key"u8, SecretPurposes.TlsPrivateKey), "acme", "AB:CD:EF", true, 0, now), default);
        await c.UpsertAcmeAccountAsync(new AcmeAccountRecord(Ids.New(), "https://acme.example/dir", "ops@example.com", secrets.Protect("acme-account-key"u8, SecretPurposes.AcmeAccountKey), "https://acme.example/acct/1", now), default);
        await c.UpsertAcmeRenewalAsync(new AcmeRenewalRecord("default", "pending", now, now.AddDays(60), 1, "challenge failed", "{\"token\":\"abc\"}", "{\"ari\":1}"), default);

        // Persisted runtime state: the last check of each record of the domain, an unsent TLS-RPT counter piece, and the sending counters of the current windows.
        await c.ReplaceDomainRecordChecksAsync(domainId, [
            new DomainRecordCheckRecord(domainId, "TXT|egg1._domainkey.example.com", "ok", "v=DKIM1; k=rsa; p=PUBLICKEYBASE64", now),
            new DomainRecordCheckRecord(domainId, "TXT|example.com", "invalid", "v=spf1 -all", now),
            new DomainRecordCheckRecord(domainId, "TXT|_dmarc.example.com", "missing", null, now),
        ], default);
        await c.AddTlsRptBucketsAsync([new TlsRptBucketRecord(Ids.New(now), (int)(now.ToUnixTimeSeconds() / 86400) - 1, "partner.example", "{\"policyDomain\":\"partner.example\"}", 2, now)], default);
        long hour = now.ToUnixTimeSeconds() / 3600;
        long day = now.ToUnixTimeSeconds() / 86400;
        await c.AddSendingCountersAsync([
            new SendingCounterRecord(0, Guid.Empty, "", 0, hour, 17),
            new SendingCounterRecord(1, TenantA, "", 1, day, 29),
            new SendingCounterRecord(2, Guid.Empty, CountedDomain, 1, day, 31),
        ], hour - 1, day - 1, default);

        Guid endpoint = Ids.New();
        await c.UpsertWebhookEndpointAsync(new WebhookEndpointRecord(endpoint, TenantA, "https://hooks.example.com/in", secrets.Protect("whsec_123"u8, SecretPurposes.WebhookSecret), ["*"], true, null, null, now, null), default);

        // History over several days: messages received on earlier days, delivered now.
        for (int d = days; d >= 1; d--)
        {
            for (int i = 0; i < deliveredPerDay; i++)
            {
                DateTimeOffset received = now.AddDays(-d);
                AcceptedMessage m = Message(received, now.AddDays(1), [$"hist{d}-{i}@example.net"], retainRaw: i == 0);
                await storage.Intake.AcceptAsync(m, default);
                var claimed = await storage.Deliveries.ClaimAsync("seed", 50, now, TimeSpan.FromMinutes(1), default);
                foreach (ClaimedDelivery cd in claimed)
                {
                    await storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt
                    {
                        DeliveryId = cd.DeliveryId, Outcome = DeliveryOutcome.Delivered, At = now, SmtpCode = 250, MxHost = "mx.example.net", Route = "direct", Duration = TimeSpan.FromMilliseconds(40),
                        WebhookEvents = [new WebhookEventDraft(Ids.New(), "message.delivered", "{\"ok\":true}")],
                    }, default);
                }
            }
        }

        // The live queue: some never tried, one deferred with retry state, one with an idempotency key.
        var ids = new List<Guid>();
        var deliveries = new List<Guid>();
        string idemKey = "idem-key-1";
        Guid idemMessage = Guid.Empty;
        for (int i = 0; i < queued; i++)
        {
            AcceptedMessage m = Message(now, now.AddDays(5), [$"queued{i}@example.org", $"queued{i}b@example.net"], idempotencyKey: i == 0 ? idemKey : null, size: i == 1 ? 120_000 : 1500);
            await storage.Intake.AcceptAsync(m, default);
            ids.Add(m.MessageId);
            deliveries.AddRange(m.Recipients.Select(r => r.DeliveryId));
            if (i == 0)
            {
                idemMessage = m.MessageId;
            }
        }

        // Defer one delivery: attempt 1, due later, last error set.
        if (queued > 0)
        {
            var first = await storage.Deliveries.ClaimAsync("seed", 1, now, TimeSpan.FromMinutes(1), default);
            await storage.Deliveries.RecordAttemptAsync(new DeliveryAttempt
            {
                DeliveryId = first[0].DeliveryId, Outcome = DeliveryOutcome.Deferred, At = now, SmtpCode = 451, Message = "try again later", NextAttemptAt = now.AddMinutes(30), Duration = TimeSpan.FromMilliseconds(10),
            }, default);
        }

        await storage.Webhooks.EnqueueAsync(TenantA, new WebhookEventDraft(Ids.New(), "message.bounced", "{\"async\":true}"), now, default);
        await storage.Stats.FlushAsync(default);
        return new Seeded(domainId, ids.ToArray(), deliveries.ToArray(), idemKey, idemMessage);
    }

    public static AcceptedMessage Message(DateTimeOffset received, DateTimeOffset expires, string[] to, string? idempotencyKey = null, bool retainRaw = false, int size = 1500, Guid? tenant = null)
    {
        byte[] raw = new byte[size];
        RandomNumberGenerator.Fill(raw);
        string head = $"From: sender@example.com\r\nTo: {string.Join(", ", to)}\r\nSubject: Hello {Guid.NewGuid():N}\r\nMessage-ID: <{Guid.NewGuid():N}@example.com>\r\nDate: Mon, 12 Oct 2026 08:00:00 +0000\r\n\r\n";
        byte[] message = System.Text.Encoding.ASCII.GetBytes(head).Concat(raw.Select(b => (byte)('a' + (b % 26)))).ToArray();
        return new AcceptedMessage
        {
            MessageId = Ids.New(received),
            TenantId = tenant ?? TenantA,
            Source = MessageSource.Api,
            EnvelopeFrom = EmailAddress.Parse("sender@example.com"),
            Recipients = to.Select(t => new AcceptedRecipient(Ids.New(received), EmailAddress.Parse(t))).ToList(),
            Raw = message,
            ReceivedAt = received,
            ExpiresAt = expires,
            IdempotencyKey = idempotencyKey,
            Content = new MessageContent("Hello", "plain text", "<p>html</p>", [new AttachmentInfo("a.pdf", "application/pdf", 10, null)], false),
            RetainRaw = retainRaw,
            SendingDomain = "example.com",
            MessageIdHeader = $"<{Guid.NewGuid():N}@example.com>",
            Tags = ["seed", "tag \"quoted\""],
        };
    }

    /// <summary>Canonical rows of every table of a store, by table (ordered, so the lists can be compared).</summary>
    public static async Task<Dictionary<string, List<string>>> SnapshotAsync(IStorage storage, bool includeHistory = true)
    {
        var result = new Dictionary<string, List<string>>();
        foreach (TransferTable table in TransferTables.All.Where(t => storage.Transfer!.HasPart(t.Part) && (includeHistory || t.Part != TransferPart.History)))
        {
            var rows = new List<string>();
            await foreach (object row in storage.Transfer!.ReadAsync(table, TransferRange.All, default))
            {
                rows.Add(table.Canonical(row));
            }

            result[table.Name] = rows.Order(StringComparer.Ordinal).ToList();
        }

        return result;
    }

    /// <summary>The plain secrets of a store, keyed by table, row (canonical text) and column.</summary>
    public static async Task<Dictionary<string, string>> PlainSecretsAsync(IStorage storage, ISecretProtector secrets)
    {
        var result = new Dictionary<string, string>();
        foreach (TransferTable table in TransferTables.All.Where(t => t.Secrets.Count > 0))
        {
            await foreach (object row in storage.Transfer!.ReadAsync(table, TransferRange.All, default))
            {
                string key = table.Name + "|" + table.Canonical(row);
                foreach (ITransferSecret secret in table.Secrets)
                {
                    if (secret.Get(row) is { Length: > 0 } stored)
                    {
                        result[key + "|" + secret.Column] = Convert.ToBase64String(secrets.Unprotect(stored, secret.Purpose));
                    }
                }
            }
        }

        return result;
    }
}
