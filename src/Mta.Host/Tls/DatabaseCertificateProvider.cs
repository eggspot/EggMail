using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Smtp.Server;
using Mta.Storage;

namespace Mta.Host.Tls;

/// <summary>
/// Serves SMTP and dashboard TLS from certificates stored in the database (decision K), with an optional file override
/// that takes precedence (for example cert-manager mounts). Each replica holds the certificates in memory and polls the
/// store for a changed version, validating a new certificate before swapping it in; if validation fails the old
/// certificate stays and a warning is logged. If the database is unreachable the in-memory certificates keep serving.
/// Bootstrap: when no certificate exists a self-signed one is generated and stored.
/// </summary>
public sealed class DatabaseCertificateProvider : IServerCertificateProvider
{
    private readonly IConfigStore _config;
    private readonly ISecretProtector _protector;
    private readonly IClock _clock;
    private readonly IMtaLog _log;
    private readonly string _hostname;
    private readonly TlsSection _tls;
    /// <summary>A self-signed certificate that expires within this is replaced at the next start.</summary>
    internal static readonly TimeSpan SelfSignedRenewalMargin = TimeSpan.FromDays(30);

    private volatile Snapshot _snapshot = Snapshot.Empty;
    private long _lastVersion = -1;
    private string? _overrideFingerprint;

    private readonly bool _replaceOnHostnameChange;

    /// <param name="replaceOnHostnameChange">
    /// Replace a self-signed certificate made for another host name by one for <paramref name="hostname"/>. Pass false while nobody chose the host name (a container
    /// that is recreated gets a new random one every time, and a new certificate for each would only pile up); an expiring self-signed certificate is replaced either way.
    /// </param>
    public DatabaseCertificateProvider(IConfigStore config, ISecretProtector protector, string hostname, TlsSection tls, IClock? clock = null, IMtaLog? log = null, bool replaceOnHostnameChange = true)
    {
        _replaceOnHostnameChange = replaceOnHostnameChange;
        _config = config;
        _protector = protector;
        _hostname = hostname;
        _tls = tls;
        _clock = clock ?? SystemClock.Instance;
        _log = log ?? NullMtaLog.Instance;
    }

    /// <summary>Number of certificates currently served (database plus override).</summary>
    public int Count => _snapshot.Entries.Count;

    /// <summary>True when the only certificate available is a first-run self-signed one (the dashboard flags it).</summary>
    public bool UsingSelfSignedOnly => _snapshot.Entries.Count > 0 && _snapshot.Entries.All(e => e.Source == "selfsigned");

    public IReadOnlyList<CertificateInfo> Describe() => _snapshot.Entries
        .Select(e => new CertificateInfo(e.Name, e.Subjects, e.Leaf.NotBefore, e.Leaf.NotAfter, e.Source, e.Leaf.Thumbprint)).ToList();

    /// <summary>
    /// Loads certificates, generating the first-run self-signed certificate if the store is empty. A self-signed certificate made for another host name
    /// (<c>EGGMAIL_HOSTNAME</c> was set later; see the constructor for when this is on) is replaced by one for the current name as long as nothing but self-signed
    /// certificates exist. While a self-signed certificate is all there is, every start says so in the log.
    /// </summary>
    public async Task InitializeAsync(CancellationToken ct)
    {
        await ReloadAsync(force: true, ct).ConfigureAwait(false);
        bool generate = _snapshot.Entries.Count == 0;
        // A name is unique among certificates, so a replacement gets its own name (CertificateMaterial.CreateSelfSigned adds the thumbprint).
        bool stale = UsingSelfSignedOnly && ((_replaceOnHostnameChange && !_snapshot.Entries.Any(e => e.Subjects.Any(s => CertificateMaterial.Matches(s, _hostname))))
            || _snapshot.Entries.All(e => e.Leaf.NotAfter.ToUniversalTime() < _clock.UtcNow.UtcDateTime + SelfSignedRenewalMargin));
        if (!generate && stale)
        {
            foreach (CertificateRecord old in (await _config.GetCertificatesAsync(ct).ConfigureAwait(false)).Where(c => c.Active && c.Source == "selfsigned"))
            {
                await _config.UpsertCertificateAsync(old with { Active = false }, ct).ConfigureAwait(false);
            }

            generate = true;
        }

        if (generate)
        {
            var record = CertificateMaterial.CreateSelfSigned(_hostname, _protector, _clock.UtcNow);
            await _config.UpsertCertificateAsync(record, ct).ConfigureAwait(false);
            await ReloadAsync(force: true, ct).ConfigureAwait(false);
        }

        if (UsingSelfSignedOnly)
        {
            _log.Write(MtaLogLevel.Warning, "tls",
                $"Serving a SELF-SIGNED certificate for {_hostname}: mail servers and browsers will not trust it, so STARTTLS and the dashboard work but show warnings. " +
                "For a trusted certificate set EGGMAIL_HOSTNAME and EGGMAIL_ACME_EMAIL (free, automatic), or upload one in the dashboard.");
        }
    }

    /// <summary>Polls for changes until cancelled.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(_tls.PollInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                try
                {
                    await ReloadAsync(force: false, ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log.Write(MtaLogLevel.Warning, "tls", "certificate reload failed; keeping the certificates already loaded", ex);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>Reloads from the store (when its version changed or <paramref name="force"/>) and from the override files.</summary>
    public async Task ReloadAsync(bool force, CancellationToken ct)
    {
        bool overrideChanged = CheckOverrideChanged();
        long version = await _config.GetCertificateVersionAsync(ct).ConfigureAwait(false);
        if (!force && !overrideChanged && version == _lastVersion)
        {
            return;
        }

        var entries = new List<Entry>();
        var records = await _config.GetCertificatesAsync(ct).ConfigureAwait(false);
        foreach (var record in records.Where(r => r.Active))
        {
            try
            {
                var (leaf, intermediates) = CertificateMaterial.Load(record, _protector);
                var now = _clock.UtcNow;
                if (leaf.NotAfter.ToUniversalTime() < now.UtcDateTime)
                {
                    _log.Write(MtaLogLevel.Warning, "tls", $"certificate '{record.Name}' expired {leaf.NotAfter:u}; not serving it");
                    leaf.Dispose();
                    continue;
                }

                var context = SslStreamCertificateContext.Create(leaf, intermediates, offline: true);
                entries.Add(new Entry(record.Name, record.Source, record.Subjects, leaf, context));
            }
            catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or FormatException or ArgumentException)
            {
                // A damaged or mismatched replacement (the row of a renewed certificate is replaced in place) must not take the working certificate of the same name out of
                // service: keep serving what was loaded before, if anything.
                var served = _snapshot.Entries.FirstOrDefault(e => e.Name == record.Name && e.Source != "file");
                if (served is not null)
                {
                    entries.Add(served);
                }

                _log.Write(MtaLogLevel.Error, "tls", $"certificate '{record.Name}' is unusable and was skipped" + (served is null ? "" : "; the certificate of that name loaded before stays in use"), ex);
            }
        }

        if (!string.IsNullOrEmpty(_tls.CertificatePath))
        {
            try
            {
                string? pw = _tls.PfxPasswordFile is null ? null : File.ReadAllText(_tls.PfxPasswordFile).Trim();
                var (leaf, intermediates) = CertificateMaterial.LoadFiles(_tls.CertificatePath, _tls.KeyPath, pw);
                var context = SslStreamCertificateContext.Create(leaf, intermediates, offline: true);
                // The override comes first so it wins over database certificates for the same names.
                entries.Insert(0, new Entry("override", "file", CertificateMaterial.SubjectsOf(leaf), leaf, context));
            }
            catch (Exception ex) when (ex is IOException or System.Security.Cryptography.CryptographicException or UnauthorizedAccessException)
            {
                _log.Write(MtaLogLevel.Error, "tls", "certificate override files could not be loaded; keeping the previous certificates", ex);
                if (_snapshot.Entries.Any(e => e.Source == "file"))
                {
                    entries.Insert(0, _snapshot.Entries.First(e => e.Source == "file"));
                }
            }
        }

        // A first-run self-signed certificate is a placeholder: whatever else is served for the same name wins over it, whatever the certificates are called.
        entries = entries.OrderBy(e => e.Source == "selfsigned" ? 1 : 0).ToList();

        if (entries.Count == 0 && _snapshot.Entries.Count > 0)
        {
            _log.Write(MtaLogLevel.Warning, "tls", "reload produced no usable certificate; keeping the previous set");
            _lastVersion = version;
            return;
        }

        _snapshot = new Snapshot(entries);
        _lastVersion = version;
    }

    private bool CheckOverrideChanged()
    {
        if (string.IsNullOrEmpty(_tls.CertificatePath))
        {
            return false;
        }

        try
        {
            var fi = new FileInfo(_tls.CertificatePath);
            var ki = _tls.KeyPath is null ? null : new FileInfo(_tls.KeyPath);
            string fingerprint = $"{fi.Length}:{fi.LastWriteTimeUtc.Ticks}:{ki?.Length}:{ki?.LastWriteTimeUtc.Ticks}";
            bool changed = fingerprint != _overrideFingerprint;
            _overrideFingerprint = fingerprint;
            return changed;
        }
        catch (IOException)
        {
            return false;
        }
    }

    public X509Certificate2? GetCertificate(string? serverName) => Select(serverName)?.Leaf;

    public SslStreamCertificateContext? GetContext(string? serverName) => Select(serverName)?.Context;

    private Entry? Select(string? serverName)
    {
        var entries = _snapshot.Entries;
        if (entries.Count == 0)
        {
            return null;
        }

        if (!string.IsNullOrEmpty(serverName))
        {
            Entry? wildcard = null;
            foreach (var e in entries)
            {
                foreach (string subject in e.Subjects)
                {
                    if (string.Equals(subject, serverName, StringComparison.OrdinalIgnoreCase))
                    {
                        return e;
                    }

                    if (wildcard is null && CertificateMaterial.Matches(subject, serverName))
                    {
                        wildcard = e;
                    }
                }
            }

            if (wildcard is not null)
            {
                return wildcard;
            }
        }

        // No SNI or no match: prefer a certificate for our own host name, else the first (override or newest).
        foreach (var e in entries)
        {
            if (e.Subjects.Any(s => CertificateMaterial.Matches(s, _hostname)))
            {
                return e;
            }
        }

        return entries[0];
    }

    private sealed record Entry(string Name, string Source, IReadOnlyList<string> Subjects, X509Certificate2 Leaf, SslStreamCertificateContext Context);

    private sealed class Snapshot(IReadOnlyList<Entry> entries)
    {
        public static readonly Snapshot Empty = new([]);
        public IReadOnlyList<Entry> Entries { get; } = entries;
    }
}

public sealed record CertificateInfo(string Name, IReadOnlyList<string> Subjects, DateTime NotBefore, DateTime NotAfter, string Source, string Thumbprint);
