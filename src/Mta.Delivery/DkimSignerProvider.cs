using System.Collections.Concurrent;
using Mta.Core;
using Mta.Dkim;
using Mta.Storage;
using StoredDkimKey = Mta.Storage.DkimKeyRecord;

namespace Mta.Delivery;

/// <summary>Supplies the DKIM signer for a sending domain; null when the domain has no active key (the message goes out unsigned).</summary>
public interface IDkimSignerProvider
{
    ValueTask<DkimSigner?> GetSignerAsync(string sendingDomain, CancellationToken cancellationToken);
}

public sealed class DkimKeyUnavailableException(string domain, Guid? keyId, bool cached, Exception innerException)
    : Exception($"DKIM key {(keyId is { } id ? id.ToString("N") + " " : string.Empty)}of {domain} cannot be read: {innerException.GetType().Name}: {innerException.Message}", innerException)
{
    public string Domain { get; } = domain;

    public Guid? KeyId { get; } = keyId;

    public bool Cached { get; } = cached;
}

/// <summary>A provider that never signs.</summary>
public sealed class NoDkimSignerProvider : IDkimSignerProvider
{
    public static readonly NoDkimSignerProvider Instance = new();

    public ValueTask<DkimSigner?> GetSignerAsync(string sendingDomain, CancellationToken cancellationToken) => ValueTask.FromResult<DkimSigner?>(null);
}

/// <summary>
/// Looks the signing key up in the configuration store: the sending domain's own record or the nearest registered parent domain,
/// and its newest active key. Private keys are stored as PKCS#8 DER protected with <see cref="SecretPurposes.DkimKey"/>.
/// Results (including "no key") are cached for <see cref="DeliveryOptions.DkimCacheTtl"/>, so a rotation takes effect within that time.
/// </summary>
public sealed class ConfigDkimSignerProvider : IDkimSignerProvider, IDisposable
{
    private sealed record Entry(DkimSigner? Signer, long ExpiresAtTimestamp, DkimKeyUnavailableException? Failure = null);

    private readonly IConfigStore _config;
    private readonly ISecretProtector _protector;
    private readonly IClock _clock;
    private readonly TimeSpan _ttl;
    private readonly ConcurrentDictionary<string, Entry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<Guid, DkimSigner> _signers = new();

    public ConfigDkimSignerProvider(IConfigStore config, ISecretProtector protector, IClock clock, TimeSpan? cacheTtl = null)
    {
        _config = config;
        _protector = protector;
        _clock = clock;
        _ttl = cacheTtl ?? TimeSpan.FromMinutes(1);
    }

    public async ValueTask<DkimSigner?> GetSignerAsync(string sendingDomain, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(sendingDomain))
        {
            return null;
        }

        string name = sendingDomain.Trim().TrimEnd('.').ToLowerInvariant();
        long now = _clock.Timestamp;
        if (_cache.TryGetValue(name, out var cached) && now < cached.ExpiresAtTimestamp)
        {
            return cached.Failure is { } failure
                ? throw new DkimKeyUnavailableException(failure.Domain, failure.KeyId, cached: true, failure.InnerException!)
                : cached.Signer;
        }

        long expiresAt = now + (long)(_ttl.TotalSeconds * System.Diagnostics.Stopwatch.Frequency);
        DkimSigner? signer;
        try
        {
            signer = await LoadAsync(name, cancellationToken).ConfigureAwait(false);
        }
        catch (DkimKeyUnavailableException ex)
        {
            _cache[name] = new Entry(null, expiresAt, ex);
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var failure = new DkimKeyUnavailableException(name, null, cached: false, ex);
            _cache[name] = new Entry(null, expiresAt, failure);
            throw failure;
        }

        _cache[name] = new Entry(signer, expiresAt);
        return signer;
    }

    private async ValueTask<DkimSigner?> LoadAsync(string name, CancellationToken ct)
    {
        string candidate = name;
        while (true)
        {
            var domain = await _config.FindDomainByNameAsync(candidate, ct).ConfigureAwait(false);
            if (domain is not null)
            {
                var keys = await _config.GetDkimKeysAsync(domain.Id, ct).ConfigureAwait(false);
                var key = keys.Where(k => k.Active && k.RetiredAt is null).OrderByDescending(k => k.CreatedAt).FirstOrDefault();
                return key is null ? null : _signers.GetOrAdd(key.Id, _ => CreateSigner(domain.Name, key));
            }

            int dot = candidate.IndexOf('.');
            if (dot < 0 || candidate.IndexOf('.', dot + 1) < 0)
            {
                return null;
            }

            candidate = candidate[(dot + 1)..];
        }
    }

    private DkimSigner CreateSigner(string domain, StoredDkimKey key)
    {
        byte[]? der = null;
        try
        {
            der = _protector.Unprotect(key.PrivateKeyProtected, SecretPurposes.DkimKey);
            return DkimSigner.FromDer(new DkimSignerOptions { Domain = domain, Selector = key.Selector, Clock = _clock }, der);
        }
        catch (Exception ex)
        {
            throw new DkimKeyUnavailableException(domain, key.Id, cached: false, ex);
        }
        finally
        {
            if (der is not null)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(der);
            }
        }
    }

    public void Dispose()
    {
        foreach (var signer in _signers.Values)
        {
            signer.Dispose();
        }

        _signers.Clear();
        _cache.Clear();
    }
}
