using System.Security.Cryptography;
using Mta.Dkim;
using Mta.Dns;

namespace Mta.Auth.Arc;

/// <summary>The outcome of fetching one DKIM key record: either an RSA public key or a failure.</summary>
internal sealed class ArcKeyLookup
{
    private ArcKeyLookup(RSA? rsa, ArcFailure failure, string reason)
    {
        Rsa = rsa;
        Failure = failure;
        Reason = reason;
    }

    public RSA? Rsa { get; }

    public ArcFailure Failure { get; }

    public string Reason { get; }

    public static ArcKeyLookup Success(RSA rsa) => new(rsa, ArcFailure.None, string.Empty);

    public static ArcKeyLookup Failed(ArcFailure failure, string reason) => new(null, failure, reason);
}

/// <summary>
/// Fetches and caches the DKIM key records (<c>selector._domainkey.domain</c> TXT) named by the ARC headers of one message, bounded by
/// <see cref="ArcValidatorOptions.MaxKeyLookups"/>. Owns the RSA keys: dispose it.
/// </summary>
internal sealed class ArcKeyCache : IDisposable
{
    private readonly IDnsResolver _dns;
    private readonly ArcValidatorOptions _options;
    private readonly Dictionary<string, ArcKeyLookup> _cache = new(StringComparer.OrdinalIgnoreCase);

    public ArcKeyCache(IDnsResolver dns, ArcValidatorOptions options)
    {
        _dns = dns;
        _options = options;
    }

    public async ValueTask<ArcKeyLookup> GetAsync(string domain, string selector, CancellationToken cancellationToken)
    {
        string name = selector + "._domainkey." + domain;
        if (_cache.TryGetValue(name, out var cached)) { return cached; }
        if (_cache.Count >= _options.MaxKeyLookups)
        {
            return ArcKeyLookup.Failed(ArcFailure.TooManyKeyLookups, "more than " + _options.MaxKeyLookups + " distinct key lookups");
        }

        var result = await LookupAsync(name, cancellationToken).ConfigureAwait(false);
        _cache[name] = result;
        return result;
    }

    private async ValueTask<ArcKeyLookup> LookupAsync(string name, CancellationToken ct)
    {
        DnsResponse response;
        try
        {
            response = await _dns.QueryAsync(name, DnsRecordType.TXT, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return ArcKeyLookup.Failed(ArcFailure.KeyDnsError, "DNS lookup of a key failed");
        }

        if (response.Rcode == DnsRcode.NameError) { return ArcKeyLookup.Failed(ArcFailure.KeyNotFound, "no key record found (NXDOMAIN)"); }
        if (response.Rcode != DnsRcode.NoError) { return ArcKeyLookup.Failed(ArcFailure.KeyDnsError, "DNS lookup of a key failed (" + response.Rcode + ")"); }

        DkimKeyRecord? record = null;
        bool sawTxt = false;
        foreach (var answer in response.Answers)
        {
            if (answer is not TxtRecord txt) { continue; }
            sawTxt = true;
            if (DkimKeyRecord.TryParse(txt.Text, out var parsed, out _))
            {
                record = parsed;
                break;
            }
        }

        if (record is null)
        {
            return sawTxt
                ? ArcKeyLookup.Failed(ArcFailure.MalformedKeyRecord, "malformed key record")
                : ArcKeyLookup.Failed(ArcFailure.KeyNotFound, "no key record found");
        }

        if (record.IsRevoked) { return ArcKeyLookup.Failed(ArcFailure.KeyRevoked, "key revoked"); }
        if (record.KeyType != "rsa") { return ArcKeyLookup.Failed(ArcFailure.KeyTypeMismatch, "key type " + record.KeyType + " does not match rsa-sha256"); }
        if (!record.AllowsSha256 || !record.AllowsEmail) { return ArcKeyLookup.Failed(ArcFailure.KeyTypeMismatch, "key record does not permit sha256 for email"); }

        RSA? rsa = null;
        try
        {
            rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(record.PublicKeySubjectPublicKeyInfo, out _);
            int bits = rsa.KeySize;
            if (bits < _options.MinimumKeyBits)
            {
                rsa.Dispose();
                return ArcKeyLookup.Failed(ArcFailure.KeyTooSmall, "key too small (" + bits + " bits, minimum " + _options.MinimumKeyBits + ")");
            }

            if (bits > _options.MaximumKeyBits)
            {
                rsa.Dispose();
                return ArcKeyLookup.Failed(ArcFailure.KeyTooLarge, "key too large (" + bits + " bits, maximum " + _options.MaximumKeyBits + ")");
            }

            return ArcKeyLookup.Success(rsa);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            rsa?.Dispose();
            return ArcKeyLookup.Failed(ArcFailure.MalformedKeyRecord, "invalid public key in key record");
        }
    }

    public void Dispose()
    {
        foreach (var lookup in _cache.Values) { lookup.Rsa?.Dispose(); }
        _cache.Clear();
    }
}
