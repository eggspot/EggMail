namespace Mta.Host.Tls;

/// <summary>Creates the DNS-01 challenge records. Providers must support several TXT values at one name (wildcard plus base domain orders).</summary>
public interface IDnsChallengeProvider
{
    /// <summary>Creates a TXT record and returns a handle for <see cref="DeleteTxtAsync"/>.</summary>
    ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken);

    ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken);
}

/// <summary>
/// One order. <paramref name="AccountKeyPem"/> is the stored account key, or null for the first order against a directory: the runner then
/// registers an account and reports it through <paramref name="AccountCreated"/> as soon as it exists, before the order can fail, so a failed
/// order never leaves an account at the CA whose key is lost (every retry would register another one, and CAs rate-limit registrations).
/// </summary>
public sealed record AcmeOrderRequest(
    string DirectoryUrl,
    string Email,
    IReadOnlyList<string> Domains,
    string? AccountKeyPem,
    TimeSpan PropagationDelay,
    Func<AcmeAccountCreated, CancellationToken, Task>? AccountCreated = null,
    string? ReplacesCertificatePem = null);

/// <summary>What the CA answered to a renewal information (ARI, RFC 9773) request: the window in which it wants the certificate renewed, and when to ask again.</summary>
public sealed record AcmeRenewalInfo(DateTimeOffset WindowStart, DateTimeOffset WindowEnd, TimeSpan? RetryAfter, string? ExplanationUrl);

/// <summary>A freshly registered ACME account: its private key (PEM) and its URL at the CA.</summary>
public sealed record AcmeAccountCreated(string AccountKeyPem, string? AccountUrl);

/// <summary>An issued certificate: leaf-first PEM chain and a PKCS#8 DER private key, plus the account that ordered it.</summary>
public sealed record AcmeIssuedCertificate(string ChainPem, byte[] PrivateKeyPkcs8, string AccountKeyPem, string? AccountUrl, DateTimeOffset NotAfter);

/// <summary>Runs one ACME order end to end. The production implementation uses Certes; tests substitute a fake.</summary>
public interface IAcmeOrderRunner
{
    Task<AcmeIssuedCertificate> IssueAsync(AcmeOrderRequest request, IDnsChallengeProvider dns, CancellationToken cancellationToken);

    /// <summary>
    /// Asks the CA when to renew the certificate (leaf-first PEM chain) issued by the directory. Null when the CA has no ARI; throws
    /// <see cref="AcmeException"/> when it has and the request failed. The default is "no ARI", which keeps the lifetime rule.
    /// </summary>
    Task<AcmeRenewalInfo?> GetRenewalInfoAsync(string directoryUrl, string certificateChainPem, CancellationToken cancellationToken) => Task.FromResult<AcmeRenewalInfo?>(null);
}

public sealed class AcmeException : Exception
{
    public AcmeException(string message, Exception? inner = null) : base(message, inner) { }
}
