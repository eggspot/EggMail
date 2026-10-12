namespace Mta.Host.Tls;

/// <summary>Creates the DNS-01 challenge records. Providers must support several TXT values at one name (wildcard plus base domain orders).</summary>
public interface IDnsChallengeProvider
{
    /// <summary>Creates a TXT record and returns a handle for <see cref="DeleteTxtAsync"/>.</summary>
    ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken);

    ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken);
}

public sealed record AcmeOrderRequest(
    string DirectoryUrl,
    string Email,
    IReadOnlyList<string> Domains,
    string? AccountKeyPem,
    TimeSpan PropagationDelay);

/// <summary>An issued certificate: leaf-first PEM chain and a PKCS#8 DER private key, plus the account that ordered it.</summary>
public sealed record AcmeIssuedCertificate(string ChainPem, byte[] PrivateKeyPkcs8, string AccountKeyPem, string? AccountUrl, DateTimeOffset NotAfter);

/// <summary>Runs one ACME order end to end. The production implementation uses Certes; tests substitute a fake.</summary>
public interface IAcmeOrderRunner
{
    Task<AcmeIssuedCertificate> IssueAsync(AcmeOrderRequest request, IDnsChallengeProvider dns, CancellationToken cancellationToken);
}

public sealed class AcmeException : Exception
{
    public AcmeException(string message, Exception? inner = null) : base(message, inner) { }
}
