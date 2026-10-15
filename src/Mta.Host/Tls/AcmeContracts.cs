namespace Mta.Host.Tls;

/// <summary>Creates the DNS-01 challenge records. Providers must support several TXT values at one name (wildcard plus base domain orders).</summary>
public interface IDnsChallengeProvider
{
    /// <summary>Creates a TXT record and returns a handle for <see cref="DeleteTxtAsync"/>.</summary>
    ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken);

    ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken);
}

/// <summary>The DNS provider of a server that has no DNS credentials (HTTP-01 only): asking it for a record explains why there is none.</summary>
public sealed class NoDnsChallengeProvider : IDnsChallengeProvider
{
    public static readonly NoDnsChallengeProvider Instance = new();

    public ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken) =>
        throw new AcmeException("DNS-01 needs a DNS provider: set Acme:CloudflareApiToken (or Acme:CloudflareApiTokenFile), or use HTTP-01 (Acme:Challenge=Http01).");

    public ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken) => ValueTask.CompletedTask;
}

/// <summary>
/// Publishes the HTTP-01 answers (<c>/.well-known/acme-challenge/&lt;token&gt;</c> returns the key authorization) where the listener of every replica
/// can find them. Implemented by <see cref="Http01Challenges"/>: in memory and in the config store, so whichever replica the CA reaches can answer.
/// </summary>
public interface IHttpChallengePublisher
{
    /// <summary>
    /// Waits (at most <paramref name="timeout"/>) until the built-in listener has tried to bind its port. Null when tokens can be answered, otherwise why not
    /// (the port is taken, or not allowed): an order must not ask the CA to connect to a closed port, which counts as a failed validation there.
    /// </summary>
    ValueTask<string?> WaitUntilReadyAsync(TimeSpan timeout, CancellationToken cancellationToken);

    /// <summary>Makes <paramref name="keyAuthorization"/> the answer for <paramref name="token"/> until it is removed.</summary>
    ValueTask PublishAsync(string certificateName, string token, string keyAuthorization, CancellationToken cancellationToken);

    /// <summary>Stops answering <paramref name="token"/>.</summary>
    ValueTask RemoveAsync(string certificateName, string token, CancellationToken cancellationToken);
}

/// <summary>The challenge type one order proves its names with.</summary>
public enum AcmeChallengeType : byte
{
    Dns01 = 0,
    Http01,
}

/// <summary>
/// One order. <paramref name="Challenge"/> says whether the names are proven through <c>dns</c> (DNS-01) or <paramref name="Http"/> (HTTP-01);
/// <paramref name="EabKeyId"/> and <paramref name="EabHmacKey"/> (base64url) bind a newly registered account to an account at the CA (RFC 8555 section 7.3.4).
/// <paramref name="AccountKeyPem"/> is the stored account key, or null for the first order against a directory: the runner then
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
    string? ReplacesCertificatePem = null,
    AcmeChallengeType Challenge = AcmeChallengeType.Dns01,
    IHttpChallengePublisher? Http = null,
    string CertificateName = "default",
    string? EabKeyId = null,
    string? EabHmacKey = null)
{
    /// <summary>The members worth printing; never the account key or the EAB HMAC key (a record prints all its members otherwise, into any log that formats a request).</summary>
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("DirectoryUrl = ").Append(DirectoryUrl)
            .Append(", Domains = [").Append(string.Join(", ", Domains)).Append(']')
            .Append(", Challenge = ").Append(Challenge)
            .Append(", CertificateName = ").Append(CertificateName)
            .Append(", AccountKnown = ").Append(AccountKeyPem is not null)
            .Append(", Eab = ").Append(EabKeyId is not null);
        return true;
    }
}

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

/// <summary>The built-in HTTP-01 listener cannot bind its port, so no order was started. Retried soon (the CA was never asked, so there is nothing to protect).</summary>
public sealed class AcmeListenerUnavailableException(string message) : Exception(message);

public sealed class AcmeException : Exception
{
    public AcmeException(string message, Exception? inner = null, bool transient = false) : base(message, inner) => Transient = transient;

    /// <summary>
    /// A server error or a network failure (the CA may recover on its own), as opposed to the CA answering with a refusal. Asking for renewal advice backs
    /// off exponentially after the first kind and waits six hours after the second (RFC 9773 section 4.3.3).
    /// </summary>
    public bool Transient { get; }
}
