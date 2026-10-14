using System.Security.Cryptography;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;

namespace Mta.Host.Tls;

/// <summary>
/// ACME order through Certes with DNS-01 (the only challenge type the design supports, decision 19). Exercised end to end against the
/// Pebble test CA (<c>tests/Mta.Integration.Tests/Acme</c>, CI only); not yet against a production CA.
/// </summary>
public sealed class CertesOrderRunner : IAcmeOrderRunner
{
    /// <summary>Authorizations are polled with a growing pause (a quick CA answers in well under a second) for about two minutes.</summary>
    private const int MaxAuthorizationPolls = 45;

    /// <summary>An order is repeated this many times in total when the CA keeps rejecting the anti-replay nonce.</summary>
    private const int MaxBadNonceAttempts = 4;

    private readonly HttpMessageHandler? _handler;

    /// <param name="handler">
    /// Transport for all requests to the CA (never disposed here). The default is a plain <see cref="HttpClient"/> with the system trust store;
    /// tests pass a handler that trusts a private test CA, and egress-controlled deployments can pass a proxying one.
    /// </param>
    public CertesOrderRunner(HttpMessageHandler? handler = null) => _handler = handler;

    public async Task<AcmeIssuedCertificate> IssueAsync(AcmeOrderRequest request, IDnsChallengeProvider dns, CancellationToken ct)
    {
        try
        {
            var account = new AccountState { KeyPem = request.AccountKeyPem };
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    return await IssueOnceAsync(request, account, dns, ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (attempt < MaxBadNonceAttempts && IsBadNonce(ex) && !ct.IsCancellationRequested)
                {
                    // The CA does not know the anti-replay nonce we used (they expire, and are per CA front end). The protocol says to
                    // start over with a fresh one; Certes only does that for some of its requests, so the whole order is repeated. An
                    // account registered by an earlier attempt is kept in <see cref="AccountState"/> and reused.
                }
            }
        }
        catch (AcmeRequestException ex)
        {
            throw new AcmeException($"ACME server error: {ex.Error?.Detail ?? ex.Message}", ex);
        }
        catch (Certes.AcmeException ex)
        {
            throw new AcmeException($"ACME error: {ex.Message}", ex);
        }
        catch (OperationCanceledException ex) when (!ct.IsCancellationRequested)
        {
            // HttpClient reports its own timeout as a cancellation; that is a failed attempt to back off from, not a shutdown.
            throw new AcmeException("The ACME server did not answer in time.", ex);
        }
        catch (AggregateException ex) when (!ct.IsCancellationRequested)
        {
            // Certes fetches the directory synchronously, so transport failures arrive wrapped; say what actually went wrong.
            var inner = ex.Flatten().InnerExceptions[0];
            throw new AcmeException(inner is OperationCanceledException
                ? "The ACME server did not answer in time."
                : $"The ACME server could not be reached or answered unexpectedly: {inner.Message}", inner);
        }
    }

    private async Task<AcmeIssuedCertificate> IssueOnceAsync(AcmeOrderRequest request, AccountState account, IDnsChallengeProvider dns, CancellationToken ct)
    {
        var directory = new Uri(request.DirectoryUrl);
        // Our own client in every case, so it is disposed with the order (Certes would otherwise leave one behind per order).
        using var http = _handler is null ? new HttpClient() : new HttpClient(_handler, disposeHandler: false);
        IAcmeHttpClient transport = new AcmeHttpClient(directory, http);

        AcmeContext acme;
        if (account.KeyPem is null)
        {
            acme = new AcmeContext(directory, null, transport, badNonceRetryCount: 3);
            var registration = acme.NewAccount([$"mailto:{request.Email}"], termsOfServiceAgreed: true);
            account.Url = (await registration.Location().ConfigureAwait(false)).ToString();
            account.KeyPem = acme.AccountKey.ToPem();
            if (request.AccountCreated is { } created)
            {
                await created(new AcmeAccountCreated(account.KeyPem, account.Url), ct).ConfigureAwait(false);
            }
        }
        else
        {
            acme = new AcmeContext(directory, KeyFactory.FromPem(account.KeyPem), transport, badNonceRetryCount: 3);
        }

        return await OrderAsync(acme, request, dns, account.Url, ct).ConfigureAwait(false);
    }

    /// <summary>The account in use across the attempts of one <see cref="IssueAsync"/>: the stored one, or the one registered by its first attempt.</summary>
    private sealed class AccountState
    {
        public string? KeyPem { get; set; }

        public string? Url { get; set; }
    }

    private static bool IsBadNonce(Exception exception)
    {
        for (var e = exception; e is not null; e = e.InnerException)
        {
            if (e is AcmeRequestException { Error.Type: { } type } && type.EndsWith(":badNonce", StringComparison.Ordinal))
            {
                return true;
            }

            if (e is AggregateException aggregate && aggregate.InnerExceptions.Any(IsBadNonce))
            {
                return true;
            }

            if (e.Message.Contains(":badNonce", StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static async Task<AcmeIssuedCertificate> OrderAsync(AcmeContext acme, AcmeOrderRequest request, IDnsChallengeProvider dns, string? accountUrl, CancellationToken ct)
    {
        var order = await acme.NewOrder(request.Domains.ToList()).ConfigureAwait(false);
        var authorizations = await order.Authorizations().ConfigureAwait(false);
        var handles = new List<string>();
        var challenges = new List<(IAuthorizationContext Authz, IChallengeContext Challenge)>();
        try
        {
            foreach (var authz in authorizations)
            {
                var resource = await authz.Resource().ConfigureAwait(false);
                // The CA may hand back an authorization that is already valid (RFC 8555 section 7.4.1: servers may reuse valid authorizations
                // of the account for the same identifier; Let's Encrypt does, and Pebble does at random). There is nothing left to prove and the
                // challenge can no longer be answered: posting to it is refused ("Cannot update challenge with status valid, only status
                // pending"). Any state other than pending or valid fails the order.
                if (resource.Status == AuthorizationStatus.Valid)
                {
                    continue;
                }

                if (resource.Status != AuthorizationStatus.Pending)
                {
                    throw new AcmeException($"Authorization for {resource.Identifier.Value} is {resource.Status}, not pending");
                }

                var challenge = await authz.Dns().ConfigureAwait(false);
                // A wildcard authorization names the base domain (the "*." is a flag), so "*.example.com" and "example.com" share this name
                // with different values; providers must hold several TXT values at one name.
                string txt = acme.AccountKey.DnsTxt(challenge.Token);
                handles.Add(await dns.CreateTxtAsync($"_acme-challenge.{resource.Identifier.Value}", txt, ct).ConfigureAwait(false));
                challenges.Add((authz, challenge));
            }

            if (request.PropagationDelay > TimeSpan.Zero)
            {
                await Task.Delay(request.PropagationDelay, ct).ConfigureAwait(false);
            }

            foreach (var (_, challenge) in challenges)
            {
                // Only a pending challenge can be answered; one that is already processing or valid is just waited for.
                if ((await challenge.Resource().ConfigureAwait(false)).Status == ChallengeStatus.Pending)
                {
                    await challenge.Validate().ConfigureAwait(false);
                }
            }

            foreach (var (authz, challenge) in challenges)
            {
                await WaitUntilValidAsync(authz, challenge, ct).ConfigureAwait(false);
            }

            var certKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
            var chain = await order.Generate(new CsrInfo { CommonName = request.Domains[0] }, certKey).ConfigureAwait(false);
            using var ec = ECDsa.Create();
            ec.ImportFromPem(certKey.ToPem());
            var leaf = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(chain.Certificate.ToDer());
            return new AcmeIssuedCertificate(chain.ToPem(), ec.ExportPkcs8PrivateKey(), acme.AccountKey.ToPem(), accountUrl, leaf.NotAfter.ToUniversalTime());
        }
        finally
        {
            foreach (string handle in handles)
            {
                try
                {
                    await dns.DeleteTxtAsync(handle, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is AcmeException or HttpRequestException or TimeoutException)
                {
                    // A leftover TXT record is harmless; never let cleanup hide why the order itself failed.
                }
            }
        }
    }

    private static async Task WaitUntilValidAsync(IAuthorizationContext authz, IChallengeContext challenge, CancellationToken ct)
    {
        for (int attempt = 0; ; attempt++)
        {
            var res = await authz.Resource().ConfigureAwait(false);
            if (res.Status == AuthorizationStatus.Valid)
            {
                return;
            }

            if (res.Status is AuthorizationStatus.Invalid or AuthorizationStatus.Revoked or AuthorizationStatus.Expired or AuthorizationStatus.Deactivated)
            {
                string? detail = null;
                try
                {
                    detail = (await challenge.Resource().ConfigureAwait(false)).Error?.Detail;
                }
                catch (Exception ex) when (ex is Certes.AcmeException or HttpRequestException)
                {
                }

                throw new AcmeException($"Authorization for {res.Identifier.Value} ended as {res.Status}" + (detail is null ? "" : $": {detail}"));
            }

            if (attempt >= MaxAuthorizationPolls)
            {
                throw new AcmeException($"Authorization for {res.Identifier.Value} is still {res.Status} after {MaxAuthorizationPolls} checks");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(3000, 200 * Math.Pow(2, Math.Min(attempt, 4)))), ct).ConfigureAwait(false);
        }
    }
}
