using System.Security.Cryptography;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;

namespace Mta.Host.Tls;

/// <summary>
/// ACME order through Certes with DNS-01. Written against Certes 4.1.0's documented flow; it has not been exercised against
/// a real ACME server in this repository's tests (no network in tests), so treat it as unverified until a staging run.
/// </summary>
public sealed class CertesOrderRunner : IAcmeOrderRunner
{
    public async Task<AcmeIssuedCertificate> IssueAsync(AcmeOrderRequest request, IDnsChallengeProvider dns, CancellationToken ct)
    {
        try
        {
            AcmeContext acme;
            string? accountUrl = null;
            if (request.AccountKeyPem is null)
            {
                acme = new AcmeContext(new Uri(request.DirectoryUrl));
                var accountTask = acme.NewAccount([$"mailto:{request.Email}"], termsOfServiceAgreed: true);
                accountUrl = (await accountTask.Location().ConfigureAwait(false)).ToString();
            }
            else
            {
                acme = new AcmeContext(new Uri(request.DirectoryUrl), KeyFactory.FromPem(request.AccountKeyPem));
            }

            var order = await acme.NewOrder(request.Domains.ToList()).ConfigureAwait(false);
            var authorizations = await order.Authorizations().ConfigureAwait(false);
            var handles = new List<string>();
            var challenges = new List<(IAuthorizationContext Authz, Certes.Acme.IChallengeContext Challenge)>();
            try
            {
                foreach (var authz in authorizations)
                {
                    var challenge = await authz.Dns().ConfigureAwait(false);
                    var resource = await authz.Resource().ConfigureAwait(false);
                    string txt = acme.AccountKey.DnsTxt(challenge.Token);
                    handles.Add(await dns.CreateTxtAsync($"_acme-challenge.{resource.Identifier.Value}", txt, ct).ConfigureAwait(false));
                    challenges.Add((authz, challenge));
                }

                await Task.Delay(request.PropagationDelay, ct).ConfigureAwait(false);
                foreach (var (authz, challenge) in challenges)
                {
                    await challenge.Validate().ConfigureAwait(false);
                }

                foreach (var (authz, _) in challenges)
                {
                    for (int attempt = 0; ; attempt++)
                    {
                        var res = await authz.Resource().ConfigureAwait(false);
                        if (res.Status == AuthorizationStatus.Valid)
                        {
                            break;
                        }

                        if (res.Status is AuthorizationStatus.Invalid or AuthorizationStatus.Revoked or AuthorizationStatus.Expired or AuthorizationStatus.Deactivated || attempt >= 40)
                        {
                            throw new AcmeException($"Authorization for {res.Identifier.Value} ended as {res.Status}");
                        }

                        await Task.Delay(TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
                    }
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
                foreach (string h in handles)
                {
                    try { await dns.DeleteTxtAsync(h, CancellationToken.None).ConfigureAwait(false); } catch (AcmeException) { }
                }
            }
        }
        catch (AcmeRequestException ex)
        {
            throw new AcmeException($"ACME server error: {ex.Error?.Detail ?? ex.Message}", ex);
        }
    }
}
