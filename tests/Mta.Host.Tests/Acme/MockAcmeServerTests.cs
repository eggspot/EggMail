using System.Security.Cryptography.X509Certificates;
using Mta.Host.Tls;

namespace Mta.Host.Tests.Acme;

/// <summary>
/// The mock CA is only worth its verdicts if it is strict: these tests pin that a correct client passes through it unchanged and that it really checks what a
/// CA checks (the key authorization, the CSR's names, nonces, signatures, external account binding), so the error-path tests do not pass for the wrong reason.
/// </summary>
public class MockAcmeServerTests
{
    [Fact]
    public async Task A_dns_order_goes_through_the_mock_and_the_chain_verifies_against_its_root()
    {
        using var rig = new AcmeRig();

        var issued = await rig.IssueAsync(names: ["mock.test", "*.mock.test"]);

        var chain = new X509Certificate2Collection();
        chain.ImportFromPem(issued.ChainPem);
        Assert.Equal(2, chain.Count);
        using var verifier = new X509Chain();
        verifier.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        verifier.ChainPolicy.CustomTrustStore.Add(rig.Ca.Root);
        verifier.ChainPolicy.ExtraStore.Add(chain[1]);
        verifier.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        Assert.True(verifier.Build(chain[0]), string.Join("; ", verifier.ChainStatus.Select(s => s.StatusInformation)));
        Assert.Equal(["*.mock.test", "mock.test"], CertificateMaterial.SubjectsOf(chain[0]).Order(StringComparer.Ordinal));
        // Two authorizations (base name, wildcard of the same base name), two values at one TXT name, all removed again.
        Assert.Equal(["_acme-challenge.mock.test", "_acme-challenge.mock.test"], rig.Dns.Created.Select(r => r.Name));
        Assert.Equal(0, rig.Dns.LiveRecords);
    }

    [Fact]
    public async Task The_mock_validates_the_key_authorization_for_real_so_a_wrong_value_is_a_failed_authorization()
    {
        using var rig = new AcmeRig();
        rig.Ca.Validator = MockChallengeValidators.Dns(rig.Dns);
        // A record with a made-up value instead of the digest of the key authorization.
        var wrongDns = new WrongValueDns(rig.Dns);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => rig.Runner.IssueAsync(rig.Order(), wrongDns, default));

        Assert.Contains("Authorization for mx.mock.test ended as Invalid", ex.Message);
        Assert.Contains("Incorrect TXT record", ex.Message);
    }

    [Fact]
    public async Task An_http_order_publishes_the_key_authorization_of_its_account_and_the_mock_checks_it()
    {
        using var rig = new AcmeRig();

        var issued = await rig.IssueAsync(AcmeChallengeType.Http01);

        var published = Assert.Single(rig.Http.Published);
        Assert.EndsWith("." + rig.Ca.AccountThumbprint, published.KeyAuthorization);
        Assert.StartsWith(published.Token + ".", published.KeyAuthorization);
        Assert.Equal([published.Token], rig.Http.Removed);
        Assert.Equal(0, rig.Http.LiveAnswers);
        Assert.NotNull(issued.ChainPem);
    }

    [Fact]
    public async Task A_stored_account_key_is_used_without_registering_again()
    {
        using var rig = new AcmeRig();
        await rig.IssueAsync();
        Assert.Equal(1, rig.Ca.AccountCount);

        await rig.IssueAsync(); // AcmeRig remembers the account key of the first order

        Assert.Equal(1, rig.Ca.AccountCount);
        Assert.Equal(1, rig.Ca.Count("newAccount", 201));
    }

    [Fact]
    public async Task Every_nonce_is_used_once_and_the_runner_never_reuses_one()
    {
        using var rig = new AcmeRig();

        await rig.IssueAsync();

        Assert.DoesNotContain(rig.Ca.Requests, r => r.Status == 400); // a replayed nonce would have been a badNonce
    }

    [Fact]
    public async Task External_account_binding_is_verified_by_the_mock()
    {
        using var rig = new AcmeRig();
        rig.Ca.ExternalAccountRequired = true;
        rig.Ca.EabKeys["kid-1"] = Base64Url(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 });

        var none = await Assert.ThrowsAsync<AcmeException>(() => rig.Runner.IssueAsync(rig.Order(), rig.Dns, default));
        Assert.Contains("external account binding", none.Message);
        var wrongKey = await Assert.ThrowsAsync<AcmeException>(() => rig.Runner.IssueAsync(rig.Order(eabKeyId: "kid-1", eabHmacKey: Base64Url(new byte[16])), rig.Dns, default));
        Assert.Contains("MAC does not verify", wrongKey.Message);
        var unknown = await Assert.ThrowsAsync<AcmeException>(() => rig.Runner.IssueAsync(rig.Order(eabKeyId: "kid-9", eabHmacKey: rig.Ca.EabKeys["kid-1"]), rig.Dns, default));
        Assert.Contains("kid-9", unknown.Message);
        Assert.Equal(0, rig.Ca.AccountCount);

        var issued = await rig.Runner.IssueAsync(rig.Order(eabKeyId: "kid-1", eabHmacKey: rig.Ca.EabKeys["kid-1"]), rig.Dns, default);

        Assert.NotNull(issued);
        Assert.Equal(1, rig.Ca.AccountCount);
    }

    private static string Base64Url(byte[] bytes) => System.Buffers.Text.Base64Url.EncodeToString(bytes);

    /// <summary>Publishes a value that is not the digest of the key authorization.</summary>
    private sealed class WrongValueDns(RecordingDnsProvider inner) : IDnsChallengeProvider
    {
        public ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken) => inner.CreateTxtAsync(fqdn, "not-the-digest", cancellationToken);

        public ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken) => inner.DeleteTxtAsync(handle, cancellationToken);
    }
}
