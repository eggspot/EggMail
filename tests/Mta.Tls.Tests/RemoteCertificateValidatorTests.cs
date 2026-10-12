using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Mta.Dns;
using Mta.Tls.Dane;
using Mta.Tls.MtaSts;
using Mta.Tls.Tests.Support;

namespace Mta.Tls.Tests;

public class RemoteCertificateValidatorTests
{
    private const string Mx = "mx.example.com";

    private sealed class Pki
    {
        public IssuedCertificate Root { get; } = TestPki.CreateRoot();
        public IssuedCertificate Intermediate { get; }
        public IssuedCertificate Leaf { get; }

        public Pki(string[]? names = null, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
        {
            Intermediate = TestPki.CreateIntermediate(Root);
            Leaf = TestPki.CreateLeaf(Intermediate, names ?? [Mx], notBefore: notBefore, notAfter: notAfter);
        }

        public X509Certificate2[] Presented => [Leaf.Public, Intermediate.Public];

        public RemoteCertificateValidatorOptions Trusting => new() { CustomTrustAnchors = [Root.Public] };
    }

    private static TlsPolicyDecision Decision(TlsSecurityLevel level) =>
        OutboundTlsPolicyResolver.Decide("example.com", Mx, new OutboundTlsConfiguration { Level = level }, MtaStsLookupResult.NoPolicy(), DaneLookupResult.NotApplicable());

    private static TlsPolicyDecision PkixDecision(bool enforce) => Decision(TlsSecurityLevel.Verify) with { EnforceValidation = enforce };

    private static TlsPolicyDecision DaneDecision(params TlsaRecord[] records) =>
        Decision(TlsSecurityLevel.May) with
        {
            Kind = TlsPolicyKind.Dane,
            PolicyType = TlsPolicyType.Tlsa,
            Validation = TlsValidationMode.Dane,
            EnforceValidation = true,
            RequireTls = true,
            TlsaRecords = records,
        };

    // ---- PKIX ----

    [Fact]
    public void Pkix_accepts_a_valid_chain_for_the_mx_name()
    {
        var pki = new Pki();
        var validator = new RemoteCertificateValidator(PkixDecision(true), pki.Trusting);
        var outcome = validator.ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.None);

        Assert.True(outcome.Accepted, string.Join("; ", outcome.Notes));
        Assert.True(outcome.Verified);
        Assert.Null(outcome.Failure);
    }

    [Fact]
    public void Pkix_accepts_a_wildcard_san_but_only_for_one_label()
    {
        var pki = new Pki(["*.example.com"]);
        Assert.True(new RemoteCertificateValidator(PkixDecision(true), pki.Trusting).ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.None).Accepted);

        var deep = PkixDecision(true) with { ExpectedHostname = "a.b.example.com" };
        var outcome = new RemoteCertificateValidator(deep, pki.Trusting).ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.None);
        Assert.False(outcome.Accepted);
        Assert.Equal(TlsResultType.CertificateHostMismatch, outcome.Failure);
    }

    [Fact]
    public void Pkix_rejects_a_host_name_mismatch_when_enforcing()
    {
        var pki = new Pki(["other.example.org"]);
        var outcome = new RemoteCertificateValidator(PkixDecision(true), pki.Trusting).ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.None);

        Assert.False(outcome.Accepted);
        Assert.False(outcome.Verified);
        Assert.Equal(TlsResultType.CertificateHostMismatch, outcome.Failure);
    }

    [Fact]
    public void Pkix_in_testing_mode_tolerates_but_records_the_failure()
    {
        var pki = new Pki(["other.example.org"]);
        var validator = new RemoteCertificateValidator(PkixDecision(false), pki.Trusting);
        var outcome = validator.ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.RemoteCertificateNameMismatch);

        Assert.True(outcome.Accepted);
        Assert.False(outcome.Verified);
        Assert.Equal(TlsResultType.CertificateHostMismatch, outcome.Failure);
        Assert.Contains(outcome.Notes, n => n.Contains("tolerated"));

        var record = validator.CreateSessionRecord(SslProtocols.Tls13, "TLS_AES_256_GCM_SHA384");
        Assert.False(record.Verified);
        Assert.False(record.ValidationEnforced);
        Assert.Equal(TlsResultType.CertificateHostMismatch, record.Failure);
    }

    [Fact]
    public void Pkix_rejects_an_untrusted_root()
    {
        var pki = new Pki();
        var stranger = TestPki.CreateRoot("Some Other Root");
        var validator = new RemoteCertificateValidator(PkixDecision(true), new RemoteCertificateValidatorOptions { CustomTrustAnchors = [stranger.Public] });
        var outcome = validator.ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.RemoteCertificateChainErrors);

        Assert.False(outcome.Accepted);
        Assert.Equal(TlsResultType.CertificateNotTrusted, outcome.Failure);
    }

    [Fact]
    public void Pkix_rejects_a_self_signed_certificate_that_is_not_a_trust_anchor()
    {
        var self = TestPki.CreateSelfSignedLeaf([Mx]);
        var outcome = new RemoteCertificateValidator(PkixDecision(true), new RemoteCertificateValidatorOptions { CustomTrustAnchors = [TestPki.CreateRoot().Public] })
            .ValidateCertificates(self.Public, [self.Public], SslPolicyErrors.RemoteCertificateChainErrors);
        Assert.False(outcome.Accepted);
        Assert.Equal(TlsResultType.CertificateNotTrusted, outcome.Failure);
    }

    [Fact]
    public void Pkix_trusts_a_pinned_self_signed_certificate_as_custom_anchor()
    {
        var self = TestPki.CreateSelfSignedLeaf([Mx]);
        var outcome = new RemoteCertificateValidator(PkixDecision(true), new RemoteCertificateValidatorOptions { CustomTrustAnchors = [self.Public] })
            .ValidateCertificates(self.Public, [self.Public], SslPolicyErrors.None);
        Assert.True(outcome.Accepted, string.Join("; ", outcome.Notes));
    }

    [Fact]
    public void Pkix_does_not_use_the_system_store_for_generated_certificates()
    {
        var pki = new Pki();
        var outcome = new RemoteCertificateValidator(PkixDecision(true)).ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.RemoteCertificateChainErrors);
        Assert.False(outcome.Accepted);
        Assert.Equal(TlsResultType.CertificateNotTrusted, outcome.Failure);
    }

    [Fact]
    public void Pkix_rejects_an_expired_leaf()
    {
        var pki = new Pki(notBefore: DateTimeOffset.UtcNow.AddDays(-30), notAfter: DateTimeOffset.UtcNow.AddDays(-1));
        var outcome = new RemoteCertificateValidator(PkixDecision(true), pki.Trusting).ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.RemoteCertificateChainErrors);

        Assert.False(outcome.Accepted);
        Assert.Equal(TlsResultType.CertificateExpired, outcome.Failure);
    }

    [Fact]
    public void Pkix_uses_the_injected_clock()
    {
        var pki = new Pki(notBefore: DateTimeOffset.UtcNow.AddDays(-30), notAfter: DateTimeOffset.UtcNow.AddDays(-1));
        var options = new RemoteCertificateValidatorOptions { CustomTrustAnchors = [pki.Root.Public], Now = () => DateTimeOffset.UtcNow.AddDays(-10) };
        Assert.True(new RemoteCertificateValidator(PkixDecision(true), options).ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.None).Accepted);
    }

    [Fact]
    public void Pkix_requires_a_certificate()
    {
        var outcome = new RemoteCertificateValidator(PkixDecision(true)).ValidateCertificates(null, [], SslPolicyErrors.RemoteCertificateNotAvailable);
        Assert.False(outcome.Accepted);
        Assert.Equal(TlsResultType.ValidationFailure, outcome.Failure);
    }

    [Fact]
    public void Pkix_ignores_the_platform_name_mismatch_flag_and_decides_for_itself()
    {
        // SslStream.TargetHost may differ from the MX name; our own name check against the decision is authoritative.
        var pki = new Pki();
        var outcome = new RemoteCertificateValidator(PkixDecision(true), pki.Trusting).ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.RemoteCertificateNameMismatch);
        Assert.True(outcome.Accepted);
    }

    // ---- opportunistic ----

    [Theory]
    [InlineData(TlsSecurityLevel.May)]
    [InlineData(TlsSecurityLevel.Encrypt)]
    public void Without_validation_everything_is_accepted_and_the_errors_are_recorded(TlsSecurityLevel level)
    {
        var self = TestPki.CreateSelfSignedLeaf(["unrelated.example.net"]);
        var validator = new RemoteCertificateValidator(Decision(level));
        var errors = SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch;
        var outcome = validator.ValidateCertificates(self.Public, [self.Public], errors);

        Assert.True(outcome.Accepted);
        Assert.False(outcome.Verified);
        Assert.Null(outcome.Failure);
        Assert.Equal(errors, outcome.SslPolicyErrors);

        var record = validator.CreateSessionRecord(SslProtocols.Tls12, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        Assert.Equal(errors, record.SslPolicyErrors);
        Assert.False(record.Verified);
        Assert.Equal(TlsValidationMode.None, record.ValidationMode);
        Assert.Equal(level == TlsSecurityLevel.May ? TlsPolicyKind.Opportunistic : TlsPolicyKind.Encrypt, record.PolicyApplied);
    }

    [Fact]
    public void Without_validation_a_clean_platform_result_counts_as_verified()
    {
        var self = TestPki.CreateSelfSignedLeaf([Mx]);
        var outcome = new RemoteCertificateValidator(Decision(TlsSecurityLevel.May)).ValidateCertificates(self.Public, [self.Public], SslPolicyErrors.None);
        Assert.True(outcome.Verified);
    }

    [Fact]
    public void Without_validation_a_missing_certificate_is_accepted()
    {
        var outcome = new RemoteCertificateValidator(Decision(TlsSecurityLevel.May)).ValidateCertificates(null, [], SslPolicyErrors.RemoteCertificateNotAvailable);
        Assert.True(outcome.Accepted);
        Assert.False(outcome.Verified);
    }

    // ---- DANE ----

    [Fact]
    public void Dane_accepts_a_matching_ee_record_even_for_an_untrusted_self_signed_certificate()
    {
        var self = TestPki.CreateSelfSignedLeaf(["whatever.example.net"]);
        var validator = new RemoteCertificateValidator(DaneDecision(Tlsa.For(self.Public, 3, 1, 1)));
        var outcome = validator.ValidateCertificates(self.Public, [self.Public], SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch);

        Assert.True(outcome.Accepted);
        Assert.True(outcome.Verified);
        Assert.Equal(TlsPolicyKind.Dane, validator.CreateSessionRecord(SslProtocols.Tls13, null).PolicyApplied);
    }

    [Fact]
    public void Dane_always_rejects_a_mismatch_even_with_a_pkix_valid_certificate()
    {
        var pki = new Pki();
        var other = TestPki.CreateSelfSignedLeaf([Mx]);
        var validator = new RemoteCertificateValidator(DaneDecision(Tlsa.For(other.Public, 3, 1, 1)), pki.Trusting);
        var outcome = validator.ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.None);

        Assert.False(outcome.Accepted);
        Assert.Equal(TlsResultType.ValidationFailure, outcome.Failure);
    }

    [Fact]
    public void Dane_ta_uses_the_presented_chain_and_reference_names()
    {
        var pki = new Pki(["real.example.org"]);
        var decision = DaneDecision(Tlsa.For(pki.Root.Public, 2, 1, 1)) with { DaneReferenceNames = ["real.example.org"] };
        var outcome = new RemoteCertificateValidator(decision).ValidateCertificates(pki.Leaf.Public, [.. pki.Presented, pki.Root.Public], SslPolicyErrors.RemoteCertificateChainErrors);
        Assert.True(outcome.Accepted, string.Join("; ", outcome.Notes));
    }

    [Fact]
    public void Dane_without_a_certificate_is_rejected()
    {
        var outcome = new RemoteCertificateValidator(DaneDecision()).ValidateCertificates(null, [], SslPolicyErrors.RemoteCertificateNotAvailable);
        Assert.False(outcome.Accepted);
    }

    [Fact]
    public void Dane_with_no_usable_records_is_tlsa_invalid()
    {
        var pki = new Pki();
        var outcome = new RemoteCertificateValidator(DaneDecision()).ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.None);
        Assert.False(outcome.Accepted);
        Assert.Equal(TlsResultType.TlsaInvalid, outcome.Failure);
    }

    // ---- robustness and records ----

    [Fact]
    public void The_callback_never_throws_even_for_a_disposed_certificate()
    {
        var pki = new Pki();
        var cert = X509CertificateLoader.LoadCertificate(pki.Leaf.Public.RawData);
        cert.Dispose();
        var validator = new RemoteCertificateValidator(PkixDecision(true), pki.Trusting);

        bool accepted = validator.Callback(this, cert, null, SslPolicyErrors.None);

        Assert.False(accepted);
        Assert.Equal(TlsResultType.ValidationFailure, validator.Outcome!.Failure);
    }

    [Fact]
    public void The_callback_maps_a_plain_x509_chain_and_leaf()
    {
        var pki = new Pki();
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(pki.Root.Public);
        chain.ChainPolicy.ExtraStore.Add(pki.Intermediate.Public);
        Assert.True(chain.Build(pki.Leaf.Public));

        var validator = new RemoteCertificateValidator(PkixDecision(true), pki.Trusting);
        Assert.True(validator.Validate(this, pki.Leaf.Public, chain, SslPolicyErrors.None));
        Assert.True(validator.Outcome!.Verified);
    }

    [Fact]
    public void Session_record_carries_peer_certificate_facts()
    {
        var pki = new Pki();
        var validator = new RemoteCertificateValidator(PkixDecision(true), pki.Trusting);
        validator.ValidateCertificates(pki.Leaf.Public, pki.Presented, SslPolicyErrors.None);
        var record = validator.CreateSessionRecord(SslProtocols.Tls13, "TLS_AES_256_GCM_SHA384");

        Assert.Equal(Mx, record.MxHost);
        Assert.Equal("TLSv1.3", record.TlsVersion);
        Assert.Equal("TLS_AES_256_GCM_SHA384", record.CipherSuite);
        Assert.True(record.Verified);
        Assert.Equal(TlsPolicyKind.Verify, record.PolicyApplied);
        Assert.Equal(TlsValidationMode.Pkix, record.ValidationMode);
        Assert.True(record.ValidationEnforced);
        Assert.Null(record.Failure);
        var peer = record.PeerCertificate!;
        Assert.Equal(pki.Leaf.Public.Subject, peer.Subject);
        Assert.Equal(pki.Intermediate.Public.Subject, peer.Issuer);
        Assert.Equal([Mx], peer.DnsNames);
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(pki.Leaf.Public.RawData)), peer.Sha256);
        Assert.True(peer.NotBefore < peer.NotAfter);
        Assert.Equal(TimeSpan.Zero, peer.NotAfter.Offset);
    }

    [Fact]
    public void Session_record_for_a_failed_handshake_has_no_version_and_a_failure()
    {
        var validator = new RemoteCertificateValidator(Decision(TlsSecurityLevel.Encrypt));
        var record = validator.CreateSessionRecord((SslStream?)null, new AuthenticationException("boom"));

        Assert.Null(record.TlsVersion);
        Assert.Null(record.CipherSuite);
        Assert.Null(record.PeerCertificate);
        Assert.False(record.Verified);
        Assert.Equal(TlsResultType.ValidationFailure, record.Failure);
        Assert.Contains(record.Notes, n => n.Contains("AuthenticationException"));
    }

    // ---- end to end over a real TLS handshake on loopback ----

    private static async Task<(SslStream Client, Exception? Failure, RemoteCertificateValidator Validator)> HandshakeAsync(
        TlsPolicyDecision decision,
        RemoteCertificateValidatorOptions? options,
        IssuedCertificate serverLeaf,
        IEnumerable<X509Certificate2> serverChain,
        string targetHost = Mx)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverCert = TestPki.ForServerUse(serverLeaf);
        var context = SslStreamCertificateContext.Create(serverCert, new X509Certificate2Collection(serverChain.ToArray()), offline: true);
        var serverTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync();
            await using var server = new SslStream(accepted.GetStream(), false);
            try
            {
                await server.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificateContext = context, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13 });
                await server.WriteAsync(new byte[] { 1 });
                await server.FlushAsync();
                var buffer = new byte[1];
                _ = await server.ReadAsync(buffer);
            }
            catch (Exception ex) when (ex is AuthenticationException or IOException)
            {
                // The client rejected the certificate.
            }
        });

        var validator = new RemoteCertificateValidator(decision, options);
        var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        var client = new SslStream(tcp.GetStream(), false);
        Exception? failure = null;
        try
        {
            await client.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = targetHost,
                EnabledSslProtocols = decision.AllowedProtocols,
                RemoteCertificateValidationCallback = validator.Callback,
            });
            var one = new byte[1];
            _ = await client.ReadAsync(one);
            await client.WriteAsync(one);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException)
        {
            failure = ex;
            tcp.Dispose(); // close the socket so the server side stops waiting for the rest of the handshake
        }

        await serverTask.WaitAsync(TimeSpan.FromSeconds(20));
        return (client, failure, validator);
    }

    [Fact]
    public async Task End_to_end_pkix_verify_succeeds_and_records_the_negotiated_session()
    {
        var pki = new Pki();
        var (client, failure, validator) = await HandshakeAsync(PkixDecision(true), pki.Trusting, pki.Leaf, [pki.Intermediate.Public]);
        using (client)
        {
            Assert.Null(failure);
            Assert.True(validator.Outcome!.Accepted, string.Join("; ", validator.Outcome.Notes));
            var record = validator.CreateSessionRecord(client);
            Assert.True(record.Verified);
            Assert.Contains(record.TlsVersion, new[] { "TLSv1.2", "TLSv1.3" });
            Assert.False(string.IsNullOrEmpty(record.CipherSuite));
            Assert.Equal(pki.Leaf.Public.Subject, record.PeerCertificate!.Subject);
        }
    }

    [Fact]
    public async Task End_to_end_pkix_failure_aborts_the_handshake_when_enforcing()
    {
        var pki = new Pki(["wrong.example.org"]);
        var (client, failure, validator) = await HandshakeAsync(PkixDecision(true), pki.Trusting, pki.Leaf, [pki.Intermediate.Public]);
        using (client)
        {
            Assert.NotNull(failure);
            Assert.Equal(TlsResultType.CertificateHostMismatch, validator.Outcome!.Failure);
            var record = validator.CreateSessionRecord(client, failure);
            Assert.False(record.Verified);
            Assert.Null(record.TlsVersion);
        }
    }

    [Fact]
    public async Task End_to_end_testing_mode_completes_the_handshake_despite_a_mismatch()
    {
        var pki = new Pki(["wrong.example.org"]);
        var (client, failure, validator) = await HandshakeAsync(PkixDecision(false), pki.Trusting, pki.Leaf, [pki.Intermediate.Public]);
        using (client)
        {
            Assert.Null(failure);
            var record = validator.CreateSessionRecord(client);
            Assert.False(record.Verified);
            Assert.Equal(TlsResultType.CertificateHostMismatch, record.Failure);
            Assert.NotNull(record.TlsVersion);
        }
    }

    [Fact]
    public async Task End_to_end_opportunistic_accepts_a_self_signed_server_and_records_chain_errors()
    {
        var self = TestPki.CreateSelfSignedLeaf([Mx]);
        var (client, failure, validator) = await HandshakeAsync(Decision(TlsSecurityLevel.May), null, self, []);
        using (client)
        {
            Assert.Null(failure);
            var record = validator.CreateSessionRecord(client);
            Assert.False(record.Verified);
            Assert.True(record.SslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors));
            Assert.Equal(self.Public.Subject, record.PeerCertificate!.Subject);
        }
    }

    [Fact]
    public async Task End_to_end_dane_ee_authenticates_an_untrusted_self_signed_server()
    {
        var self = TestPki.CreateSelfSignedLeaf(["not-the-mx.example.net"]);
        var decision = DaneDecision(Tlsa.For(self.Public, 3, 1, 1));
        var (client, failure, validator) = await HandshakeAsync(decision, null, self, []);
        using (client)
        {
            Assert.Null(failure);
            Assert.True(validator.CreateSessionRecord(client).Verified);
        }
    }

    [Fact]
    public async Task End_to_end_dane_mismatch_aborts()
    {
        var self = TestPki.CreateSelfSignedLeaf([Mx]);
        var other = TestPki.CreateSelfSignedLeaf([Mx]);
        var decision = DaneDecision(Tlsa.For(other.Public, 3, 1, 1));
        var (client, failure, validator) = await HandshakeAsync(decision, null, self, []);
        using (client)
        {
            Assert.NotNull(failure);
            Assert.Equal(TlsResultType.ValidationFailure, validator.Outcome!.Failure);
        }
    }

    [Fact]
    public async Task End_to_end_dane_ta_anchors_at_a_presented_intermediate()
    {
        var pki = new Pki();
        var decision = DaneDecision(Tlsa.For(pki.Intermediate.Public, 2, 1, 1));
        var (client, failure, validator) = await HandshakeAsync(decision, null, pki.Leaf, [pki.Intermediate.Public]);
        using (client)
        {
            Assert.True(failure is null, string.Join("; ", validator.Outcome!.Notes));
            Assert.True(validator.Outcome!.Accepted);
        }
    }

    [Fact]
    public async Task End_to_end_dane_ta_with_the_root_certificate_in_dns_works_when_the_server_omits_the_root()
    {
        // .NET servers do not send the root; a full-certificate TA record carries it in DNS instead.
        var pki = new Pki();
        var decision = DaneDecision(Tlsa.For(pki.Root.Public, 2, 0, 0));
        var (client, failure, validator) = await HandshakeAsync(decision, null, pki.Leaf, [pki.Intermediate.Public]);
        using (client)
        {
            Assert.True(failure is null, string.Join("; ", validator.Outcome!.Notes));
            Assert.True(validator.Outcome!.Accepted);
        }
    }
}
