using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Mta.Tls.Dane;

namespace Mta.Tls;

/// <summary>Facts about the peer certificate that delivery persists with each attempt.</summary>
/// <param name="Subject">The subject distinguished name.</param>
/// <param name="Issuer">The issuer distinguished name.</param>
/// <param name="NotBefore">Start of validity (UTC).</param>
/// <param name="NotAfter">End of validity (UTC).</param>
/// <param name="Sha256">Lower-case hex SHA-256 of the DER certificate.</param>
/// <param name="DnsNames">The DNS names in the subject alternative name extension.</param>
public sealed record TlsPeerCertificateInfo(
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string Sha256,
    IReadOnlyList<string> DnsNames);

/// <summary>
/// The TLS facts of one delivery attempt (decision 19: TLS version, cipher and peer certificate are recorded per attempt).
/// </summary>
/// <param name="MxHost">The MX host connected to.</param>
/// <param name="TlsVersion">The negotiated protocol (for example <c>TLSv1.3</c>), or <see langword="null"/> if no session was established.</param>
/// <param name="CipherSuite">The negotiated cipher suite name, if known.</param>
/// <param name="PeerCertificate">The peer certificate, if one was presented.</param>
/// <param name="SslPolicyErrors">The platform's <see cref="System.Net.Security.SslPolicyErrors"/> for the handshake.</param>
/// <param name="Verified">True when the peer was authenticated under the decision's validation mode (PKIX or DANE), or, for no validation, when the platform found no errors.</param>
/// <param name="PolicyApplied">The rule that governed the attempt.</param>
/// <param name="ValidationMode">How the certificate was validated.</param>
/// <param name="ValidationEnforced">Whether a validation failure would have aborted the session.</param>
/// <param name="Failure">The TLS-RPT classification of a validation or handshake failure, if any.</param>
/// <param name="Notes">Human-readable details of the validation.</param>
public sealed record TlsSessionRecord(
    string MxHost,
    string? TlsVersion,
    string? CipherSuite,
    TlsPeerCertificateInfo? PeerCertificate,
    SslPolicyErrors SslPolicyErrors,
    bool Verified,
    TlsPolicyKind PolicyApplied,
    TlsValidationMode ValidationMode,
    bool ValidationEnforced,
    TlsResultType? Failure,
    IReadOnlyList<string> Notes);

/// <summary>The result of validating one peer certificate against a <see cref="TlsPolicyDecision"/>.</summary>
/// <param name="Accepted">Whether the handshake may continue.</param>
/// <param name="Verified">Whether the peer was authenticated under the decision's validation mode.</param>
/// <param name="Failure">The classification when validation failed (also set when a failure was tolerated).</param>
/// <param name="SslPolicyErrors">The platform errors that were passed in.</param>
/// <param name="Notes">Human-readable details.</param>
public sealed record CertificateValidationOutcome(
    bool Accepted,
    bool Verified,
    TlsResultType? Failure,
    SslPolicyErrors SslPolicyErrors,
    IReadOnlyList<string> Notes);

/// <summary>Options for <see cref="RemoteCertificateValidator"/>.</summary>
public sealed class RemoteCertificateValidatorOptions
{
    /// <summary>Trust anchors to use instead of the system store for PKIX validation (private CAs, tests). Empty means the system store.</summary>
    public IReadOnlyList<X509Certificate2> CustomTrustAnchors { get; init; } = [];

    /// <summary>The time used for validity checks. Defaults to now.</summary>
    public Func<DateTimeOffset>? Now { get; init; }
}

/// <summary>
/// Implements a <see cref="TlsPolicyDecision"/> as an <see cref="SslStream"/> remote certificate callback. Create one
/// instance per connection attempt: it remembers the outcome and peer certificate for <see cref="CreateSessionRecord(SslStream?, Exception?)"/>.
/// <list type="bullet">
/// <item><description>No validation (<c>May</c>, <c>Encrypt</c>): accept everything, record the platform errors.</description></item>
/// <item><description>PKIX: the chain must lead to a trusted root (revocation is not checked for MX delivery), be valid in time and carry a SAN DNS name matching the MX host; failures abort only when the decision enforces validation (MTA-STS testing validates and reports but accepts).</description></item>
/// <item><description>DANE: <see cref="DaneVerifier"/> over the decision's TLSA records; a failure always aborts.</description></item>
/// </list>
/// The callback never throws; any unexpected condition is a validation failure.
/// </summary>
public sealed class RemoteCertificateValidator
{
    private readonly TlsPolicyDecision _decision;
    private readonly RemoteCertificateValidatorOptions _options;
    private TlsPeerCertificateInfo? _peer;
    private CertificateValidationOutcome? _outcome;

    /// <summary>Creates a validator for one connection attempt.</summary>
    public RemoteCertificateValidator(TlsPolicyDecision decision, RemoteCertificateValidatorOptions? options = null)
    {
        _decision = decision ?? throw new ArgumentNullException(nameof(decision));
        _options = options ?? new RemoteCertificateValidatorOptions();
    }

    /// <summary>The validator as an <see cref="SslStream"/> callback: <c>new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = validator.Callback }</c>.</summary>
    public RemoteCertificateValidationCallback Callback => Validate;

    /// <summary>The outcome of the last validation, or <see langword="null"/> before the handshake reached it.</summary>
    public CertificateValidationOutcome? Outcome => _outcome;

    /// <summary>The <see cref="RemoteCertificateValidationCallback"/> implementation.</summary>
    public bool Validate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        try
        {
            X509Certificate2? leaf = certificate switch
            {
                null => null,
                X509Certificate2 c2 => c2,
                _ => new X509Certificate2(certificate),
            };
            var presented = new List<X509Certificate2>();
            if (chain is not null)
            {
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    presented.Add(element.Certificate);
                }

                foreach (X509Certificate2 extra in chain.ChainPolicy.ExtraStore)
                {
                    presented.Add(extra);
                }
            }

            return ValidateCertificates(leaf, presented, sslPolicyErrors).Accepted;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _outcome = new CertificateValidationOutcome(
                !_decision.EnforceValidation,
                false,
                TlsResultType.ValidationFailure,
                sslPolicyErrors,
                ["unexpected error during certificate validation: " + ex.GetType().Name]);
            return _outcome.Accepted;
        }
    }

    /// <summary>
    /// Validates a certificate and the certificates the server presented. This is what <see cref="Validate"/> calls; it is
    /// public so callers that already hold the presented certificates can use it directly.
    /// </summary>
    /// <param name="leaf">The server's end-entity certificate, or <see langword="null"/> if none was presented.</param>
    /// <param name="presentedChain">The other certificates the server presented (the leaf may be included).</param>
    /// <param name="sslPolicyErrors">The platform's error flags, recorded as-is.</param>
    public CertificateValidationOutcome ValidateCertificates(X509Certificate2? leaf, IReadOnlyList<X509Certificate2> presentedChain, SslPolicyErrors sslPolicyErrors)
    {
        ArgumentNullException.ThrowIfNull(presentedChain);
        _peer = leaf is null ? null : Describe(leaf);
        var notes = new List<string>();
        CertificateValidationOutcome outcome;

        if (leaf is null)
        {
            notes.Add("the server presented no certificate");
            outcome = new CertificateValidationOutcome(
                _decision.Validation == TlsValidationMode.None,
                false,
                _decision.Validation == TlsValidationMode.None ? null : TlsResultType.ValidationFailure,
                sslPolicyErrors,
                notes);
            return _outcome = outcome;
        }

        switch (_decision.Validation)
        {
            case TlsValidationMode.Pkix:
                outcome = ValidatePkix(leaf, presentedChain, sslPolicyErrors, notes);
                break;
            case TlsValidationMode.Dane:
                outcome = ValidateDane(leaf, presentedChain, sslPolicyErrors, notes);
                break;
            default:
                notes.Add(sslPolicyErrors == SslPolicyErrors.None
                    ? "certificate not validated by policy; the platform found no errors"
                    : $"certificate not validated by policy; platform reported {sslPolicyErrors}");
                outcome = new CertificateValidationOutcome(true, sslPolicyErrors == SslPolicyErrors.None, null, sslPolicyErrors, notes);
                break;
        }

        return _outcome = outcome;
    }

    /// <summary>Builds the per-attempt record from the validation outcome and the negotiated session.</summary>
    /// <param name="stream">The authenticated stream; <see langword="null"/> if the handshake did not complete.</param>
    /// <param name="handshakeException">The exception that ended the handshake, if it failed.</param>
    public TlsSessionRecord CreateSessionRecord(SslStream? stream, Exception? handshakeException = null)
    {
        SslProtocols? protocol = null;
        string? cipher = null;
        if (stream is { IsAuthenticated: true })
        {
            try
            {
                protocol = stream.SslProtocol;
                cipher = stream.NegotiatedCipherSuite.ToString();
            }
            catch (Exception ex) when (ex is NotSupportedException or PlatformNotSupportedException or InvalidOperationException)
            {
                // Cipher details are best effort.
            }
        }

        return CreateSessionRecord(protocol, cipher, handshakeException);
    }

    /// <summary>Builds the per-attempt record from explicit values (also used by tests and by hosts that do their own handshake).</summary>
    public TlsSessionRecord CreateSessionRecord(SslProtocols? protocol, string? cipherSuite, Exception? handshakeException = null)
    {
        var outcome = _outcome;
        TlsResultType? failure = outcome?.Failure;
        var notes = new List<string>(outcome?.Notes ?? []);
        if (handshakeException is not null)
        {
            failure ??= TlsResultType.ValidationFailure;
            notes.Add("handshake failed: " + handshakeException.GetType().Name);
        }

        return new TlsSessionRecord(
            _decision.MxHost,
            protocol is null ? null : VersionName(protocol.Value),
            cipherSuite,
            _peer,
            outcome?.SslPolicyErrors ?? SslPolicyErrors.None,
            outcome?.Verified ?? false,
            _decision.Kind,
            _decision.Validation,
            _decision.EnforceValidation,
            failure,
            notes);
    }

    private CertificateValidationOutcome ValidatePkix(X509Certificate2 leaf, IReadOnlyList<X509Certificate2> presented, SslPolicyErrors errors, List<string> notes)
    {
        TlsResultType? failure = null;
        DateTimeOffset now = _options.Now?.Invoke() ?? DateTimeOffset.UtcNow;

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = now.UtcDateTime;
        chain.ChainPolicy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
        if (_options.CustomTrustAnchors.Count > 0)
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (var anchor in _options.CustomTrustAnchors)
            {
                chain.ChainPolicy.CustomTrustStore.Add(anchor);
            }
        }

        foreach (var certificate in presented.Take(16))
        {
            if (certificate.Thumbprint != leaf.Thumbprint)
            {
                chain.ChainPolicy.ExtraStore.Add(certificate);
            }
        }

        bool chainOk = chain.Build(leaf);
        if (!chainOk)
        {
            X509ChainStatusFlags flags = 0;
            foreach (var status in chain.ChainStatus)
            {
                flags |= status.Status;
                notes.Add($"chain: {status.Status}");
            }

            const X509ChainStatusFlags timeFlags = X509ChainStatusFlags.NotTimeValid | X509ChainStatusFlags.NotTimeNested;
            failure = (flags & ~timeFlags) == 0 && (flags & timeFlags) != 0
                ? TlsResultType.CertificateExpired
                : TlsResultType.CertificateNotTrusted;
        }

        bool nameOk = CertificateHelpers.MatchesHost(leaf, _decision.ExpectedHostname);
        if (!nameOk)
        {
            notes.Add($"certificate does not match host name {_decision.ExpectedHostname}");
            failure ??= TlsResultType.CertificateHostMismatch;
        }

        bool verified = chainOk && nameOk;
        if (verified)
        {
            notes.Add("PKIX validation succeeded");
        }

        bool accepted = verified || !_decision.EnforceValidation;
        if (!verified && accepted)
        {
            notes.Add("validation failure tolerated (policy does not enforce)");
        }

        return new CertificateValidationOutcome(accepted, verified, failure, errors, notes);
    }

    private CertificateValidationOutcome ValidateDane(X509Certificate2 leaf, IReadOnlyList<X509Certificate2> presented, SslPolicyErrors errors, List<string> notes)
    {
        var result = DaneVerifier.Verify(
            _decision.TlsaRecords,
            leaf,
            presented,
            _decision.ExpectedHostname,
            new DaneVerifyOptions { AdditionalReferenceNames = _decision.DaneReferenceNames, Now = _options.Now?.Invoke() });
        notes.Add("certificates available for chain building: " + string.Join(" | ", presented.Select(c => c.Subject).Distinct()));
        notes.AddRange(result.Notes);
        return new CertificateValidationOutcome(result.Success, result.Success, result.Failure, errors, notes);
    }

    private static TlsPeerCertificateInfo Describe(X509Certificate2 certificate) =>
        new(
            certificate.Subject,
            certificate.Issuer,
            new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
            new DateTimeOffset(certificate.NotAfter.ToUniversalTime()),
            CertificateHelpers.Sha256Hex(certificate),
            CertificateHelpers.GetDnsNames(certificate));

    private static string VersionName(SslProtocols protocol) => protocol switch
    {
        SslProtocols.Tls13 => "TLSv1.3",
        SslProtocols.Tls12 => "TLSv1.2",
        SslProtocols.None => "none",
        _ => protocol.ToString(),
    };
}
