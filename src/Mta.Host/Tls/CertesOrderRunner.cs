using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Certes;
using Mta.Core;
using Certes.Acme;
using Certes.Acme.Resource;

namespace Mta.Host.Tls;

/// <summary>
/// ACME order through Certes with HTTP-01 (answered by the built-in listener through <see cref="IHttpChallengePublisher"/>) or DNS-01 (through
/// <see cref="IDnsChallengeProvider"/>), decision 87 (which supersedes 19's "DNS-01 only"); external account binding for CAs that need it. Exercised end
/// to end against the Pebble test CA (<c>tests/Mta.Integration.Tests/Acme</c>, CI); not yet against a production CA.
/// </summary>
public sealed class CertesOrderRunner : IAcmeOrderRunner
{
    /// <summary>Authorizations are polled with a growing pause (a quick CA answers in well under a second) for about two minutes.</summary>
    private const int MaxAuthorizationPolls = 45;

    /// <summary>
    /// After finalize the order is polled this often until it is valid (a CA that issues in a second or two needs one or two; a slow one a few more). The same
    /// pause schedule as for authorizations; a CA's <c>Retry-After</c> lengthens a pause but never beyond <see cref="MaxRetryAfterPause"/>.
    /// </summary>
    private const int MaxOrderPolls = 45;

    /// <summary>A CA's <c>Retry-After</c> on an order that is still processing is honoured up to this long (Certes alone would wait up to 15 minutes per poll, 60 polls).</summary>
    private static readonly TimeSpan MaxRetryAfterPause = TimeSpan.FromSeconds(10);

    /// <summary>An order is repeated this many times in total when the CA keeps rejecting the anti-replay nonce.</summary>
    private const int MaxBadNonceAttempts = 4;

    /// <summary>No answer of a CA is larger than this (an ACME response is a few KB; the certificate chain is the largest).</summary>
    private const long MaxResponseBytes = 1024 * 1024;

    private readonly HttpMessageHandler? _handler;
    private readonly IMtaLog _log;
    private readonly Func<TimeSpan, CancellationToken, Task> _pause;
    private readonly IClock _clock;

    /// <param name="handler">
    /// Transport for all requests to the CA (never disposed here). The default is a plain <see cref="HttpClient"/> with the system trust store;
    /// tests pass a handler that trusts a private test CA, and egress-controlled deployments can pass a proxying one.
    /// </param>
    /// <param name="log">Where a refused <c>replaces</c> link is reported (Debug); none by default.</param>
    /// <param name="clock">The time a received certificate is judged by (it must not be expired already); the system clock by default.</param>
    /// <param name="pause">How the runner waits between polls of the CA and for DNS propagation (<see cref="Task.Delay(TimeSpan, CancellationToken)"/>); tests pass one that records the wait and returns at once.</param>
    public CertesOrderRunner(HttpMessageHandler? handler = null, IMtaLog? log = null, Func<TimeSpan, CancellationToken, Task>? pause = null, IClock? clock = null)
    {
        _clock = clock ?? SystemClock.Instance;
        _handler = handler;
        _log = log ?? NullMtaLog.Instance;
        _pause = pause ?? Task.Delay;
    }

    /// <summary>Our own client in every case, so it is disposed with the call (Certes would otherwise leave one behind), with the response size capped.</summary>
    private HttpClient NewClient() =>
        new(_handler ?? new HttpClientHandler(), disposeHandler: _handler is null) { MaxResponseContentBufferSize = MaxResponseBytes };

    public Task<AcmeIssuedCertificate> IssueAsync(AcmeOrderRequest request, IDnsChallengeProvider dns, CancellationToken ct) =>
        TranslateAsync(async trace =>
        {
            var account = new AccountState { KeyPem = request.AccountKeyPem };
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    return await IssueOnceAsync(request, account, dns, trace, ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (attempt < MaxBadNonceAttempts && IsBadNonce(ex) && !ct.IsCancellationRequested)
                {
                    // The CA does not know the anti-replay nonce we used (they expire, and are per CA front end). The protocol says to
                    // start over with a fresh one; Certes only does that for some of its requests, so the whole order is repeated. An
                    // account registered by an earlier attempt is kept in <see cref="AccountState"/> and reused.
                }
            }
        }, ct);

    /// <summary>
    /// ARI (RFC 9773): asks the CA when it wants the certificate renewed. The request needs no account. Null when the CA does not advertise
    /// <c>renewalInfo</c> in its directory; <see cref="AcmeException"/> when it does and the answer is an error or unusable.
    /// </summary>
    public Task<AcmeRenewalInfo?> GetRenewalInfoAsync(string directoryUrl, string certificateChainPem, CancellationToken ct) =>
        TranslateAsync(async trace =>
        {
            var directory = new Uri(directoryUrl);
            using var http = NewClient();
            var acme = new AcmeContext(directory, null, new ErrorTracingHttpClient(new AcmeHttpClient(directory, http), trace));
            if ((await acme.GetDirectory().ConfigureAwait(false)).RenewalInfo is null)
            {
                return (AcmeRenewalInfo?)null;
            }

            string certificateId = new CertificateChain(certificateChainPem).GetRenewalInfoCertificateId();
            var info = await acme.GetRenewalInfo(certificateId).ConfigureAwait(false);
            return new AcmeRenewalInfo(info.SuggestedWindow.Start, info.SuggestedWindow.End, info.RetryAfter, info.ExplanationUrl?.ToString());
        }, ct);

    /// <summary>
    /// Runs one operation and turns what can go wrong into an <see cref="AcmeException"/> that says what happened, so the renewal record, the banner category and
    /// the log are never a raw <c>NullReferenceException</c>, <c>JsonException</c> or "One or more errors occurred".
    /// </summary>
    private static async Task<T> TranslateAsync<T>(Func<ErrorTrace, Task<T>> body, CancellationToken ct)
    {
        var trace = new ErrorTrace();
        try
        {
            return await body(trace).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not AcmeException && !(ct.IsCancellationRequested && ex is OperationCanceledException) && Translate(ex, trace) is not null)
        {
            throw Translate(ex, trace)!;
        }
    }

    /// <summary>
    /// Certes waits for some of its own tasks synchronously (registering an account, the directory), so a refusal or a transport failure there arrives inside an
    /// <see cref="AggregateException"/>: it is unwrapped first, or a rate limit or a wrong external account binding would be reported as "could not be reached".
    /// </summary>
    private static AcmeException? Translate(Exception exception, ErrorTrace trace)
    {
        switch (exception)
        {
            case AggregateException aggregate:
                var flat = aggregate.Flatten().InnerExceptions;
                return flat.Count == 1
                    ? Translate(flat[0], trace)
                    : flat.Count == 0 ? null : new AcmeException($"The ACME server could not be reached or answered unexpectedly: {flat[0].Message}", flat[0], transient: true);
            case AcmeRequestException request:
                return new AcmeException($"ACME server error: {request.Error?.Detail ?? request.Message}{ProblemName(request.Error)}", request, transient: IsServerError(request), retryAfter: RetryAfterOf(trace))
                {
                    AccountUnknown = request.Error?.Type?.EndsWith(":accountDoesNotExist", StringComparison.Ordinal) == true,
                };
            case Certes.AcmeException other:
                return new AcmeException($"ACME error: {other.Message}", other);
            case OperationCanceledException:
                // HttpClient reports its own timeout as a cancellation; that is a failed attempt to back off from, not a shutdown.
                return new AcmeException("The ACME server did not answer in time.", exception, transient: true);
            case HttpRequestException:
                return new AcmeException($"The ACME server could not be reached or answered unexpectedly: {exception.Message}", exception, transient: true);
            case NotSupportedException:
                return new AcmeException($"The CA's directory does not offer an endpoint this client needs ({exception.Message}).", exception);
            default:
                // Certes reads the CA's JSON without checking it: a body that is not JSON, or lacks a member it needs, surfaces as one of these two. Other exceptions are our own
                // (a damaged stored key, a bad URL) and keep their own message.
                if (exception is JsonException or NullReferenceException)
                {
                    string what = exception is NullReferenceException ? "a member it needs is missing" : $"{exception.GetType().Name}: {exception.Message}";
                    return new AcmeException($"The ACME server sent an answer this client cannot read ({what}).", exception, transient: true);
                }

                return null;
        }
    }

    /// <summary>The problem type as people know it (<c>rateLimited</c>, <c>badNonce</c>, ...), in brackets after the CA's own words; empty when the CA sent none.</summary>
    private static string ProblemName(AcmeError? error) =>
        error?.Type is { Length: > 0 } type ? $" ({type[(type.LastIndexOf(':') + 1)..]})" : "";

    /// <summary>The <c>Retry-After</c> the CA sent with the refusal that ended the operation (rate limits carry one), if any.</summary>
    private static TimeSpan? RetryAfterOf(ErrorTrace trace) => trace.RetryAfterSeconds is > 0 and var seconds ? TimeSpan.FromSeconds(seconds) : null;

    /// <summary>What the transport saw of the CA's refusals: Certes keeps <c>Retry-After</c> of an error answer to itself, the exception does not carry it.</summary>
    private sealed class ErrorTrace
    {
        public int? RetryAfterSeconds { get; set; }
    }

    /// <summary>Notes the <c>Retry-After</c> of the last error answer for <see cref="ErrorTrace"/>; passes everything else through.</summary>
    private sealed class ErrorTracingHttpClient(IAcmeHttpClient inner, ErrorTrace trace) : IAcmeHttpClient
    {
        public Task<string> ConsumeNonce() => inner.ConsumeNonce();

        public async Task<AcmeHttpResponse<T>> Post<T>(Uri uri, object payload) => Note(await inner.Post<T>(uri, payload).ConfigureAwait(false));

        public async Task<AcmeHttpResponse<T>> Get<T>(Uri uri) => Note(await inner.Get<T>(uri).ConfigureAwait(false));

        private AcmeHttpResponse<T> Note<T>(AcmeHttpResponse<T> response)
        {
            trace.RetryAfterSeconds = response.Error is not null && response.RetryAfter > 0 ? response.RetryAfter : null;
            return response;
        }
    }

    private async Task<AcmeIssuedCertificate> IssueOnceAsync(AcmeOrderRequest request, AccountState account, IDnsChallengeProvider dns, ErrorTrace trace, CancellationToken ct)
    {
        var directory = new Uri(request.DirectoryUrl);
        using var http = NewClient();
        IAcmeHttpClient transport = new ErrorTracingHttpClient(new AcmeHttpClient(directory, http), trace);

        AcmeContext acme;
        if (account.KeyPem is null)
        {
            acme = new AcmeContext(directory, null, transport, badNonceRetryCount: 3);
            bool eab = !string.IsNullOrEmpty(request.EabKeyId) && !string.IsNullOrEmpty(request.EabHmacKey);
            if (!eab && (await acme.GetDirectory().ConfigureAwait(false)).Meta?.ExternalAccountRequired == true)
            {
                throw new AcmeException("This CA requires external account binding: set Acme:EabKeyId and Acme:EabHmacKey (or Acme:EabHmacKeyFile) to the key identifier and HMAC key its account page gives you.");
            }

            var registration = eab
                ? acme.NewAccount(ContactsOf(request), termsOfServiceAgreed: true, request.EabKeyId, request.EabHmacKey, "HS256")
                : acme.NewAccount(ContactsOf(request), termsOfServiceAgreed: true);
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

    /// <summary>The account contact (RFC 8555 section 7.3): the email address when there is one; some CAs register accounts without.</summary>
    private static string[] ContactsOf(AcmeOrderRequest request) => string.IsNullOrWhiteSpace(request.Email) ? [] : [$"mailto:{request.Email}"];

    /// <summary>The account in use across the attempts of one <see cref="IssueAsync"/>: the stored one, or the one registered by its first attempt.</summary>
    private sealed class AccountState
    {
        public string? KeyPem { get; set; }

        public string? Url { get; set; }
    }

    private static bool IsServerError(AcmeRequestException ex) =>
        ex.Error is { } error && ((int)error.Status >= 500 || error.Type?.EndsWith(":serverInternal", StringComparison.Ordinal) == true);

    /// <summary>
    /// Failures of the order that carries <c>replaces</c> for which the plain order is the right next step: the certificate was already replaced by another
    /// order, the CA does not know it or the order does not match it (malformed, conflict, not found), it belongs to another account, or the CA failed on its side
    /// (5xx, <c>serverInternal</c>: a CA that has just issued the certificate may not have indexed it yet, as Pebble does not, and a real CA may hiccup). The plain order
    /// loses only the renewal treatment of the link. Rate limits are not among them: asking the CA again at once makes them worse and the plain order would meet the same.
    /// </summary>
    private static bool IsRefusedReplacement(Certes.AcmeException ex) =>
        ex is not AcmeRequestException request // the certificate id could not even be built (no authority key identifier)
        || request.Error is { } error && ((int)error.Status == 404 || IsServerError(request) || error.Type is { } type && (type.EndsWith(":alreadyReplaced", StringComparison.Ordinal) || type.EndsWith(":malformed", StringComparison.Ordinal)
            || type.EndsWith(":conflict", StringComparison.Ordinal) || type.EndsWith(":unauthorized", StringComparison.Ordinal)));

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

    /// <summary>
    /// A new order; when the certificate it renews is known and the CA advertises ARI, an order that names it (<c>replaces</c>, RFC 9773 section 5),
    /// so the CA can tell a renewal from a new certificate (rate limits, and it marks the old one as replaced). The CA may refuse the link
    /// (already replaced by another order, certificate unknown to it, no name in common); that must never stop the renewal, so the plain order follows.
    /// </summary>
    private async Task<IOrderContext> NewOrderAsync(AcmeContext acme, AcmeOrderRequest request)
    {
        var names = request.Domains.ToList();
        if (request.ReplacesCertificatePem is { } replaced && (await acme.GetDirectory().ConfigureAwait(false)).RenewalInfo is not null)
        {
            try
            {
                return await acme.NewReplacementOrder(names, new CertificateChain(replaced).GetRenewalInfoCertificateId()).ConfigureAwait(false);
            }
            catch (Certes.AcmeException ex) when (!IsBadNonce(ex) && IsRefusedReplacement(ex))
            {
                _log.Write(MtaLogLevel.Debug, "acme", $"the CA refused the replaces link ({ex.Message}); ordering without it");
            }
        }

        return await acme.NewOrder(names).ConfigureAwait(false);
    }

    private async Task<AcmeIssuedCertificate> OrderAsync(AcmeContext acme, AcmeOrderRequest request, IDnsChallengeProvider dns, string? accountUrl, CancellationToken ct)
    {
        var order = await NewOrderAsync(acme, request).ConfigureAwait(false);
        var authorizations = await order.Authorizations().ConfigureAwait(false);
        var handles = new List<string>();
        var tokens = new List<string>();
        var challenges = new List<(IAuthorizationContext Authz, IChallengeContext Challenge)>();
        bool http = request.Challenge == AcmeChallengeType.Http01;
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

                if (http)
                {
                    // Only DNS-01 proves a wildcard (RFC 8555 section 8.3); the order was meant for names HTTP-01 can prove, so say so rather than fail at the CA.
                    if (resource.Wildcard == true)
                    {
                        throw new AcmeException($"The order includes the wildcard name *.{resource.Identifier.Value}, which only DNS-01 can prove: set Acme:CloudflareApiToken (DNS-01 with Cloudflare) or remove the wildcard.");
                    }

                    var httpChallenge = await authz.Http().ConfigureAwait(false)
                        ?? throw new AcmeException($"The CA offers no http-01 challenge for {resource.Identifier.Value}; use DNS-01 (Acme:CloudflareApiToken).");
                    await request.Http!.PublishAsync(request.CertificateName, httpChallenge.Token, acme.AccountKey.KeyAuthorization(httpChallenge.Token), ct).ConfigureAwait(false);
                    tokens.Add(httpChallenge.Token);
                    challenges.Add((authz, httpChallenge));
                    continue;
                }

                var challenge = await authz.Dns().ConfigureAwait(false);
                // A wildcard authorization names the base domain (the "*." is a flag), so "*.example.com" and "example.com" share this name
                // with different values; providers must hold several TXT values at one name.
                string txt = acme.AccountKey.DnsTxt(challenge.Token);
                handles.Add(await dns.CreateTxtAsync($"_acme-challenge.{resource.Identifier.Value}", txt, ct).ConfigureAwait(false));
                challenges.Add((authz, challenge));
            }

            if (!http && request.PropagationDelay > TimeSpan.Zero)
            {
                await _pause(request.PropagationDelay, ct).ConfigureAwait(false);
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
                await WaitUntilValidAsync(authz, challenge, http, ct).ConfigureAwait(false);
            }

            var certKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
            string chainPem = await FinalizeAndDownloadAsync(acme, order, request, certKey, ct).ConfigureAwait(false);
            using var ec = ECDsa.Create();
            ec.ImportFromPem(certKey.ToPem());
            using var leaf = PemCertificates(chainPem)[0];
            return new AcmeIssuedCertificate(chainPem, ec.ExportPkcs8PrivateKey(), acme.AccountKey.ToPem(), accountUrl, leaf.NotAfter.ToUniversalTime());
        }
        finally
        {
            foreach (string token in tokens)
            {
                try
                {
                    await request.Http!.RemoveAsync(request.CertificateName, token, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // A token left behind is harmless (it expires, and answers only what the CA already got); never hide why the order failed.
                }
            }

            foreach (string handle in handles)
            {
                try
                {
                    await dns.DeleteTxtAsync(handle, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    // A leftover TXT record is harmless (the next order for the name has its own value next to it); never let cleanup hide why the order itself failed, or
                    // turn an order that succeeded into a failure: the provider can fail in more ways than its own exception type (a timeout is a cancellation, a damaged answer
                    // a JSON error). The handle names the record, so the log says what to delete by hand.
                    _log.Write(MtaLogLevel.Warning, "acme", $"the DNS-01 TXT record '{handle}' could not be removed ({ex.GetType().Name}: {ex.Message}); remove it by hand if it is still there");
                }
            }
        }
    }

    /// <summary>
    /// Finalize, wait for the order to be valid and download the certificate: what Certes' <c>Generate</c> does, with a bounded wait that goes through the runner's
    /// pause (Certes sleeps a CA's <c>Retry-After</c> of up to 15 minutes at a time, 60 times, and ignores why an order the CA made <c>invalid</c> is invalid), a
    /// download whose refusal is reported as the CA's (Certes' download turns a refusal into a <c>NullReferenceException</c>), and a chain that is checked: the
    /// certificate for our key comes first, followed by its issuers in order, and it covers the names ordered.
    /// </summary>
    private async Task<string> FinalizeAndDownloadAsync(AcmeContext acme, IOrderContext order, AcmeOrderRequest request, IKey certKey, CancellationToken ct)
    {
        var state = await order.Resource().ConfigureAwait(false);
        for (int poll = 0; state.Status == OrderStatus.Pending && poll < MaxOrderPolls; poll++)
        {
            // Every authorization is valid but the CA has not noticed yet.
            await _pause(OrderPause(poll, order.RetryAfter), ct).ConfigureAwait(false);
            state = await order.Resource().ConfigureAwait(false);
        }

        if (state.Status != OrderStatus.Ready)
        {
            throw new AcmeException(OrderProblem(state, "before it was finalized"));
        }

        state = await order.Finalize(new CsrInfo { CommonName = request.Domains[0] }, certKey).ConfigureAwait(false);
        for (int poll = 0; state.Status is OrderStatus.Pending or OrderStatus.Processing && poll < MaxOrderPolls; poll++)
        {
            await _pause(OrderPause(poll, order.RetryAfter), ct).ConfigureAwait(false);
            state = await order.Resource().ConfigureAwait(false);
        }

        if (state.Status != OrderStatus.Valid || state.Certificate is null)
        {
            throw new AcmeException(OrderProblem(state, "after it was finalized"));
        }

        // POST-as-GET of the certificate URL. A refusal (rate limit, server error) is an ACME problem like any other, and a badNonce makes the whole order start again.
        AcmeHttpResponse<string> download = null!;
        for (int attempt = 0; attempt <= acme.BadNonceRetryCount; attempt++)
        {
            download = await acme.HttpClient.Post<string>(state.Certificate, await acme.Sign(null!, state.Certificate).ConfigureAwait(false)).ConfigureAwait(false);
            if (download.Error?.Type?.EndsWith(":badNonce", StringComparison.Ordinal) != true)
            {
                break;
            }
        }

        if (download.Error?.Type?.EndsWith(":badNonce", StringComparison.Ordinal) == true)
        {
            // Not an AcmeRequestException, so the order is not started again: a new order is a new certificate (duplicate-certificate and new-order rate limits); the
            // next attempt comes after the back-off.
            throw new AcmeException("The CA kept rejecting the anti-replay nonce while the certificate was downloaded; the order is not repeated at once.", transient: true);
        }

        if (download.Error is not null)
        {
            throw new AcmeRequestException("The CA refused the certificate download", download.Error);
        }

        return ArrangeChain(download.Resource, request.Domains, certKey);
    }

    private static TimeSpan OrderPause(int poll, int retryAfterSeconds)
    {
        var scheduled = PollDelay(poll);
        var asked = TimeSpan.FromSeconds(Math.Clamp(retryAfterSeconds, 0, (int)MaxRetryAfterPause.TotalSeconds));
        return asked > scheduled ? asked : scheduled;
    }

    private static string OrderProblem(Order state, string when)
    {
        string? detail = null;
        if (state.Error is JsonElement { ValueKind: JsonValueKind.Object } error && error.TryGetProperty("detail", out var d) && d.ValueKind == JsonValueKind.String)
        {
            detail = d.GetString();
        }

        return state.Status switch
        {
            OrderStatus.Invalid => "The CA marked the order invalid " + when + (detail is null ? "" : $": {detail}"),
            null => "The CA's order has no status " + when,
            var other => $"The order is still {other} {when}" + (other is OrderStatus.Pending or OrderStatus.Processing ? $" after {MaxOrderPolls} checks" : "") + (detail is null ? "" : $": {detail}"),
        };
    }

    /// <summary>The certificates in a PEM text, in the order they appear; throws when the text holds a certificate that is cut off or damaged.</summary>
    private static List<X509Certificate2> PemCertificates(string? pem)
    {
        pem ??= "";
        int begins = 0;
        for (int at = 0; (at = pem.IndexOf("-----BEGIN CERTIFICATE-----", at, StringComparison.Ordinal)) >= 0; at += 11)
        {
            begins++;
        }

        var certificates = new List<X509Certificate2>();
        try
        {
            var collection = new X509Certificate2Collection();
            collection.ImportFromPem(pem);
            certificates.AddRange(collection.Cast<X509Certificate2>());
        }
        catch (CryptographicException ex)
        {
            throw new AcmeException($"The CA's certificate chain cannot be read: {ex.Message}", ex);
        }

        if (begins == 0)
        {
            throw new AcmeException("The CA sent no certificate (the answer is empty or not PEM).");
        }

        if (certificates.Count != begins)
        {
            throw new AcmeException($"The CA's certificate chain is damaged or cut off: {begins} certificates start but {certificates.Count} are complete.");
        }

        return certificates;
    }

    /// <summary>
    /// The PEM chain in the order TLS wants it (the certificate for our key, then each certificate that issued the one before), checked to be the answer to this order:
    /// a certificate for our key exists and covers every name ordered. Certificates the CA sent that are not on the path stay after it, in the order sent. A chain
    /// without the issuer of the leaf is kept (strict peers cannot verify it, so it is logged), since refusing it would leave the old certificate to expire.
    /// </summary>
    private string ArrangeChain(string? pem, IReadOnlyList<string> names, IKey certKey)
    {
        var received = PemCertificates(pem);
        using var key = ECDsa.Create();
        key.ImportFromPem(certKey.ToPem());
        byte[] ourPublicKey = key.ExportSubjectPublicKeyInfo();
        int leafIndex = received.FindIndex(c => c.GetECDsaPublicKey() is { } ecdsa && ecdsa.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(ourPublicKey));
        if (leafIndex < 0)
        {
            throw new AcmeException("The CA's certificate chain has no certificate for the key of this order (it sent another CA's certificate or one for another key).");
        }

        var leaf = received[leafIndex];
        var covered = CertificateMaterial.SubjectsOf(leaf);
        string? missing = names.FirstOrDefault(name => !AcmeNames.IsCovered(covered, name));
        if (missing is not null)
        {
            throw new AcmeException($"The CA issued a certificate that does not cover '{missing}' (it covers {string.Join(", ", covered)}).");
        }

        if (leaf.NotAfter.ToUniversalTime() <= _clock.UtcNow.UtcDateTime)
        {
            throw new AcmeException($"The CA issued a certificate that is already expired ({leaf.NotAfter.ToUniversalTime():u}); its clock or this server's is wrong.");
        }

        var ordered = new List<X509Certificate2> { leaf };
        var rest = received.Where((_, i) => i != leafIndex).ToList();
        for (var current = leaf; !current.SubjectName.RawData.AsSpan().SequenceEqual(current.IssuerName.RawData);)
        {
            var wantedIssuer = current.IssuerName.RawData;
            int next = rest.FindIndex(c => c.SubjectName.RawData.AsSpan().SequenceEqual(wantedIssuer));
            if (next < 0)
            {
                // The root is normally left out (peers have it), so only a missing issuer of the leaf itself is worth a line: the intermediate is what strict peers cannot fetch.
                if (ReferenceEquals(current, leaf))
                {
                    _log.Write(MtaLogLevel.Warning, "acme", $"the CA's chain does not contain the issuer of the certificate ({current.Issuer}); peers that cannot fetch it will not be able to verify the certificate");
                }

                break;
            }

            current = rest[next];
            ordered.Add(current);
            rest.RemoveAt(next);
        }

        ordered.AddRange(rest);
        if (!ordered.SequenceEqual(received))
        {
            _log.Write(MtaLogLevel.Warning, "acme", "the CA sent its certificate chain in an unusual order; stored leaf first, then its issuers");
        }

        // ExportCertificatePem has no line end after END CERTIFICATE: certificates must be joined with one or the next BEGIN would not be found.
        return string.Concat(ordered.Select(c => c.ExportCertificatePem() + "\n"));
    }

    /// <summary>The pause before poll number <paramref name="attempt"/> (0-based): 200 ms, growing to 3 s.</summary>
    internal static TimeSpan PollDelay(int attempt) => TimeSpan.FromMilliseconds(Math.Min(3000, 200 * Math.Pow(2, Math.Min(attempt, 4))));

    private async Task WaitUntilValidAsync(IAuthorizationContext authz, IChallengeContext challenge, bool http, CancellationToken ct)
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

                throw new AcmeException($"Authorization for {res.Identifier.Value} ended as {res.Status}" + (detail is null ? "" : $": {detail}")
                    + (http ? $" (HTTP-01: the CA connects to port 80 of {res.Identifier.Value}; check that its DNS record points to this server and that port 80 reaches Acme:Http01ListenPort)" : ""));
            }

            if (attempt >= MaxAuthorizationPolls)
            {
                throw new AcmeException($"Authorization for {res.Identifier.Value} is still {res.Status} after {MaxAuthorizationPolls} checks");
            }

            await _pause(PollDelay(attempt), ct).ConfigureAwait(false);
        }
    }
}
