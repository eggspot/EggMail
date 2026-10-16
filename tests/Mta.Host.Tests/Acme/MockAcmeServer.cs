using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Mta.Host.Tests.Acme;

/// <summary>What a mock CA decides about one challenge once the client asked it to validate.</summary>
internal abstract record ChallengeVerdict
{
    /// <summary>The CA validated the challenge.</summary>
    public static readonly ChallengeVerdict Valid = new ValidVerdict();

    /// <summary>The CA validates forever: the challenge and its authorization stay <c>processing</c>.</summary>
    public static readonly ChallengeVerdict PendingForever = new PendingVerdict();

    /// <summary>The CA failed the challenge with an ACME problem (<paramref name="type"/> is the short name, e.g. <c>dns</c> or <c>connection</c>).</summary>
    public static ChallengeVerdict Invalid(string type, string detail) => new InvalidVerdict(type, detail);

    /// <summary>The authorization ends in this status (<c>expired</c>, <c>revoked</c>, <c>deactivated</c>) without a challenge error.</summary>
    public static ChallengeVerdict EndsAs(string authorizationStatus) => new EndsVerdict(authorizationStatus);

    internal sealed record ValidVerdict : ChallengeVerdict;

    internal sealed record EndsVerdict(string Status) : ChallengeVerdict;

    internal sealed record PendingVerdict : ChallengeVerdict;

    internal sealed record InvalidVerdict(string Type, string Detail) : ChallengeVerdict;
}

/// <summary>A challenge as the mock CA validates it: what the client has to publish for it.</summary>
internal sealed record MockChallenge(string Identifier, bool Wildcard, string Type, string Token, string KeyAuthorization)
{
    /// <summary>The value of the DNS-01 TXT record at <c>_acme-challenge.&lt;identifier&gt;</c> (RFC 8555 section 8.4).</summary>
    public string DnsTxtValue => Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(KeyAuthorization)));
}

/// <summary>What the mock CA answers to a request for the certificate.</summary>
public enum MockCertificateMode
{
    /// <summary>Leaf then intermediate, as every real CA sends it.</summary>
    Normal,

    /// <summary>The intermediate comes first, the leaf second.</summary>
    WrongOrder,

    /// <summary>Only the leaf: the intermediate is missing.</summary>
    LeafOnly,

    /// <summary>A certificate for other names than the order's (signed for the CSR's key).</summary>
    WrongNames,

    /// <summary>A certificate for the right names, but for another key than the CSR's.</summary>
    WrongKey,

    /// <summary>The PEM text is cut in the middle of the leaf.</summary>
    Truncated,

    /// <summary>Not PEM at all.</summary>
    Garbage,

    /// <summary>A 200 with an empty body.</summary>
    Empty,

    /// <summary>The certificate is valid for two days only and expired a day ago (the CA's clock is wrong, or a replayed answer).</summary>
    AlreadyExpired,

    /// <summary>Only the intermediate and the root (no leaf for the CSR's key at all).</summary>
    NoLeaf,
}

/// <summary>One request the mock CA saw.</summary>
internal sealed record MockRequest(string Method, string Endpoint, string Path, JsonNode? Payload, int Status);

/// <summary>
/// An ACME server (RFC 8555) as an in-process HTTP transport: no sockets, everything scriptable and deterministic. It speaks the real wire format (JWS with
/// nonces and key id or JWK, verified ES256 signatures, directory, accounts with external account binding, orders, authorizations, challenges, finalize with
/// a CSR it parses and issues from, certificate download, ACME Renewal Information) and issues real certificates from a throw-away root and intermediate, so
/// <c>CertesOrderRunner</c> runs through it unchanged. It validates challenges through a <see cref="Validator"/> the test sets (by default everything is valid);
/// see <see cref="MockChallengeValidators"/> for validators that really check the TXT value or the HTTP answer the client published.
/// It is what Pebble cannot be told to do: rate limits, bad nonces in storms, malformed answers, expired orders, wrong chains.
/// </summary>
internal sealed class MockAcmeServer : HttpMessageHandler, IDisposable
{
    public const string Base = "https://acme.mock.test";
    public const string DirectoryUrl = Base + "/directory";

    private readonly object _gate = new();
    private readonly Func<DateTimeOffset> _now;
    private readonly HashSet<string> _validNonces = [];
    private readonly Dictionary<string, Account> _accountsByKid = [];
    private readonly Dictionary<string, Account> _accountsByThumbprint = [];
    private readonly Dictionary<string, Order> _orders = [];
    private readonly Dictionary<string, Authorization> _authorizations = [];
    private readonly Dictionary<string, Challenge> _challenges = [];
    private readonly Dictionary<string, List<(string Endpoint, Func<HttpRequestMessage, HttpResponseMessage>? Response, Exception? Throw, int Times)>> _overrides = [];
    private readonly List<MockRequest> _requests = [];
    private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 _root;
    private readonly X509Certificate2 _intermediate;
    private int _counter;
    private int _badNonceRemaining;

    public MockAcmeServer(Func<DateTimeOffset>? now = null)
    {
        _now = now ?? (() => DateTimeOffset.UtcNow);
        var start = _now().AddDays(-3650);
        var end = _now().AddDays(3650);
        var rootRequest = new CertificateRequest("CN=Mock Root CA", _rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootRequest.PublicKey, false));
        _root = rootRequest.CreateSelfSigned(start, end);
        var intermediateRequest = new CertificateRequest("CN=Mock Intermediate CA", _intermediateKey, HashAlgorithmName.SHA256);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        intermediateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, false));
        intermediateRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_root, true, false));
        using var signed = intermediateRequest.Create(_root, start, end, RandomNumberGenerator.GetBytes(8));
        _intermediate = signed.CopyWithPrivateKey(_intermediateKey);
    }

    // ----------------------------------------------------------------------------------------------------------------------------------
    // Scripting

    /// <summary>Validates challenges; by default every challenge is valid.</summary>
    public Func<MockChallenge, ChallengeVerdict> Validator { get; set; } = _ => ChallengeVerdict.Valid;

    /// <summary>How many times an authorization is looked at after the client asked for validation before the CA decides (1: the first look decides).</summary>
    public int ValidationPolls { get; set; } = 1;

    /// <summary>How many times the order is looked at in state <c>processing</c> after finalize before it is <c>valid</c> (0: finalize answers <c>valid</c>).</summary>
    public int FinalizeProcessingPolls { get; set; }

    /// <summary>The <c>Retry-After</c> seconds sent with an order that is <c>processing</c> (null: none).</summary>
    public int? ProcessingRetryAfterSeconds { get; set; }

    /// <summary>The order ends <c>invalid</c> after finalize (with this problem detail) instead of <c>valid</c>.</summary>
    public string? FinalizeEndsInvalid { get; set; }

    public MockCertificateMode CertificateMode { get; set; }

    /// <summary>
    /// Once every authorization is valid the order is not <c>ready</c> but this status (with the problem detail), as an order the CA let expire in the meantime
    /// (RFC 8555 has no <c>expired</c> order status: it is <c>invalid</c>) or a CA that sends a status the client does not know.
    /// </summary>
    public (string Status, string Detail)? OrderTurnsInsteadOfReady { get; set; }

    /// <summary>The CA answers a new order with authorizations that are already valid (RFC 8555 section 7.4.1).</summary>
    public bool ReuseValidAuthorizations { get; set; }

    /// <summary>The directory advertises <c>renewalInfo</c> (ARI).</summary>
    public bool AdvertiseRenewalInfo { get; set; }

    /// <summary>The directory says <c>meta.externalAccountRequired</c>.</summary>
    public bool ExternalAccountRequired { get; set; }

    /// <summary>Key identifier to HMAC key (base64url) of the accounts the CA knows at its CA-side (for external account binding).</summary>
    public Dictionary<string, string> EabKeys { get; } = [];

    /// <summary>The CA refuses these names (<c>rejectedIdentifier</c>).</summary>
    public HashSet<string> RejectedNames { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Answers a renewal information request (the argument is the certificate id).</summary>
    public Func<string, HttpResponseMessage>? RenewalInfo { get; set; }

    /// <summary>Lifetime of the certificates it issues.</summary>
    public TimeSpan CertificateLifetime { get; set; } = TimeSpan.FromDays(90);

    /// <summary>The next <paramref name="count"/> POSTs (other than the nonce endpoint) are rejected with <c>badNonce</c>, as a CA does whose front ends do not share nonces.</summary>
    public void RejectNonces(int count)
    {
        lock (_gate)
        {
            _badNonceRemaining = count;
        }
    }

    /// <summary>Answers the next <paramref name="times"/> requests to <paramref name="endpoint"/> with an ACME problem.</summary>
    public void Fail(string endpoint, int status, string type, string detail = "scripted failure", int times = 1, int? retryAfterSeconds = null, string? retryAfterRaw = null) =>
        Override(endpoint, _ =>
        {
            var response = Problem(status, type, detail);
            if (retryAfterSeconds is not null)
            {
                response.Headers.TryAddWithoutValidation("Retry-After", retryAfterSeconds.Value.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            else if (retryAfterRaw is not null)
            {
                response.Headers.TryAddWithoutValidation("Retry-After", retryAfterRaw);
            }

            return response;
        }, times);

    /// <summary>Answers the next <paramref name="times"/> requests to <paramref name="endpoint"/> with this response (built per request).</summary>
    public void Override(string endpoint, Func<HttpRequestMessage, HttpResponseMessage> response, int times = 1)
    {
        lock (_gate)
        {
            GetOverrides(endpoint).Add((endpoint, response, null, times));
        }
    }

    /// <summary>The next <paramref name="times"/> requests to <paramref name="endpoint"/> fail like the network (a timeout or a refused connection).</summary>
    public void Throw(string endpoint, Exception exception, int times = 1)
    {
        lock (_gate)
        {
            GetOverrides(endpoint).Add((endpoint, null, exception, times));
        }
    }

    private List<(string Endpoint, Func<HttpRequestMessage, HttpResponseMessage>? Response, Exception? Throw, int Times)> GetOverrides(string endpoint) =>
        _overrides.TryGetValue(endpoint, out var list) ? list : _overrides[endpoint] = [];

    // ----------------------------------------------------------------------------------------------------------------------------------
    // What the tests look at

    public IReadOnlyList<MockRequest> Requests
    {
        get
        {
            lock (_gate)
            {
                return [.. _requests];
            }
        }
    }

    public int Count(string endpoint, string? method = null) => Requests.Count(r => r.Endpoint == endpoint && (method is null || r.Method == method));

    public int Count(string endpoint, int status) => Requests.Count(r => r.Endpoint == endpoint && r.Status == status);

    public int AccountCount
    {
        get
        {
            lock (_gate)
            {
                return _accountsByKid.Count;
            }
        }
    }

    /// <summary>Names (identifier values) of the orders created, in order, and whether the order carried <c>replaces</c>.</summary>
    public IReadOnlyList<(string[] Names, string? Replaces)> OrdersCreated
    {
        get
        {
            lock (_gate)
            {
                return [.. _orders.Values.OrderBy(o => o.Number).Select(o => (o.Identifiers.ToArray(), o.Replaces))];
            }
        }
    }

    /// <summary>The root certificate of the CA (DER), for tests that verify chains.</summary>
    public X509Certificate2 Root => _root;

    public X509Certificate2 Intermediate => _intermediate;

    /// <summary>The thumbprint of the account key (RFC 7638) that registered, which key authorizations are built from.</summary>
    public string? AccountThumbprint
    {
        get
        {
            lock (_gate)
            {
                return _accountsByThumbprint.Keys.FirstOrDefault();
            }
        }
    }

    public new void Dispose()
    {
        _root.Dispose();
        _intermediate.Dispose();
        _rootKey.Dispose();
        _intermediateKey.Dispose();
        base.Dispose();
    }

    // ----------------------------------------------------------------------------------------------------------------------------------
    // Transport

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string body = request.Content is null ? "" : request.Content.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
        lock (_gate)
        {
            string path = request.RequestUri!.AbsolutePath;
            string endpoint = EndpointOf(path);
            JsonNode? payload = null;
            HttpResponseMessage response;
            try
            {
                var scripted = TakeOverride(endpoint) ?? TakeOverride("*");
                if (scripted is { Throw: { } exception })
                {
                    _requests.Add(new MockRequest(request.Method.Method, endpoint, path, null, -1));
                    throw exception;
                }

                // A CA checks the anti-replay nonce before it looks at anything else, so a scripted failure never hides a client that reuses a nonce.
                Jws? jws = null;
                if (request.Method == HttpMethod.Post && endpoint is not ("directory" or "newNonce" or "renewalInfo" or "unknown"))
                {
                    jws = CheckJws(request, body);
                    payload = jws.Payload;
                }

                response = scripted is { Response: { } make } ? make(request) : Handle(request, endpoint, path, jws);
            }
            catch (ProblemException problem)
            {
                response = Problem(problem.Status, problem.Type, problem.Detail);
            }

            response.Headers.TryAddWithoutValidation("Replay-Nonce", NewNonce());

            _requests.Add(new MockRequest(request.Method.Method, endpoint, path, payload, (int)response.StatusCode));
            return Task.FromResult(response);
        }
    }

    private (string Endpoint, Func<HttpRequestMessage, HttpResponseMessage>? Response, Exception? Throw, int Times)? TakeOverride(string endpoint)
    {
        if (!_overrides.TryGetValue(endpoint, out var list) || list.Count == 0)
        {
            return null;
        }

        var first = list[0];
        if (first.Times <= 1)
        {
            list.RemoveAt(0);
        }
        else
        {
            list[0] = first with { Times = first.Times - 1 };
        }

        return first;
    }

    private static string EndpointOf(string path) => path switch
    {
        "/directory" => "directory",
        "/new-nonce" => "newNonce",
        "/new-account" => "newAccount",
        "/new-order" => "newOrder",
        "/revoke" => "revoke",
        _ when path.StartsWith("/acct/", StringComparison.Ordinal) => "account",
        _ when path.StartsWith("/order/", StringComparison.Ordinal) => "order",
        _ when path.StartsWith("/finalize/", StringComparison.Ordinal) => "finalize",
        _ when path.StartsWith("/authz/", StringComparison.Ordinal) => "authz",
        _ when path.StartsWith("/chall/", StringComparison.Ordinal) => "challenge",
        _ when path.StartsWith("/cert/", StringComparison.Ordinal) => "certificate",
        _ when path.StartsWith("/renewal-info", StringComparison.Ordinal) => "renewalInfo",
        _ => "unknown",
    };

    /// <summary>Parses the JWS and consumes its nonce (one use), and checks the signed URL.</summary>
    private Jws CheckJws(HttpRequestMessage request, string body)
    {
        var jws = Jws.Parse(body);
        if (_badNonceRemaining > 0)
        {
            _badNonceRemaining--;
            throw new ProblemException(400, "badNonce", "JWS has an invalid anti-replay nonce: simulated front end that does not know it");
        }

        if (jws.Nonce is null || !_validNonces.Remove(jws.Nonce))
        {
            throw new ProblemException(400, "badNonce", $"JWS has an invalid anti-replay nonce: {jws.Nonce}");
        }

        if (jws.Url != request.RequestUri!.AbsoluteUri)
        {
            throw new ProblemException(401, "unauthorized", $"JWS header parameter 'url' ({jws.Url}) does not match the request URL");
        }

        return jws;
    }

    private HttpResponseMessage Handle(HttpRequestMessage request, string endpoint, string path, Jws? jws)
    {
        switch (endpoint)
        {
            case "directory":
                return Json(HttpStatusCode.OK, Directory());
            case "newNonce":
                return new HttpResponseMessage(request.Method == HttpMethod.Head ? HttpStatusCode.OK : HttpStatusCode.NoContent);
            case "renewalInfo":
                return RenewalInfo is { } ari ? ari(path["/renewal-info/".Length..]) : Problem(404, "malformed", "no such certificate");
            case "unknown":
                return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        if (request.Method != HttpMethod.Post)
        {
            throw new ProblemException(405, "malformed", "ACME resources are POST-as-GET");
        }

        if (jws is null)
        {
            throw new ProblemException(400, "malformed", "a signed request is required");
        }

        if (endpoint == "newAccount")
        {
            return NewAccount(jws);
        }

        var account = Authenticate(jws);
        return endpoint switch
        {
            "newOrder" => NewOrder(account, jws),
            "authz" => GetAuthorization(account, path),
            "challenge" => AnswerChallenge(account, path, jws),
            "order" => GetOrder(account, path),
            "finalize" => Finalize(account, path, jws),
            "certificate" => GetCertificate(account, path),
            "account" => Json(HttpStatusCode.OK, new JsonObject { ["status"] = account.Status }),
            _ => throw new ProblemException(404, "malformed", "unknown resource"),
        };
    }

    private JsonObject Directory()
    {
        var directory = new JsonObject
        {
            ["newNonce"] = Base + "/new-nonce",
            ["newAccount"] = Base + "/new-account",
            ["newOrder"] = Base + "/new-order",
            ["revokeCert"] = Base + "/revoke",
            ["keyChange"] = Base + "/key-change",
            ["meta"] = new JsonObject { ["termsOfService"] = Base + "/terms", ["externalAccountRequired"] = ExternalAccountRequired },
        };
        if (AdvertiseRenewalInfo)
        {
            directory["renewalInfo"] = Base + "/renewal-info";
        }

        return directory;
    }

    private string NewNonce()
    {
        string nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(12));
        _validNonces.Add(nonce);
        return nonce;
    }

    // ----------------------------------------------------------------------------------------------------------------------------------
    // Accounts

    private HttpResponseMessage NewAccount(Jws jws)
    {
        if (jws.Jwk is null)
        {
            throw new ProblemException(400, "malformed", "newAccount needs a jwk");
        }

        string thumbprint = jws.JwkThumbprint!;
        bool onlyReturnExisting = jws.Payload?["onlyReturnExisting"]?.GetValue<bool>() == true;
        if (_accountsByThumbprint.TryGetValue(thumbprint, out var existing))
        {
            if (existing.Status != "valid")
            {
                throw new ProblemException(403, "unauthorized", "The account has been deactivated");
            }

            var found = Json(HttpStatusCode.OK, new JsonObject { ["status"] = "valid" });
            found.Headers.Location = new Uri(existing.Kid);
            return found;
        }

        if (onlyReturnExisting)
        {
            throw new ProblemException(400, "accountDoesNotExist", "No account exists with the provided key");
        }

        if (jws.Payload?["termsOfServiceAgreed"]?.GetValue<bool>() != true)
        {
            throw new ProblemException(403, "unauthorized", "Terms of service must be agreed to");
        }

        string? eabKeyId = null;
        if (jws.Payload?["externalAccountBinding"] is JsonObject eab)
        {
            eabKeyId = VerifyBinding(eab, jws);
        }
        else if (ExternalAccountRequired)
        {
            throw new ProblemException(400, "externalAccountRequired", "the CA requires an external account binding");
        }

        string kid = $"{Base}/acct/{++_counter}";
        var account = new Account(kid, thumbprint, jws.Jwk, "valid", eabKeyId);
        _accountsByKid[kid] = account;
        _accountsByThumbprint[thumbprint] = account;
        var created = Json(HttpStatusCode.Created, new JsonObject { ["status"] = "valid", ["contact"] = jws.Payload?["contact"]?.DeepClone() });
        created.Headers.Location = new Uri(kid);
        return created;
    }

    /// <summary>RFC 8555 section 7.3.4: the binding is an HS256 JWS over the account key, with the CA-side key id as <c>kid</c>.</summary>
    private string VerifyBinding(JsonObject eab, Jws outer)
    {
        string protectedPart = eab["protected"]!.GetValue<string>();
        string payloadPart = eab["payload"]!.GetValue<string>();
        string signaturePart = eab["signature"]!.GetValue<string>();
        using var header = JsonDocument.Parse(Base64Url.DecodeFromChars(protectedPart));
        string? alg = header.RootElement.GetProperty("alg").GetString();
        string? kid = header.RootElement.GetProperty("kid").GetString();
        string? url = header.RootElement.GetProperty("url").GetString();
        if (alg != "HS256" || kid is null || url != Base + "/new-account")
        {
            throw new ProblemException(400, "malformed", "the external account binding header is wrong");
        }

        if (!EabKeys.TryGetValue(kid, out string? key))
        {
            throw new ProblemException(403, "unauthorized", $"the key identifier '{kid}' of the external account binding is unknown");
        }

        byte[] expected = HMACSHA256.HashData(Base64Url.DecodeFromChars(key), Encoding.ASCII.GetBytes(protectedPart + "." + payloadPart));
        if (!CryptographicOperations.FixedTimeEquals(expected, Base64Url.DecodeFromChars(signaturePart)))
        {
            throw new ProblemException(403, "unauthorized", "the external account binding MAC does not verify");
        }

        var bound = JsonNode.Parse(Base64Url.DecodeFromChars(payloadPart));
        if (!JsonNode.DeepEquals(bound, outer.Jwk))
        {
            throw new ProblemException(400, "malformed", "the external account binding does not bind this account key");
        }

        return kid;
    }

    private Account Authenticate(Jws jws)
    {
        if (jws.Kid is null || !_accountsByKid.TryGetValue(jws.Kid, out var account))
        {
            throw new ProblemException(400, "accountDoesNotExist", "unknown account (kid)");
        }

        if (!jws.Verify(account.Jwk))
        {
            throw new ProblemException(403, "unauthorized", "JWS verification error");
        }

        if (account.Status != "valid")
        {
            throw new ProblemException(403, "unauthorized", "The account has been deactivated");
        }

        return account;
    }

    /// <summary>The CA deactivates the account (the next request signed with its key is refused <c>unauthorized</c>).</summary>
    public void DeactivateAccounts()
    {
        lock (_gate)
        {
            foreach (var account in _accountsByKid.Values)
            {
                account.Status = "deactivated";
            }
        }
    }

    /// <summary>The CA forgets all accounts (a reset test CA, a migrated one): the stored key then names an account that does not exist.</summary>
    public void ForgetAccounts()
    {
        lock (_gate)
        {
            _accountsByKid.Clear();
            _accountsByThumbprint.Clear();
        }
    }

    // ----------------------------------------------------------------------------------------------------------------------------------
    // Orders, authorizations, challenges

    private HttpResponseMessage NewOrder(Account account, Jws jws)
    {
        var identifiers = jws.Payload?["identifiers"]?.AsArray() ?? throw new ProblemException(400, "malformed", "no identifiers");
        if (identifiers.Count == 0)
        {
            throw new ProblemException(400, "malformed", "an order needs identifiers");
        }

        var order = new Order(++_counter, account.Kid) { Replaces = jws.Payload?["replaces"]?.GetValue<string>() };
        foreach (var identifier in identifiers)
        {
            string value = identifier!["value"]!.GetValue<string>();
            if (identifier["type"]?.GetValue<string>() != "dns")
            {
                throw new ProblemException(400, "unsupportedIdentifier", "only dns identifiers");
            }

            if (RejectedNames.Contains(value))
            {
                throw new ProblemException(400, "rejectedIdentifier", $"The CA will not issue for \"{value}\"");
            }

            order.Identifiers.Add(value);
            bool wildcard = value.StartsWith("*.", StringComparison.Ordinal);
            string baseName = wildcard ? value[2..] : value;
            var reusable = ReuseValidAuthorizations
                ? _authorizations.Values.FirstOrDefault(a => a.AccountKid == account.Kid && a.Identifier == baseName && a.Wildcard == wildcard && a.Status == "valid")
                : null;
            order.AuthorizationIds.Add((reusable ?? CreateAuthorization(account, baseName, wildcard)).Id);
        }

        _orders[order.Number.ToString(System.Globalization.CultureInfo.InvariantCulture)] = order;
        var response = Json(HttpStatusCode.Created, OrderJson(order));
        response.Headers.Location = new Uri($"{Base}/order/{order.Number}");
        return response;
    }

    private Authorization CreateAuthorization(Account account, string identifier, bool wildcard)
    {
        var authorization = new Authorization(++_counter, account.Kid, identifier, wildcard);
        _authorizations[authorization.Id.ToString(System.Globalization.CultureInfo.InvariantCulture)] = authorization;
        var types = wildcard ? new[] { "dns-01" } : new[] { "http-01", "dns-01" };
        foreach (string type in types)
        {
            var challenge = new Challenge(++_counter, authorization.Id, type, Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32)), authorization);
            _challenges[challenge.Id.ToString(System.Globalization.CultureInfo.InvariantCulture)] = challenge;
            authorization.Challenges.Add(challenge);
        }

        return authorization;
    }

    private JsonObject OrderJson(Order order)
    {
        RefreshOrder(order);
        var json = new JsonObject
        {
            ["status"] = order.Status,
            ["expires"] = _now().AddDays(7).ToString("o"),
            ["identifiers"] = new JsonArray([.. order.Identifiers.Select(i => (JsonNode)new JsonObject { ["type"] = "dns", ["value"] = i })]),
            ["authorizations"] = new JsonArray([.. order.AuthorizationIds.Select(id => (JsonNode)JsonValue.Create($"{Base}/authz/{id}")!)]),
            ["finalize"] = $"{Base}/finalize/{order.Number}",
        };
        if (order.Status == "valid")
        {
            json["certificate"] = $"{Base}/cert/{order.Number}";
        }

        if (order.Status == "invalid" && order.Error is not null)
        {
            json["error"] = new JsonObject { ["type"] = "urn:ietf:params:acme:error:serverInternal", ["detail"] = order.Error, ["status"] = 500 };
        }

        return json;
    }

    /// <summary>The order's status follows its authorizations (pending, ready, invalid) until it is finalized.</summary>
    private void RefreshOrder(Order order)
    {
        if (order.Status is not ("pending" or "ready"))
        {
            return;
        }

        var states = order.AuthorizationIds.Select(id => _authorizations[id.ToString(System.Globalization.CultureInfo.InvariantCulture)].Status).ToList();
        order.Status = states.Any(s => s is "invalid" or "expired" or "deactivated" or "revoked") ? "invalid"
            : states.All(s => s == "valid") ? OrderTurnsInsteadOfReady?.Status ?? "ready"
            : "pending";
        if (order.Status != "ready" && order.Status != "pending" && OrderTurnsInsteadOfReady is { } turned)
        {
            order.Error = turned.Detail;
        }
    }

    private HttpResponseMessage GetAuthorization(Account account, string path)
    {
        var authorization = Find(_authorizations, path["/authz/".Length..], account.Kid, a => a.AccountKid);
        Advance(authorization);
        return Json(HttpStatusCode.OK, AuthorizationJson(authorization));
    }

    /// <summary>A looked-at authorization whose challenge the client answered moves on: once enough looks have passed the CA decides.</summary>
    private void Advance(Authorization authorization)
    {
        if (authorization.Status != "pending")
        {
            return;
        }

        var processing = authorization.Challenges.FirstOrDefault(c => c.Status == "processing");
        if (processing is null)
        {
            return;
        }

        if (++processing.Looks < ValidationPolls)
        {
            return;
        }

        var verdict = Validator(new MockChallenge(authorization.Identifier, authorization.Wildcard, processing.Type, processing.Token, processing.Token + "." + AccountThumbprintOf(authorization.AccountKid)));
        switch (verdict)
        {
            case ChallengeVerdict.ValidVerdict:
                processing.Status = "valid";
                authorization.Status = "valid";
                break;
            case ChallengeVerdict.EndsVerdict ends:
                processing.Status = "invalid";
                authorization.Status = ends.Status;
                break;
            case ChallengeVerdict.InvalidVerdict invalid:
                processing.Status = "invalid";
                processing.Error = new JsonObject { ["type"] = "urn:ietf:params:acme:error:" + invalid.Type, ["detail"] = invalid.Detail, ["status"] = 400 };
                authorization.Status = "invalid";
                break;
        }
    }

    private string AccountThumbprintOf(string kid) => _accountsByKid.TryGetValue(kid, out var account) ? account.Thumbprint : "?";

    private JsonObject AuthorizationJson(Authorization authorization)
    {
        var json = new JsonObject
        {
            ["status"] = authorization.Status,
            ["expires"] = _now().AddDays(7).ToString("o"),
            ["identifier"] = new JsonObject { ["type"] = "dns", ["value"] = authorization.Identifier },
            ["challenges"] = new JsonArray([.. authorization.Challenges.Select(ChallengeJson)]),
        };
        if (authorization.Wildcard)
        {
            json["wildcard"] = true;
        }

        return json;
    }

    private JsonNode ChallengeJson(Challenge challenge)
    {
        var json = new JsonObject { ["type"] = challenge.Type, ["url"] = $"{Base}/chall/{challenge.Id}", ["status"] = challenge.Status, ["token"] = challenge.Token };
        if (challenge.Error is not null)
        {
            json["error"] = challenge.Error.DeepClone();
        }

        if (challenge.Status == "valid")
        {
            json["validated"] = _now().ToString("o");
        }

        return json;
    }

    private HttpResponseMessage AnswerChallenge(Account account, string path, Jws jws)
    {
        var challenge = Find(_challenges, path["/chall/".Length..], account.Kid, c => c.Authorization.AccountKid);
        if (jws.Payload is null)
        {
            // POST-as-GET (empty payload): only reads the challenge. The client answers it by posting {}.
            return Json(HttpStatusCode.OK, ChallengeJson(challenge));
        }

        if (challenge.Status != "pending")
        {
            throw new ProblemException(400, "malformed", $"Cannot update challenge with status {challenge.Status}, only status pending");
        }

        challenge.Status = "processing";
        return Json(HttpStatusCode.OK, ChallengeJson(challenge));
    }

    private HttpResponseMessage GetOrder(Account account, string path)
    {
        var order = Find(_orders, path["/order/".Length..], account.Kid, o => o.AccountKid);
        var response = Json(HttpStatusCode.OK, OrderJson(order));
        if (order.Status == "processing")
        {
            if (order.ProcessingLooksLeft-- <= 1)
            {
                order.Status = FinalizeEndsInvalid is null ? "valid" : "invalid";
                order.Error = FinalizeEndsInvalid;
                response.Dispose();
                response = Json(HttpStatusCode.OK, OrderJson(order));
            }
            else if (ProcessingRetryAfterSeconds is { } seconds)
            {
                response.Headers.TryAddWithoutValidation("Retry-After", seconds.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
        }

        return response;
    }

    private HttpResponseMessage Finalize(Account account, string path, Jws jws)
    {
        var order = Find(_orders, path["/finalize/".Length..], account.Kid, o => o.AccountKid);
        RefreshOrder(order);
        if (order.Status != "ready")
        {
            throw new ProblemException(403, "orderNotReady", $"Order's status (\"{order.Status}\") is not acceptable for finalization");
        }

        string csrB64 = jws.Payload?["csr"]?.GetValue<string>() ?? throw new ProblemException(400, "malformed", "no csr");
        order.CsrDer = Base64Url.DecodeFromChars(csrB64);
        CertificateRequest csr;
        try
        {
            csr = CertificateRequest.LoadSigningRequest(order.CsrDer, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        }
        catch (CryptographicException ex)
        {
            throw new ProblemException(400, "badCSR", "the CSR cannot be parsed: " + ex.Message);
        }

        var names = csr.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(e => e.EnumerateDnsNames()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!names.SetEquals(order.Identifiers))
        {
            throw new ProblemException(400, "badCSR", $"CSR names [{string.Join(", ", names)}] differ from the order's [{string.Join(", ", order.Identifiers)}]");
        }

        order.CsrPublicKey = csr.PublicKey;
        order.Status = "processing";
        order.ProcessingLooksLeft = FinalizeProcessingPolls;
        if (FinalizeProcessingPolls == 0)
        {
            order.Status = FinalizeEndsInvalid is null ? "valid" : "invalid";
            order.Error = FinalizeEndsInvalid;
        }

        var response = Json(HttpStatusCode.OK, OrderJson(order));
        response.Headers.Location = new Uri($"{Base}/order/{order.Number}");
        if (order.Status == "processing" && ProcessingRetryAfterSeconds is { } seconds)
        {
            response.Headers.TryAddWithoutValidation("Retry-After", seconds.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        return response;
    }

    // ----------------------------------------------------------------------------------------------------------------------------------
    // Certificates

    private HttpResponseMessage GetCertificate(Account account, string path)
    {
        var order = Find(_orders, path["/cert/".Length..], account.Kid, o => o.AccountKid);
        if (order.Status != "valid")
        {
            throw new ProblemException(403, "orderNotReady", "the order has no certificate");
        }

        string pem = CertificateMode switch
        {
            MockCertificateMode.Empty => "",
            MockCertificateMode.Garbage => "this is not a certificate\n",
            _ => BuildChain(order),
        };
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(pem, Encoding.ASCII, "application/pem-certificate-chain") };
    }

    private string BuildChain(Order order)
    {
        var names = CertificateMode == MockCertificateMode.WrongNames ? ["someone-else.mock.test"] : order.Identifiers;
        PublicKey key = order.CsrPublicKey!;
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (CertificateMode == MockCertificateMode.WrongKey)
        {
            key = PublicKeyOf(otherKey.ExportSubjectPublicKeyInfo());
        }

        var request = new CertificateRequest(new X500DistinguishedName("CN=" + names[0]), key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        foreach (string name in names)
        {
            san.AddDnsName(name);
        }

        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_intermediate, true, false));
        var notBefore = _now().AddMinutes(-5);
        var notAfter = _now() + CertificateLifetime;
        if (CertificateMode == MockCertificateMode.AlreadyExpired)
        {
            notBefore = _now().AddDays(-3);
            notAfter = _now().AddDays(-1);
        }

        using var leaf = request.Create(_intermediate, notBefore, notAfter, RandomNumberGenerator.GetBytes(12));
        string leafPem = leaf.ExportCertificatePem() + "\n";
        string intermediatePem = _intermediate.ExportCertificatePem() + "\n";
        string rootPem = _root.ExportCertificatePem() + "\n";
        return CertificateMode switch
        {
            MockCertificateMode.WrongOrder => intermediatePem + leafPem,
            MockCertificateMode.LeafOnly => leafPem,
            MockCertificateMode.Truncated => leafPem[..(leafPem.Length / 2)],
            MockCertificateMode.NoLeaf => intermediatePem + rootPem,
            _ => leafPem + intermediatePem,
        };
    }

    private static PublicKey PublicKeyOf(byte[] subjectPublicKeyInfo)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
        var request = new CertificateRequest("CN=x", ecdsa, HashAlgorithmName.SHA256);
        return request.PublicKey;
    }

    // ----------------------------------------------------------------------------------------------------------------------------------
    // Helpers

    private static T Find<T>(Dictionary<string, T> items, string id, string accountKid, Func<T, string> owner)
    {
        if (!items.TryGetValue(id, out var item))
        {
            throw new ProblemException(404, "malformed", "no such resource");
        }

        if (owner(item) != accountKid)
        {
            throw new ProblemException(403, "unauthorized", "the resource belongs to another account");
        }

        return item;
    }

    public static HttpResponseMessage Json(HttpStatusCode status, JsonNode body) =>
        new(status) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Problem(int status, string type, string detail) =>
        new((HttpStatusCode)status)
        {
            Content = new StringContent(new JsonObject
            {
                ["type"] = type.StartsWith("urn:", StringComparison.Ordinal) ? type : "urn:ietf:params:acme:error:" + type,
                ["detail"] = detail,
                ["status"] = status,
            }.ToJsonString(), Encoding.UTF8, "application/problem+json"),
        };

    private sealed class ProblemException(int status, string type, string detail) : Exception(detail)
    {
        public int Status { get; } = status;

        public string Type { get; } = type;

        public string Detail { get; } = detail;
    }

    private sealed class Account(string kid, string thumbprint, JsonNode jwk, string status, string? eabKeyId)
    {
        public string Kid { get; } = kid;

        public string Thumbprint { get; } = thumbprint;

        public JsonNode Jwk { get; } = jwk;

        public string Status { get; set; } = status;

        public string? EabKeyId { get; } = eabKeyId;
    }

    private sealed class Order(int number, string accountKid)
    {
        public int Number { get; } = number;

        public string AccountKid { get; } = accountKid;

        public string Status { get; set; } = "pending";

        public string? Error { get; set; }

        public string? Replaces { get; set; }

        public List<string> Identifiers { get; } = [];

        public List<int> AuthorizationIds { get; } = [];

        public byte[]? CsrDer { get; set; }

        public PublicKey? CsrPublicKey { get; set; }

        public int ProcessingLooksLeft { get; set; }
    }

    private sealed class Authorization(int id, string accountKid, string identifier, bool wildcard)
    {
        public int Id { get; } = id;

        public string AccountKid { get; } = accountKid;

        public string Identifier { get; } = identifier;

        public bool Wildcard { get; } = wildcard;

        public string Status { get; set; } = "pending";

        public List<Challenge> Challenges { get; } = [];
    }

    private sealed class Challenge(int id, int authorizationId, string type, string token, Authorization authorization)
    {
        public int Id { get; } = id;

        public int AuthorizationId { get; } = authorizationId;

        public string Type { get; } = type;

        public string Token { get; } = token;

        public Authorization Authorization { get; } = authorization;

        public string Status { get; set; } = "pending";

        public JsonNode? Error { get; set; }

        public int Looks { get; set; }
    }

    /// <summary>A parsed ACME request (RFC 8555 section 6.2): flattened JWS with <c>nonce</c>, <c>url</c> and either <c>jwk</c> or <c>kid</c>.</summary>
    private sealed class Jws
    {
        private string _protected = "";
        private string _payload = "";
        private string _signature = "";

        public string? Nonce { get; private set; }

        public string? Url { get; private set; }

        public string? Kid { get; private set; }

        public JsonNode? Jwk { get; private set; }

        public string? JwkThumbprint { get; private set; }

        public JsonNode? Payload { get; private set; }

        public static Jws Parse(string body)
        {
            try
            {
                var envelope = JsonNode.Parse(body)!.AsObject();
                var jws = new Jws
                {
                    _protected = envelope["protected"]!.GetValue<string>(),
                    _payload = envelope["payload"]!.GetValue<string>(),
                    _signature = envelope["signature"]!.GetValue<string>(),
                };
                var header = JsonNode.Parse(Base64Url.DecodeFromChars(jws._protected))!.AsObject();
                if (header["alg"]?.GetValue<string>() != "ES256")
                {
                    throw new ProblemException(400, "badSignatureAlgorithm", "only ES256 account keys are supported by the mock CA");
                }

                jws.Nonce = header["nonce"]?.GetValue<string>();
                jws.Url = header["url"]?.GetValue<string>();
                jws.Kid = header["kid"]?.GetValue<string>();
                jws.Jwk = header["jwk"]?.DeepClone();
                if (jws.Jwk is JsonObject jwk)
                {
                    // RFC 7638: members in lexicographic order, no whitespace.
                    string canonical = $"{{\"crv\":\"{jwk["crv"]}\",\"kty\":\"{jwk["kty"]}\",\"x\":\"{jwk["x"]}\",\"y\":\"{jwk["y"]}\"}}";
                    jws.JwkThumbprint = Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
                    if (!jws.Verify(jwk))
                    {
                        throw new ProblemException(400, "malformed", "JWS verification error");
                    }
                }

                // POST-as-GET has the empty payload.
                jws.Payload = jws._payload.Length == 0 ? null : JsonNode.Parse(Base64Url.DecodeFromChars(jws._payload));
                return jws;
            }
            catch (Exception ex) when (ex is JsonException or NullReferenceException or InvalidOperationException or FormatException)
            {
                throw new ProblemException(400, "malformed", "unparsable JWS: " + ex.Message);
            }
        }

        public bool Verify(JsonNode key)
        {
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = Base64Url.DecodeFromChars(key["x"]!.GetValue<string>()), Y = Base64Url.DecodeFromChars(key["y"]!.GetValue<string>()) },
            });
            return ecdsa.VerifyData(Encoding.ASCII.GetBytes(_protected + "." + _payload), Base64Url.DecodeFromChars(_signature), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }
}

/// <summary>Validators for <see cref="MockAcmeServer.Validator"/> that check what the client really published, as a CA would.</summary>
internal static class MockChallengeValidators
{
    /// <summary>DNS-01: valid when a TXT record at <c>_acme-challenge.&lt;identifier&gt;</c> carries the digest of the key authorization.</summary>
    public static Func<MockChallenge, ChallengeVerdict> Dns(RecordingDnsProvider dns) => challenge =>
    {
        if (challenge.Type != "dns-01")
        {
            return ChallengeVerdict.Invalid("malformed", $"the {challenge.Type} challenge was answered, this test publishes DNS records only");
        }

        string name = "_acme-challenge." + challenge.Identifier;
        var values = dns.ValuesAt(name);
        return values.Contains(challenge.DnsTxtValue)
            ? ChallengeVerdict.Valid
            : ChallengeVerdict.Invalid("unauthorized", values.Count == 0
                ? $"No TXT record found at {name}"
                : $"Incorrect TXT record \"{values[0]}\" (and {values.Count - 1} more) found at {name}");
    };

    /// <summary>HTTP-01: valid when the published answer for the token is exactly the key authorization.</summary>
    public static Func<MockChallenge, ChallengeVerdict> Http(RecordingHttpPublisher http) => challenge =>
    {
        if (challenge.Type != "http-01")
        {
            return ChallengeVerdict.Invalid("malformed", $"the {challenge.Type} challenge was answered, this test publishes HTTP answers only");
        }

        string? answer = http.AnswerFor(challenge.Token);
        return answer == challenge.KeyAuthorization
            ? ChallengeVerdict.Valid
            : ChallengeVerdict.Invalid("unauthorized", answer is null
                ? $"Invalid response from http://{challenge.Identifier}/.well-known/acme-challenge/{challenge.Token}: 404"
                : $"The key authorization file from the server did not match this challenge \"{challenge.KeyAuthorization}\" != \"{answer}\"");
    };
}
