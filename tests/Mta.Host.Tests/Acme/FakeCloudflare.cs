using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace Mta.Host.Tests.Acme;

/// <summary>One request the fake Cloudflare saw.</summary>
internal sealed record CloudflareRequest(string Method, string Route, string PathAndQuery, string? Authorization, JsonNode? Body, int Status);

/// <summary>What a token may do (Cloudflare API tokens carry permissions and zone scope).</summary>
internal sealed record CloudflareToken(bool ReadZones = true, bool EditDns = true, IReadOnlySet<string>? OnlyZones = null);

/// <summary>
/// The parts of api.cloudflare.com v4 that DNS-01 uses, as an in-process HTTP transport: <c>GET /zones?name=&amp;status=</c> (paged), <c>POST /zones/{id}/dns_records</c>,
/// <c>GET /zones/{id}/dns_records?type=&amp;name=</c> (paged) and <c>DELETE /zones/{id}/dns_records/{id}</c>, with Cloudflare's envelope
/// (<c>success</c>, <c>errors[{code,message}]</c>, <c>result</c>, <c>result_info</c>), API tokens that carry permissions and a zone scope, TXT content returned in quotes,
/// several TXT values at one name, refusal of an identical record, and a record becoming visible to resolvers only after a propagation lag on a clock the test moves.
/// Error codes and statuses are those of Cloudflare's documentation and observed behaviour; real Cloudflare has quirks this does not know (see docs/testing-offline-coverage.md).
/// Anything can be scripted per route (rate limits with <c>Retry-After</c>, 5xx, HTML pages, damaged JSON, timeouts).
/// </summary>
internal sealed class FakeCloudflare : HttpMessageHandler
{
    public const string ValidToken = "cf-test-token-0123456789abcdef";

    private readonly object _gate = new();
    private readonly List<Zone> _zones = [];
    private readonly List<CloudflareRequest> _requests = [];
    private readonly Dictionary<string, List<(Func<HttpRequestMessage, HttpResponseMessage>? Response, Exception? Throw, int Times)>> _scripts = [];
    private readonly Func<DateTimeOffset> _now;
    private readonly Dictionary<string, List<(Func<HttpResponseMessage, HttpResponseMessage> Transform, int Times)>> _after = [];
    private readonly Dictionary<string, int> _routeCounts = [];
    private readonly Dictionary<(string Route, int Nth), Func<HttpResponseMessage>> _nth = [];
    private int _ids;

    public FakeCloudflare(Func<DateTimeOffset>? now = null)
    {
        _now = now ?? (() => DateTimeOffset.UtcNow);
        Tokens[ValidToken] = new CloudflareToken();
    }

    /// <summary>The API tokens that exist and what they may do.</summary>
    public Dictionary<string, CloudflareToken> Tokens { get; } = [];

    /// <summary>TXT content is returned wrapped in double quotes, as the API does when reading records.</summary>
    public bool QuoteTxtContent { get; set; } = true;

    /// <summary>How long after creation a record is visible to <see cref="ResolveTxt"/> (resolvers of the CA).</summary>
    public TimeSpan PropagationLag { get; set; }

    /// <summary>The page size zones and records are listed with when the client does not ask for one (Cloudflare: 20 for zones, 100 for records).</summary>
    public int ZonesPerPage { get; set; } = 20;

    public int RecordsPerPage { get; set; } = 100;

    /// <summary>The largest page the server gives however much the client asks for (Cloudflare caps <c>per_page</c>).</summary>
    public int MaxPerPage { get; set; } = 5000;

    // ----------------------------------------------------------------------------------------------------------------------------------

    public string AddZone(string name, string status = "active")
    {
        lock (_gate)
        {
            string id = Id();
            _zones.Add(new Zone(id, name.ToLowerInvariant(), status));
            return id;
        }
    }

    public string ZoneId(string name)
    {
        lock (_gate)
        {
            return _zones.Single(z => z.Name == name).Id;
        }
    }

    /// <summary>A TXT (or other) record that exists in the zone already, as left by an earlier order or created by hand.</summary>
    public string AddRecord(string zoneName, string type, string name, string content)
    {
        lock (_gate)
        {
            var zone = _zones.Single(z => z.Name == zoneName);
            var record = new Record(Id(), type, name.ToLowerInvariant(), content, _now());
            zone.Records.Add(record);
            return record.Id;
        }
    }

    /// <summary>The records in the zone: (type, name, content as stored without quotes).</summary>
    public IReadOnlyList<(string Type, string Name, string Content, string Id)> RecordsIn(string zoneName)
    {
        lock (_gate)
        {
            return [.. _zones.Single(z => z.Name == zoneName).Records.Select(r => (r.Type, r.Name, r.Content, r.Id))];
        }
    }

    public int RecordCount
    {
        get
        {
            lock (_gate)
            {
                return _zones.Sum(z => z.Records.Count);
            }
        }
    }

    /// <summary>What a resolver of the CA sees for a TXT name right now: records older than <see cref="PropagationLag"/>.</summary>
    public IReadOnlyList<string> ResolveTxt(string name)
    {
        lock (_gate)
        {
            var now = _now();
            return [.. _zones.SelectMany(z => z.Records).Where(r => r.Type == "TXT" && r.Name == name.ToLowerInvariant() && r.CreatedAt + PropagationLag <= now).Select(r => r.Content)];
        }
    }

    public IReadOnlyList<CloudflareRequest> Requests
    {
        get
        {
            lock (_gate)
            {
                return [.. _requests];
            }
        }
    }

    public int Count(string route, string? method = null) => Requests.Count(r => r.Route == route && (method is null || r.Method == method));

    // ----------------------------------------------------------------------------------------------------------------------------------
    // Scripting

    /// <summary>The next <paramref name="times"/> requests to <paramref name="route"/> (<c>zones</c>, <c>records.list</c>, <c>records.create</c>, <c>records.delete</c>, or <c>*</c>) get this response.</summary>
    public void Respond(string route, Func<HttpRequestMessage, HttpResponseMessage> response, int times = 1)
    {
        lock (_gate)
        {
            Script(route).Add((response, null, times));
        }
    }

    /// <summary>The next <paramref name="times"/> requests fail like the network does (timeout, reset connection).</summary>
    public void Throw(string route, Exception exception, int times = 1)
    {
        lock (_gate)
        {
            Script(route).Add((null, exception, times));
        }
    }

    /// <summary>An error envelope with one error, as Cloudflare answers.</summary>
    public void Fail(string route, int status, int code, string message, int times = 1, int? retryAfterSeconds = null) =>
        Respond(route, _ =>
        {
            var response = Error(status, code, message);
            if (retryAfterSeconds is not null)
            {
                response.Headers.TryAddWithoutValidation("Retry-After", retryAfterSeconds.Value.ToString(CultureInfo.InvariantCulture));
            }

            return response;
        }, times);

    /// <summary>
    /// The next <paramref name="times"/> requests to <paramref name="route"/> are carried out and then answered with what <paramref name="transform"/> makes of the real
    /// answer: a request that took effect whose answer was lost (a gateway error, a reset connection).
    /// </summary>
    public void AfterApplying(string route, Func<HttpResponseMessage, HttpResponseMessage> transform, int times = 1)
    {
        lock (_gate)
        {
            (_after.TryGetValue(route, out var list) ? list : _after[route] = []).Add((transform, times));
        }
    }

    /// <summary>The <paramref name="nth"/> request (1-based, counted from now on) to <paramref name="route"/> gets this answer instead; the others are served normally.</summary>
    public void FailNth(string route, int nth, int status, int code, string message)
    {
        lock (_gate)
        {
            _nth[(route, nth + _routeCounts.GetValueOrDefault(route))] = () => Error(status, code, message);
        }
    }

    private List<(Func<HttpRequestMessage, HttpResponseMessage>? Response, Exception? Throw, int Times)> Script(string route) =>
        _scripts.TryGetValue(route, out var list) ? list : _scripts[route] = [];

    private (Func<HttpRequestMessage, HttpResponseMessage>? Response, Exception? Throw, int Times)? Take(string route)
    {
        if (!_scripts.TryGetValue(route, out var list) || list.Count == 0)
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

    // ----------------------------------------------------------------------------------------------------------------------------------
    // Transport

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string body = request.Content is null ? "" : request.Content.ReadAsStringAsync(cancellationToken).GetAwaiter().GetResult();
        lock (_gate)
        {
            string route = RouteOf(request);
            string? authorization = request.Headers.Authorization?.ToString();
            JsonNode? payload = body.Length == 0 ? null : TryParse(body);
            int number = _routeCounts[route] = _routeCounts.GetValueOrDefault(route) + 1;
            var scripted = Take(route) ?? Take("*");
            if (scripted is null && _nth.Remove((route, number), out var nthResponse))
            {
                var nthAnswer = nthResponse();
                _requests.Add(new CloudflareRequest(request.Method.Method, route, request.RequestUri!.PathAndQuery, authorization, payload, (int)nthAnswer.StatusCode));
                return Task.FromResult(nthAnswer);
            }

            if (scripted is { Throw: { } exception })
            {
                _requests.Add(new CloudflareRequest(request.Method.Method, route, request.RequestUri!.PathAndQuery, authorization, payload, -1));
                throw exception;
            }

            var response = scripted is { Response: { } make } ? make(request) : Handle(request, route, authorization, payload);
            if (scripted is null && _after.TryGetValue(route, out var afters) && afters.Count > 0)
            {
                var (transform, times) = afters[0];
                if (times <= 1)
                {
                    afters.RemoveAt(0);
                }
                else
                {
                    afters[0] = (transform, times - 1);
                }

                response = transform(response);
            }

            _requests.Add(new CloudflareRequest(request.Method.Method, route, request.RequestUri!.PathAndQuery, authorization, payload, (int)response.StatusCode));
            return Task.FromResult(response);
        }
    }

    private static JsonNode? TryParse(string body)
    {
        try
        {
            return JsonNode.Parse(body);
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }

    private static string RouteOf(HttpRequestMessage request)
    {
        string path = request.RequestUri!.AbsolutePath;
        const string Prefix = "/client/v4/";
        if (!path.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return "unknown";
        }

        string[] parts = path[Prefix.Length..].Split('/', StringSplitOptions.RemoveEmptyEntries);
        return (request.Method.Method, parts) switch
        {
            ("GET", ["zones"]) => "zones",
            ("GET", ["zones", _, "dns_records"]) => "records.list",
            ("POST", ["zones", _, "dns_records"]) => "records.create",
            ("DELETE", ["zones", _, "dns_records", _]) => "records.delete",
            _ => "unknown",
        };
    }

    private HttpResponseMessage Handle(HttpRequestMessage request, string route, string? authorization, JsonNode? payload)
    {
        if (authorization is null || !authorization.StartsWith("Bearer ", StringComparison.Ordinal))
        {
            return Error(400, 6111, "Invalid format for Authorization header");
        }

        string tokenText = authorization["Bearer ".Length..];
        if (!Tokens.TryGetValue(tokenText, out var token))
        {
            return Error(403, 9109, "Invalid access token");
        }

        var query = ParseQuery(request.RequestUri!.Query);
        string[] parts = request.RequestUri.AbsolutePath["/client/v4/".Length..].Split('/', StringSplitOptions.RemoveEmptyEntries);
        switch (route)
        {
            case "zones":
                return token.ReadZones ? ListZones(token, query) : Error(403, 9109, "Unauthorized to access requested resource");
            case "records.list":
                return ListRecords(token, parts[1], query);
            case "records.create":
                return CreateRecord(token, parts[1], payload);
            case "records.delete":
                return DeleteRecord(token, parts[1], parts[3]);
            default:
                return Error(404, 7000, "No route for that URI");
        }
    }

    private HttpResponseMessage ListZones(CloudflareToken token, Dictionary<string, string> query)
    {
        IEnumerable<Zone> zones = _zones.Where(z => token.OnlyZones is null || token.OnlyZones.Contains(z.Id));
        if (query.TryGetValue("name", out string? name))
        {
            zones = zones.Where(z => z.Name == name.ToLowerInvariant());
        }

        if (query.TryGetValue("status", out string? status))
        {
            zones = zones.Where(z => z.Status == status);
        }

        return Page(zones.Select(z => (JsonNode)new JsonObject { ["id"] = z.Id, ["name"] = z.Name, ["status"] = z.Status }).ToList(), query, ZonesPerPage, 50);
    }

    private HttpResponseMessage ListRecords(CloudflareToken token, string zoneId, Dictionary<string, string> query)
    {
        if (Check(token, zoneId, edit: false, out var zone) is { } refusal)
        {
            return refusal;
        }

        IEnumerable<Record> records = zone!.Records;
        if (query.TryGetValue("type", out string? type))
        {
            records = records.Where(r => r.Type == type);
        }

        if (query.TryGetValue("name", out string? name))
        {
            records = records.Where(r => r.Name == name.ToLowerInvariant());
        }

        if (query.TryGetValue("content", out string? content))
        {
            records = records.Where(r => r.Content == content);
        }

        return Page(records.Select(RecordJson).ToList(), query, RecordsPerPage, MaxPerPage);
    }

    private HttpResponseMessage CreateRecord(CloudflareToken token, string zoneId, JsonNode? payload)
    {
        if (Check(token, zoneId, edit: true, out var zone) is { } refusal)
        {
            return refusal;
        }

        if (payload is not JsonObject body || body["type"]?.GetValue<string>() is not { } type || body["name"]?.GetValue<string>() is not { } name || body["content"]?.GetValue<string>() is not { } content)
        {
            return Error(400, 9207, "Request body is invalid.");
        }

        string normalized = name.TrimEnd('.').ToLowerInvariant();
        if (!normalized.EndsWith(zone!.Name, StringComparison.Ordinal) || (normalized.Length > zone.Name.Length && normalized[^(zone.Name.Length + 1)] != '.'))
        {
            return Error(400, 9005, $"Content for A record is invalid. Name '{name}' is not within the zone");
        }

        if (zone.Records.Any(r => r.Type == type && r.Name == normalized && r.Content == content))
        {
            return Error(400, 81058, "An identical record already exists.");
        }

        var record = new Record(Id(), type, normalized, content, _now());
        zone.Records.Add(record);
        return Json(HttpStatusCode.OK, Envelope(RecordJson(record)));
    }

    private HttpResponseMessage DeleteRecord(CloudflareToken token, string zoneId, string recordId)
    {
        if (Check(token, zoneId, edit: true, out var zone) is { } refusal)
        {
            return refusal;
        }

        var record = zone!.Records.FirstOrDefault(r => r.Id == recordId);
        if (record is null)
        {
            return Error(404, 81044, "Record does not exist.");
        }

        zone.Records.Remove(record);
        return Json(HttpStatusCode.OK, Envelope(new JsonObject { ["id"] = recordId }));
    }

    /// <summary>Zone exists and the token may touch it; otherwise the refusal Cloudflare gives.</summary>
    private HttpResponseMessage? Check(CloudflareToken token, string zoneId, bool edit, out Zone? zone)
    {
        zone = _zones.FirstOrDefault(z => z.Id == zoneId);
        if (zone is null)
        {
            return Error(404, 7003, $"Could not route to /zones/{zoneId}/dns_records, perhaps your object identifier is invalid?");
        }

        if (token.OnlyZones is not null && !token.OnlyZones.Contains(zoneId))
        {
            return Error(403, 10000, "Authentication error");
        }

        if (edit && !token.EditDns)
        {
            return Error(403, 10000, "Authentication error");
        }

        return null;
    }

    private JsonNode RecordJson(Record record) => new JsonObject
    {
        ["id"] = record.Id,
        ["type"] = record.Type,
        ["name"] = record.Name,
        ["content"] = QuoteTxtContent && record.Type == "TXT" ? "\"" + record.Content + "\"" : record.Content,
        ["ttl"] = 60,
        ["proxied"] = false,
    };

    private static HttpResponseMessage Page(List<JsonNode> all, Dictionary<string, string> query, int defaultPerPage, int maxPerPage)
    {
        int perPage = Math.Min(maxPerPage, query.TryGetValue("per_page", out string? pp) && int.TryParse(pp, CultureInfo.InvariantCulture, out int parsed) && parsed > 0 ? parsed : defaultPerPage);
        int page = query.TryGetValue("page", out string? p) && int.TryParse(p, CultureInfo.InvariantCulture, out int parsedPage) && parsedPage > 0 ? parsedPage : 1;
        var slice = all.Skip((page - 1) * perPage).Take(perPage).ToList();
        var envelope = Envelope(new JsonArray([.. slice]));
        envelope["result_info"] = new JsonObject
        {
            ["page"] = page,
            ["per_page"] = perPage,
            ["count"] = slice.Count,
            ["total_count"] = all.Count,
            ["total_pages"] = Math.Max(1, (all.Count + perPage - 1) / perPage),
        };
        return Json(HttpStatusCode.OK, envelope);
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            string key = Uri.UnescapeDataString(eq < 0 ? pair : pair[..eq]);
            string value = eq < 0 ? "" : Uri.UnescapeDataString(pair[(eq + 1)..].Replace('+', ' '));
            result[key] = value;
        }

        return result;
    }

    private string Id() => (++_ids).ToString("x32", CultureInfo.InvariantCulture);

    public static JsonObject Envelope(JsonNode? result) => new() { ["success"] = true, ["errors"] = new JsonArray(), ["messages"] = new JsonArray(), ["result"] = result };

    public static HttpResponseMessage Error(int status, int code, string message) =>
        Json((HttpStatusCode)status, new JsonObject
        {
            ["success"] = false,
            ["errors"] = new JsonArray(new JsonObject { ["code"] = code, ["message"] = message }),
            ["messages"] = new JsonArray(),
            ["result"] = null,
        });

    public static HttpResponseMessage Json(HttpStatusCode status, JsonNode body) =>
        new(status) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Raw(HttpStatusCode status, string body, string contentType = "application/json") =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, contentType) };

    private sealed record Zone(string Id, string Name, string Status)
    {
        public List<Record> Records { get; } = [];
    }

    private sealed record Record(string Id, string Type, string Name, string Content, DateTimeOffset CreatedAt);
}
