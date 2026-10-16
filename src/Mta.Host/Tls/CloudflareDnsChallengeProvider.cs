using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Mta.Host.Tls;

/// <summary>
/// DNS-01 challenge records through the Cloudflare API (first provider, decision 19). The token needs Zone:Read and DNS:Edit.
/// Requests are retried (three attempts) when Cloudflare rate-limits (429, honouring a short <c>Retry-After</c>), answers 5xx or does not answer; a longer
/// <c>Retry-After</c> ends the call with an <see cref="AcmeException"/> that carries it. Creating a record Cloudflare already holds (an identical record left by an
/// earlier order, or created by a request whose answer was lost) adopts that record. The token is never part of any message.
/// </summary>
public sealed class CloudflareDnsChallengeProvider : IDnsChallengeProvider
{
    /// <summary>Attempts per request: the first and two retries.</summary>
    internal const int MaxAttempts = 3;

    /// <summary>A <c>Retry-After</c> up to this is waited for inside the call; a longer one ends the call (the renewal back-off then waits for it).</summary>
    internal static readonly TimeSpan MaxRetryAfterWait = TimeSpan.FromSeconds(30);

    /// <summary>Cloudflare answers are a few KB; nothing larger is read.</summary>
    private const int MaxAnswerBytes = 1024 * 1024;

    /// <summary>Pages of existing records looked through when adopting an identical record (100 records each).</summary>
    private const int MaxRecordPages = 20;

    private readonly HttpClient _http;
    private readonly string _token;
    private readonly Func<TimeSpan, CancellationToken, Task> _pause;
    private readonly ConcurrentDictionary<string, string> _zoneCache = new(StringComparer.OrdinalIgnoreCase);

    /// <param name="pause">How the provider waits between attempts (<see cref="Task.Delay(TimeSpan, CancellationToken)"/>); tests pass one that records the wait.</param>
    public CloudflareDnsChallengeProvider(HttpClient http, string apiToken, string baseUrl = "https://api.cloudflare.com/client/v4/", Func<TimeSpan, CancellationToken, Task>? pause = null)
    {
        // A token pasted into an environment variable or a file brings its line end along; one with spaces or non-ASCII characters cannot be sent at all, and the HTTP stack
        // would then put the whole header, token included, into its exception message.
        string token = apiToken?.Trim() ?? "";
        if (token.Length == 0 || token.Any(c => c is <= ' ' or > '~'))
        {
            throw new ArgumentException("The Cloudflare API token is empty or contains characters that cannot be sent in an HTTP header (spaces, line breaks, non-ASCII): check Acme:CloudflareApiToken or the token file.", nameof(apiToken));
        }

        _http = http;
        _token = token;
        _pause = pause ?? Task.Delay;
        _http.BaseAddress = new Uri(baseUrl.EndsWith('/') ? baseUrl : baseUrl + "/");
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    public async ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken ct)
    {
        string name = fqdn.Trim().TrimEnd('.').ToLowerInvariant();
        string zone = await FindZoneAsync(name, ct).ConfigureAwait(false);
        string path = $"zones/{Segment(zone)}/dns_records";
        using var created = await SendAsync(HttpMethod.Post, path, new { type = "TXT", name, content = value, ttl = 60 }, "create the TXT record", ct).ConfigureAwait(false);
        if (created.Succeeded)
        {
            return $"{zone}/{ResultId(created, "create the TXT record")}";
        }

        if (created.HasErrorCode(81057) || created.HasErrorCode(81058))
        {
            // Cloudflare holds this record already: left behind by an order that could not clean up, or created by an attempt whose answer never reached us. Its owner is
            // this order's own token (the value is derived from the token and the account key), so it is ours to use and to delete afterwards.
            string? existing = await FindRecordAsync(zone, name, value, ct).ConfigureAwait(false);
            if (existing is not null)
            {
                return $"{zone}/{existing}";
            }
        }

        if (created.Status is HttpStatusCode.NotFound or HttpStatusCode.Forbidden)
        {
            // The zone was deleted or re-created, or the token lost access to it since it was looked up: look it up again next time instead of failing with a stale id for ever.
            foreach (var entry in _zoneCache.Where(e => e.Value == zone))
            {
                _zoneCache.TryRemove(entry.Key, out _);
            }
        }

        throw created.Failure("create the TXT record");
    }

    public async ValueTask DeleteTxtAsync(string handle, CancellationToken ct)
    {
        int slash = handle.IndexOf('/');
        if (slash <= 0 || slash == handle.Length - 1)
        {
            throw new AcmeException("Cloudflare: the TXT record handle is damaged, nothing was deleted.");
        }

        using var deleted = await SendAsync(HttpMethod.Delete, $"zones/{Segment(handle[..slash])}/dns_records/{Segment(handle[(slash + 1)..])}", null, "delete the TXT record", ct).ConfigureAwait(false);
        // Already gone (an earlier attempt whose answer was lost, or removed by hand) is as good as deleted.
        if (!deleted.Succeeded && deleted.Status != HttpStatusCode.NotFound)
        {
            throw deleted.Failure("delete the TXT record");
        }
    }

    private async Task<string> FindZoneAsync(string name, CancellationToken ct)
    {
        if (_zoneCache.TryGetValue(name, out var known))
        {
            return known;
        }

        string[] labels = name.Split('.');
        // A label that starts with an underscore (_acme-challenge) is a service label, never the name of a zone: asking for it would cost a request that cannot succeed.
        for (int i = labels[0].StartsWith('_') ? 1 : 0; i < labels.Length - 1; i++)
        {
            string candidate = string.Join('.', labels.Skip(i));
            if (_zoneCache.TryGetValue(candidate, out var cached))
            {
                _zoneCache[name] = cached;
                return cached;
            }

            using var answer = await SendAsync(HttpMethod.Get, $"zones?name={Uri.EscapeDataString(candidate)}&status=active", null, "look up the zone", ct).ConfigureAwait(false);
            if (!answer.Succeeded)
            {
                throw answer.Failure("look up the zone", " Check that Acme:CloudflareApiToken can read zones (Zone:Read) and edit DNS (DNS:Edit) for this domain.");
            }

            if (answer.Result is { ValueKind: JsonValueKind.Array } result)
            {
                foreach (var zone in result.EnumerateArray())
                {
                    // The filter is an exact match; check anyway, since the zone found is where records are written.
                    if (zone.ValueKind == JsonValueKind.Object && zone.TryGetProperty("name", out var zoneName) && string.Equals(StringOf(zoneName), candidate, StringComparison.OrdinalIgnoreCase)
                        && zone.TryGetProperty("id", out var id) && StringOf(id) is { } zoneId && IsSafeId(zoneId))
                    {
                        _zoneCache[candidate] = zoneId;
                        _zoneCache[name] = zoneId;
                        return zoneId;
                    }
                }
            }
        }

        throw new AcmeException($"Cloudflare: no active zone found for {name} (does the API token have access?)");
    }

    /// <summary>The id of the TXT record with this name and value, looking through the pages of the zone's records of that name.</summary>
    private async Task<string?> FindRecordAsync(string zone, string name, string value, CancellationToken ct)
    {
        for (int page = 1; page <= MaxRecordPages; page++)
        {
            using var answer = await SendAsync(HttpMethod.Get, $"zones/{Segment(zone)}/dns_records?type=TXT&name={Uri.EscapeDataString(name)}&per_page=100&page={page}", null, "list the TXT records", ct).ConfigureAwait(false);
            if (!answer.Succeeded)
            {
                throw answer.Failure("list the TXT records");
            }

            if (answer.Result is { ValueKind: JsonValueKind.Array } records)
            {
                foreach (var record in records.EnumerateArray())
                {
                    // TXT content is returned in double quotes.
                    if (record.ValueKind == JsonValueKind.Object && record.TryGetProperty("content", out var content) && StringOf(content)?.Trim('"') == value
                        && record.TryGetProperty("id", out var id) && StringOf(id) is { } recordId && IsSafeId(recordId))
                    {
                        return recordId;
                    }
                }
            }

            if (answer.TotalPages is not { } total || page >= total)
            {
                return null;
            }
        }

        return null;
    }

    private string ResultId(Answer answer, string what) =>
        answer.Result is { ValueKind: JsonValueKind.Object } result && result.TryGetProperty("id", out var id) && StringOf(id) is { } text && IsSafeId(text)
            ? text
            : throw new AcmeException($"Cloudflare: could not {what}: the answer has no record id.");

    /// <summary>The text of a JSON string, null for any other kind of value (an id that is a number is as unusable as one that is missing).</summary>
    private static string? StringOf(JsonElement element) => element.ValueKind == JsonValueKind.String ? element.GetString() : null;

    /// <summary>Cloudflare ids are 32 hexadecimal digits; anything else would change the path of the next request.</summary>
    private static bool IsSafeId(string? id) => id is { Length: > 0 and <= 64 } && id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    private static string Segment(string id) => IsSafeId(id) ? id : throw new AcmeException("Cloudflare: an id in the answer is not usable.");

    // ----------------------------------------------------------------------------------------------------------------------------------

    private async Task<Answer> SendAsync(HttpMethod method, string relativeUrl, object? body, string what, CancellationToken ct)
    {
        for (int attempt = 1; ; attempt++)
        {
            Answer? answer = null;
            string? networkProblem = null;
            try
            {
                using var request = new HttpRequestMessage(method, relativeUrl);
                if (body is not null)
                {
                    request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
                }

                // Headers first: the body is read by hand up to MaxAnswerBytes; HttpClient would otherwise buffer all of it before the cap could apply.
                using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                answer = await Answer.ReadAsync(response, this, ct).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                networkProblem = Redact(ex.Message);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                networkProblem = "no answer in time";
            }

            if (answer is not null)
            {
                bool limited = answer.Status == HttpStatusCode.TooManyRequests;
                if (!limited && (int)answer.Status < 500)
                {
                    return answer;
                }

                if (attempt >= MaxAttempts)
                {
                    return answer;
                }

                TimeSpan wait = answer.RetryAfter ?? BackoffBeforeAttempt(attempt + 1);
                if (wait > MaxRetryAfterWait)
                {
                    // Waiting that long here would hold the order (and its lease) for nothing: report it with the wait, the renewal back-off honours it.
                    return answer.WithLongWait(wait);
                }

                answer.Dispose();
                await _pause(wait < TimeSpan.Zero ? TimeSpan.Zero : wait, ct).ConfigureAwait(false);
                continue;
            }

            if (attempt >= MaxAttempts)
            {
                throw new AcmeException($"Cloudflare: could not {what}: {networkProblem}", transient: true);
            }

            await _pause(BackoffBeforeAttempt(attempt + 1), ct).ConfigureAwait(false);
        }
    }

    /// <summary>One second before the second attempt, two before the third.</summary>
    private static TimeSpan BackoffBeforeAttempt(int attempt) => TimeSpan.FromSeconds(1 << Math.Min(attempt - 2, 4));

    private string Redact(string text) => text.Replace(_token, "[token]", StringComparison.Ordinal);

    /// <summary>What Cloudflare answered, read once: status, the envelope's parts and the errors it lists.</summary>
    private sealed class Answer : IDisposable
    {
        private readonly JsonDocument? _document;
        private readonly CloudflareDnsChallengeProvider _owner;
        private readonly TimeSpan? _longWait;

        private Answer(HttpStatusCode status, JsonDocument? document, TimeSpan? retryAfter, CloudflareDnsChallengeProvider owner, TimeSpan? longWait = null)
        {
            Status = status;
            _document = document;
            RetryAfter = retryAfter;
            _owner = owner;
            _longWait = longWait;
        }

        public HttpStatusCode Status { get; }

        public TimeSpan? RetryAfter { get; }

        /// <summary>The HTTP status is a success and the envelope does not say otherwise.</summary>
        public bool Succeeded => (int)Status is >= 200 and < 300 && _document is not null && Root.ValueKind == JsonValueKind.Object
            && (!Root.TryGetProperty("success", out var success) || success.ValueKind != JsonValueKind.False);

        private JsonElement Root => _document!.RootElement;

        public JsonElement? Result => _document is not null && Root.ValueKind == JsonValueKind.Object && Root.TryGetProperty("result", out var result) ? result : null;

        public int? TotalPages => _document is not null && Root.ValueKind == JsonValueKind.Object && Root.TryGetProperty("result_info", out var info)
            && info.ValueKind == JsonValueKind.Object && info.TryGetProperty("total_pages", out var pages) && pages.TryGetInt32(out int n) ? n : null;

        public bool HasErrorCode(int code) => Errors().Any(e => e.Code == code);

        public static async Task<Answer> ReadAsync(HttpResponseMessage response, CloudflareDnsChallengeProvider owner, CancellationToken ct)
        {
            TimeSpan? retryAfter = null;
            if (response.Headers.RetryAfter is { } header)
            {
                retryAfter = header.Delta ?? (header.Date is { } date ? date - DateTimeOffset.UtcNow : null);
            }

            JsonDocument? document = null;
            await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int read;
            while ((read = await stream.ReadAsync(chunk, ct).ConfigureAwait(false)) > 0)
            {
                buffer.Write(chunk, 0, read);
                if (buffer.Length > MaxAnswerBytes)
                {
                    return new Answer(response.StatusCode, null, retryAfter, owner);
                }
            }

            try
            {
                document = JsonDocument.Parse(buffer.ToArray());
            }
            catch (JsonException)
            {
                // An HTML error page of a proxy, an empty body, a cut-off answer: the status says what there is to say.
            }

            return new Answer(response.StatusCode, document, retryAfter, owner);
        }

        public Answer WithLongWait(TimeSpan wait) => new(Status, _document, RetryAfter, _owner, wait);

        /// <summary>The failure as an exception: what was attempted, Cloudflare's status and its error codes with their messages (never the token).</summary>
        public AcmeException Failure(string what, string hint = "")
        {
            string detail = string.Join("; ", Errors().Take(3).Select(e => e.Code is { } code ? $"{code}: {e.Message}" : e.Message));
            bool envelope = _document is not null && Root.ValueKind == JsonValueKind.Object;
            string text = $"Cloudflare: could not {what} (HTTP {(int)Status}" + (detail.Length == 0 ? (envelope ? "" : ", the answer was not a Cloudflare JSON envelope") : $", {detail}") + ")." + hint;
            if (Status == HttpStatusCode.TooManyRequests && _longWait is { } wait)
            {
                text += $" Cloudflare asks to wait {wait.TotalSeconds:0} seconds.";
            }

            return new AcmeException(_owner.Redact(text), transient: (int)Status >= 500 || Status == HttpStatusCode.TooManyRequests, retryAfter: RetryAfter);
        }

        private IEnumerable<(int? Code, string Message)> Errors()
        {
            if (_document is null || Root.ValueKind != JsonValueKind.Object || !Root.TryGetProperty("errors", out var errors) || errors.ValueKind != JsonValueKind.Array)
            {
                yield break;
            }

            foreach (var error in errors.EnumerateArray())
            {
                if (error.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                int? code = error.TryGetProperty("code", out var c) && c.TryGetInt32(out int n) ? n : null;
                string message = error.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString()! : "";
                yield return (code, Sanitize(message));
            }
        }

        /// <summary>Printable ASCII only, at most 200 characters: the text ends up in logs and in the dashboard.</summary>
        private static string Sanitize(string text)
        {
            var clean = new string([.. text.Select(c => c is >= ' ' and <= '~' ? c : '?')]);
            return clean.Length <= 200 ? clean : clean[..200];
        }

        public void Dispose() => _document?.Dispose();
    }
}
