using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>What a webhook receiver was sent: the request exactly as it arrived.</summary>
internal sealed record ReceivedWebhook(IReadOnlyDictionary<string, string> Headers, byte[] Body, string ContentType)
{
    public string Id => Headers.GetValueOrDefault("webhook-id", "");
    public string Text => Encoding.UTF8.GetString(Body);
}

/// <summary>
/// A real HTTP server on an ephemeral loopback port that plays a customer's webhook receiver: it records every request (headers and the body bytes) and answers with the status a test scripts. The
/// runtime's own HTTP stack (the SSRF guard, signing, no redirects) talks to it over a real socket.
/// </summary>
internal sealed class WebhookReceiver : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly ConcurrentQueue<ReceivedWebhook> _requests = new();
    private readonly Queue<int> _script = new();
    private readonly SemaphoreSlim _arrivals = new(0);
    private int _last = 200;
    private int _active, _maxActive;

    private WebhookReceiver(WebApplication app, int port)
    {
        _app = app;
        Port = port;
    }

    public int Port { get; }

    public string Url => $"http://127.0.0.1:{Port}/hook";

    public IReadOnlyCollection<ReceivedWebhook> Requests => _requests;

    /// <summary>The most requests that were being answered at the same moment.</summary>
    public int MaxConcurrent => Volatile.Read(ref _maxActive);

    /// <summary>When set, a request waits for it before it is answered (to hold an attempt in flight).</summary>
    public Func<Task>? Gate { get; set; }

    public static async Task<WebhookReceiver> StartAsync()
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseKestrel(o => o.Listen(IPAddress.Loopback, 0));
        WebApplication app = builder.Build();
        WebhookReceiver? receiver = null;
        app.Run(async context =>
        {
            await receiver!.HandleAsync(context);
        });
        await app.StartAsync();
        string address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        receiver = new WebhookReceiver(app, new Uri(address).Port);
        return receiver;
    }

    /// <summary>Answers the next requests with these statuses, in order; the last one repeats.</summary>
    public void Respond(params int[] statuses)
    {
        lock (_script)
        {
            foreach (int s in statuses)
            {
                _script.Enqueue(s);
            }
        }
    }

    /// <summary>Completes when <paramref name="count"/> requests have arrived in all.</summary>
    public async Task WaitForRequestsAsync(int count, TimeSpan? timeout = null)
    {
        DateTime deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(30));
        while (_requests.Count < count)
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException($"{_requests.Count} of {count} webhook requests arrived");
            }

            await _arrivals.WaitAsync(TimeSpan.FromMilliseconds(50));
        }
    }

    private async Task HandleAsync(HttpContext context)
    {
        int active = Interlocked.Increment(ref _active);
        int seen;
        while ((seen = Volatile.Read(ref _maxActive)) < active && Interlocked.CompareExchange(ref _maxActive, active, seen) != seen)
        {
        }

        try
        {
            using var ms = new MemoryStream();
            await context.Request.Body.CopyToAsync(ms);
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in context.Request.Headers)
            {
                headers[h.Key] = h.Value.ToString();
            }

            _requests.Enqueue(new ReceivedWebhook(headers, ms.ToArray(), context.Request.ContentType ?? ""));
            _arrivals.Release();
            if (Gate is { } gate)
            {
                await gate().WaitAsync(context.RequestAborted);
            }

            int status;
            lock (_script)
            {
                status = _script.Count > 0 ? _last = _script.Dequeue() : _last;
            }

            context.Response.StatusCode = status;
            await context.Response.WriteAsync("ok");
        }
        finally
        {
            Interlocked.Decrement(ref _active);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}

/// <summary>
/// A verifier of Standard Webhooks signatures written from the specification (https://www.standardwebhooks.com/): the signed content is <c>{webhook-id}.{webhook-timestamp}.{body}</c>, the key is the base64
/// part of a <c>whsec_</c> secret, the signature is the base64 of HMAC-SHA256 and the header lists <c>v1,{signature}</c> entries separated by spaces. It shares no code with the signer under test.
/// </summary>
internal static class IndependentWebhookVerifier
{
    public static bool Verify(ReceivedWebhook request, IEnumerable<string> secrets, DateTimeOffset now, TimeSpan tolerance, out string reason)
    {
        reason = "";
        if (!request.Headers.TryGetValue("webhook-id", out string? id) || !request.Headers.TryGetValue("webhook-timestamp", out string? timestamp) || !request.Headers.TryGetValue("webhook-signature", out string? signature))
        {
            reason = "a header is missing";
            return false;
        }

        if (!long.TryParse(timestamp, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long seconds))
        {
            reason = "the timestamp is not a number";
            return false;
        }

        if (Math.Abs((now - DateTimeOffset.FromUnixTimeSeconds(seconds)).TotalSeconds) > tolerance.TotalSeconds)
        {
            reason = "the timestamp is outside the tolerance";
            return false;
        }

        byte[] prefix = Encoding.UTF8.GetBytes($"{id}.{timestamp}.");
        byte[] signed = [.. prefix, .. request.Body];
        string[] offered = signature.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (string secret in secrets)
        {
            byte[] key = Convert.FromBase64String(secret.StartsWith("whsec_", StringComparison.Ordinal) ? secret["whsec_".Length..] : secret);
            string expected = "v1," + Convert.ToBase64String(HMACSHA256.HashData(key, signed));
            foreach (string candidate in offered)
            {
                if (candidate.Length == expected.Length && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(candidate), Encoding.ASCII.GetBytes(expected)))
                {
                    return true;
                }
            }
        }

        reason = "no signature matches";
        return false;
    }
}
