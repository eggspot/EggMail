using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Mta.Core;
using Mta.Storage;

namespace Mta.Host.Domains;

/// <summary>
/// Serves the MTA-STS policy file (RFC 8461) of the registered sending domains on the dashboard listeners: a request whose <c>Host</c> is
/// <c>mta-sts.&lt;registered domain&gt;</c> and whose path is <c>/.well-known/mta-sts.txt</c> gets the policy; every other path on such a host is 404 (the
/// dashboard is not offered under that name). A request for the policy path on a host of an unregistered domain is 404 as well. Nothing is served unless
/// <c>Domains:MtaStsMode</c> is <c>Testing</c> or <c>Enforce</c>.
/// <para>The HTTPS certificate the listener presents for that name has to cover <c>mta-sts.&lt;domain&gt;</c> (a SAN or a wildcard): senders refuse the policy otherwise.</para>
/// </summary>
public sealed class MtaStsPolicyMiddleware
{
    private const string HostPrefix = "mta-sts.";
    private static readonly TimeSpan CacheTime = TimeSpan.FromSeconds(30);

    private readonly RequestDelegate _next;
    private readonly IStorage _storage;
    private readonly IClock _clock;
    private readonly byte[] _policy;
    private readonly SemaphoreSlim _refresh = new(1, 1);
    private volatile NameSnapshot? _snapshot;

    private sealed record NameSnapshot(HashSet<string> Names, DateTimeOffset LoadedAt);

    public MtaStsPolicyMiddleware(RequestDelegate next, IStorage storage, DomainRecordOptions options, IClock clock)
    {
        _next = next;
        _storage = storage;
        _clock = clock;
        _policy = Encoding.UTF8.GetBytes(MtaStsPolicyDocument.Render(options));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        string host = context.Request.Host.Host.TrimEnd('.').ToLowerInvariant();
        bool policyPath = context.Request.Path.Equals(MtaStsPolicyDocument.WellKnownPath, StringComparison.Ordinal);
        if (!host.StartsWith(HostPrefix, StringComparison.Ordinal) || host.Length == HostPrefix.Length)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (!await IsRegisteredAsync(host[HostPrefix.Length..], context.RequestAborted).ConfigureAwait(false))
        {
            if (policyPath)
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;   // no policy for a domain that is not ours (the SPA fallback must not answer it with HTML)
                return;
            }

            await _next(context).ConfigureAwait(false);
            return;
        }

        if (!policyPath || !(HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method)))
        {
            context.Response.StatusCode = policyPath ? StatusCodes.Status405MethodNotAllowed : StatusCodes.Status404NotFound;
            return;
        }

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "text/plain; charset=utf-8";
        context.Response.Headers.CacheControl = "public, max-age=300";
        context.Response.ContentLength = _policy.Length;
        if (HttpMethods.IsGet(context.Request.Method))
        {
            await context.Response.Body.WriteAsync(_policy, context.RequestAborted).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Whether <paramref name="domain"/> is registered by any tenant. The registered names are read as one list at most every 30 seconds (one request at a time
    /// does the reading), so anonymous requests with invented host names never reach the database one by one. A domain added a moment ago is served within 30 seconds.
    /// </summary>
    private async Task<bool> IsRegisteredAsync(string domain, CancellationToken ct)
    {
        NameSnapshot? snapshot = _snapshot;
        if (snapshot is null || _clock.UtcNow - snapshot.LoadedAt >= CacheTime)
        {
            await _refresh.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                snapshot = _snapshot;
                if (snapshot is null || _clock.UtcNow - snapshot.LoadedAt >= CacheTime)
                {
                    var domains = await _storage.Config.GetDomainsAsync(null, ct).ConfigureAwait(false);
                    snapshot = new NameSnapshot(domains.Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase), _clock.UtcNow);
                    _snapshot = snapshot;
                }
            }
            finally
            {
                _refresh.Release();
            }
        }

        return snapshot.Names.Contains(domain);
    }
}

public static class MtaStsPolicyServingExtensions
{
    /// <summary>Adds <see cref="MtaStsPolicyMiddleware"/> when <c>Domains:MtaStsMode</c> turns the policy on; otherwise adds nothing.</summary>
    public static IApplicationBuilder UseMtaStsPolicy(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.ApplicationServices.GetRequiredService<DomainRecordOptions>().MtaStsEnabled ? app.UseMiddleware<MtaStsPolicyMiddleware>() : app;
    }
}
