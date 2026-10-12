using System.Net;
using System.Net.Http.Headers;
using System.Security.Authentication;

namespace Mta.Tls.MtaSts;

/// <summary>Why an MTA-STS policy fetch failed.</summary>
public enum MtaStsFetchFailure
{
    /// <summary>The fetch succeeded.</summary>
    None,

    /// <summary>The policy domain is not a valid host name.</summary>
    InvalidDomain,

    /// <summary>The connection or the request failed (DNS, refused, reset, blocked address).</summary>
    ConnectionFailed,

    /// <summary>The HTTPS certificate of <c>mta-sts.&lt;domain&gt;</c> failed validation.</summary>
    TlsValidationFailed,

    /// <summary>The overall fetch timeout elapsed.</summary>
    Timeout,

    /// <summary>The HTTP status was not 200.</summary>
    HttpStatus,

    /// <summary>The server answered with a redirect (never followed).</summary>
    Redirected,

    /// <summary>The content type is not <c>text/plain</c> (or has a non-UTF-8 charset).</summary>
    ContentType,

    /// <summary>The body exceeds the size limit.</summary>
    TooLarge,

    /// <summary>The body is not a valid MTA-STS policy.</summary>
    InvalidPolicy,
}

/// <summary>The result of one MTA-STS policy fetch.</summary>
/// <param name="Policy">The policy; non-null exactly when <paramref name="Failure"/> is <see cref="MtaStsFetchFailure.None"/>.</param>
/// <param name="Failure">The failure kind.</param>
/// <param name="Detail">A short human-readable detail (never contains response body text).</param>
public sealed record MtaStsFetchResult(MtaStsPolicy? Policy, MtaStsFetchFailure Failure, string? Detail)
{
    /// <summary>True when a policy was fetched and parsed.</summary>
    public bool IsSuccess => Policy is not null;

    /// <summary>The TLS-RPT result type matching <see cref="Failure"/>.</summary>
    public TlsResultType? ResultType => Failure switch
    {
        MtaStsFetchFailure.None => null,
        MtaStsFetchFailure.TlsValidationFailed => TlsResultType.StsWebpkiInvalid,
        MtaStsFetchFailure.InvalidPolicy => TlsResultType.StsPolicyInvalid,
        _ => TlsResultType.StsPolicyFetchError,
    };
}

/// <summary>Fetches the MTA-STS policy of a domain over HTTPS.</summary>
public interface IMtaStsPolicyFetcher
{
    /// <summary>Fetches <c>https://mta-sts.&lt;domain&gt;/.well-known/mta-sts.txt</c>. Does not throw on remote failures.</summary>
    ValueTask<MtaStsFetchResult> FetchAsync(string domain, CancellationToken cancellationToken = default);
}

/// <summary>Options for <see cref="MtaStsPolicyFetcher"/>.</summary>
public sealed class MtaStsFetchOptions
{
    /// <summary>Total time allowed for one fetch (connect, TLS, headers and body). Default 15 seconds.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>Maximum accepted body size in bytes. Default 64 KiB (RFC 8461 recommends not accepting larger policies).</summary>
    public int MaxBodyBytes { get; init; } = MtaStsPolicyParser.MaxPolicyBytes;

    /// <summary>The <c>User-Agent</c> header value.</summary>
    public string UserAgent { get; init; } = "EggMail-MTA-STS/1.0";

    /// <summary>
    /// Only applies when the fetcher creates its own handler: allow connections to loopback/private addresses.
    /// Off by default (SSRF guard); enable only for local testing.
    /// </summary>
    public bool AllowNonPublicAddresses { get; init; }
}

/// <summary>
/// The default <see cref="IMtaStsPolicyFetcher"/>. Accepts only HTTP 200 with <c>text/plain</c>, never follows
/// redirects, bounds time and size, and validates the HTTPS certificate with the platform trust store.
/// </summary>
public sealed class MtaStsPolicyFetcher : IMtaStsPolicyFetcher, IDisposable
{
    private readonly HttpClient _client;
    private readonly MtaStsFetchOptions _options;

    /// <summary>Creates a fetcher with its own hardened handler (no redirects, no proxy, public addresses only).</summary>
    public MtaStsPolicyFetcher(MtaStsFetchOptions? options = null)
        : this(null, options)
    {
    }

    /// <summary>
    /// Creates a fetcher over an injected handler (tests, custom egress). The handler must not follow redirects and must
    /// perform normal certificate validation; a response whose final request URI differs from the requested one is
    /// rejected as a redirect regardless.
    /// </summary>
    /// <param name="handler">The message handler, or <see langword="null"/> for the hardened default.</param>
    /// <param name="options">Fetch options.</param>
    public MtaStsPolicyFetcher(HttpMessageHandler? handler, MtaStsFetchOptions? options = null)
    {
        _options = options ?? new MtaStsFetchOptions();
        handler ??= SafeHttpHandler.Create(_options.Timeout, _options.AllowNonPublicAddresses);
        _client = new HttpClient(handler, disposeHandler: true) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
    }

    /// <inheritdoc />
    public async ValueTask<MtaStsFetchResult> FetchAsync(string domain, CancellationToken cancellationToken = default)
    {
        if (!DnsNames.TryNormalizeHost(domain, out string host))
        {
            return Fail(MtaStsFetchFailure.InvalidDomain, "invalid policy domain");
        }

        var uri = new Uri($"https://mta-sts.{host}/.well-known/mta-sts.txt");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.Timeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri) { Version = HttpVersion.Version11 };
            request.Headers.UserAgent.ParseAdd(_options.UserAgent);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/plain"));
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            return await ReadAsync(uri, response, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Fail(MtaStsFetchFailure.Timeout, "fetch timed out");
        }
        catch (HttpRequestException ex) when (IsTlsFailure(ex))
        {
            return Fail(MtaStsFetchFailure.TlsValidationFailed, "HTTPS certificate validation failed");
        }
        catch (HttpRequestException)
        {
            return Fail(MtaStsFetchFailure.ConnectionFailed, "request failed");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Anything else from the transport (I/O errors, malformed responses, disposed streams) is a failed fetch.
            return Fail(MtaStsFetchFailure.ConnectionFailed, "request failed");
        }
    }

    /// <inheritdoc cref="IDisposable.Dispose" />
    public void Dispose() => _client.Dispose();

    private async Task<MtaStsFetchResult> ReadAsync(Uri requested, HttpResponseMessage response, CancellationToken ct)
    {
        int status = (int)response.StatusCode;
        if (status is >= 300 and < 400)
        {
            return Fail(MtaStsFetchFailure.Redirected, $"redirect (HTTP {status}) is not allowed");
        }

        if (response.RequestMessage?.RequestUri is { } finalUri && finalUri != requested)
        {
            return Fail(MtaStsFetchFailure.Redirected, "request was redirected");
        }

        if (status != 200)
        {
            return Fail(MtaStsFetchFailure.HttpStatus, $"HTTP {status}");
        }

        MediaTypeHeaderValue? contentType = response.Content.Headers.ContentType;
        if (contentType is null || !string.Equals(contentType.MediaType, "text/plain", StringComparison.OrdinalIgnoreCase))
        {
            return Fail(MtaStsFetchFailure.ContentType, "content type is not text/plain");
        }

        string? charset = contentType.CharSet?.Trim('"');
        if (charset is not null
            && !charset.Equals("utf-8", StringComparison.OrdinalIgnoreCase)
            && !charset.Equals("us-ascii", StringComparison.OrdinalIgnoreCase))
        {
            return Fail(MtaStsFetchFailure.ContentType, "charset is not UTF-8");
        }

        if (response.Content.Headers.ContentLength is long declared && declared > _options.MaxBodyBytes)
        {
            return Fail(MtaStsFetchFailure.TooLarge, "body exceeds size limit");
        }

        byte[]? body = await ReadBoundedAsync(response.Content, _options.MaxBodyBytes, ct).ConfigureAwait(false);
        if (body is null)
        {
            return Fail(MtaStsFetchFailure.TooLarge, "body exceeds size limit");
        }

        if (!MtaStsPolicyParser.TryParse(body, out MtaStsPolicy? policy, out string? error) || policy is null)
        {
            return Fail(MtaStsFetchFailure.InvalidPolicy, error ?? "invalid policy");
        }

        return new MtaStsFetchResult(policy, MtaStsFetchFailure.None, null);
    }

    private static async Task<byte[]?> ReadBoundedAsync(HttpContent content, int max, CancellationToken ct)
    {
        await using Stream stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buffer = new byte[Math.Min(max, 8192) + 1];
        using var ms = new MemoryStream();
        while (true)
        {
            int n = await stream.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (n == 0)
            {
                return ms.ToArray();
            }

            if (ms.Length + n > max)
            {
                return null;
            }

            ms.Write(buffer, 0, n);
        }
    }

    private static bool IsTlsFailure(Exception ex)
    {
        for (Exception? e = ex; e is not null; e = e.InnerException)
        {
            if (e is AuthenticationException)
            {
                return true;
            }
        }

        return false;
    }

    private static MtaStsFetchResult Fail(MtaStsFetchFailure failure, string detail) => new(null, failure, detail);
}
