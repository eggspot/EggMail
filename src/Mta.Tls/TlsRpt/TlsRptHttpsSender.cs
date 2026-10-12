using System.Net.Http.Headers;
using System.Security.Authentication;

namespace Mta.Tls.TlsRpt;

/// <summary>Options for <see cref="TlsRptHttpsSender"/>.</summary>
public sealed class TlsRptHttpsSenderOptions
{
    /// <summary>Total time allowed for one POST. Default 30 seconds.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Largest payload sent. Default 10 MiB.</summary>
    public int MaxPayloadBytes { get; init; } = 10 * 1024 * 1024;

    /// <summary>The <c>User-Agent</c> header value.</summary>
    public string UserAgent { get; init; } = "EggMail-TLS-RPT/1.0";

    /// <summary>Only applies to the default handler: allow loopback/private targets. Off by default (SSRF guard).</summary>
    public bool AllowNonPublicAddresses { get; init; }
}

/// <summary>The result of one report POST.</summary>
/// <param name="Success">True for an HTTP 2xx answer.</param>
/// <param name="StatusCode">The HTTP status, if a response was received.</param>
/// <param name="Error">A short description of the failure.</param>
public sealed record TlsRptSendResult(bool Success, int? StatusCode, string? Error);

/// <summary>
/// POSTs gzip reports to <c>https:</c> <c>rua</c> endpoints with content type <c>application/tlsrpt+gzip</c> (RFC 8460
/// section 5.3). Redirects are not followed, certificates are validated strictly, and non-public addresses are refused
/// by the default handler, because the endpoint comes from the recipient's DNS. <c>mailto:</c> endpoints are not handled
/// here; the delivery layer sends those as e-mail.
/// </summary>
public sealed class TlsRptHttpsSender : IDisposable
{
    private readonly HttpClient _client;
    private readonly TlsRptHttpsSenderOptions _options;

    /// <summary>Creates a sender, optionally over an injected handler (tests, custom egress).</summary>
    public TlsRptHttpsSender(HttpMessageHandler? handler = null, TlsRptHttpsSenderOptions? options = null)
    {
        _options = options ?? new TlsRptHttpsSenderOptions();
        handler ??= SafeHttpHandler.Create(_options.Timeout, _options.AllowNonPublicAddresses);
        _client = new HttpClient(handler, disposeHandler: true) { Timeout = System.Threading.Timeout.InfiniteTimeSpan };
    }

    /// <summary>Posts <paramref name="report"/> to <paramref name="endpoint"/>. Does not throw on remote failures.</summary>
    public Task<TlsRptSendResult> SendAsync(TlsRptEndpoint endpoint, TlsRptReport report, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(report);
        return SendAsync(endpoint, report.GzipPayload, cancellationToken);
    }

    /// <summary>Posts a gzip payload to <paramref name="endpoint"/>. Does not throw on remote failures.</summary>
    public async Task<TlsRptSendResult> SendAsync(TlsRptEndpoint endpoint, byte[] gzipPayload, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(gzipPayload);
        if (endpoint.Kind != TlsRptEndpointKind.Https || !Uri.TryCreate(endpoint.Uri, UriKind.Absolute, out Uri? uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            return new TlsRptSendResult(false, null, "endpoint is not an https URI");
        }

        if (gzipPayload.Length > _options.MaxPayloadBytes)
        {
            return new TlsRptSendResult(false, null, "payload exceeds size limit");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.Timeout);
        try
        {
            using var content = new ByteArrayContent(gzipPayload);
            content.Headers.ContentType = new MediaTypeHeaderValue(TlsRptReport.GzipMediaType);
            using var request = new HttpRequestMessage(HttpMethod.Post, uri) { Content = content };
            request.Headers.UserAgent.ParseAdd(_options.UserAgent);
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            int status = (int)response.StatusCode;
            return status is >= 200 and < 300
                ? new TlsRptSendResult(true, status, null)
                : new TlsRptSendResult(false, status, status is >= 300 and < 400 ? "redirects are not followed" : $"HTTP {status}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new TlsRptSendResult(false, null, "request timed out");
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or AuthenticationException or InvalidOperationException)
        {
            return new TlsRptSendResult(false, null, "request failed");
        }
    }

    /// <inheritdoc cref="IDisposable.Dispose" />
    public void Dispose() => _client.Dispose();
}
