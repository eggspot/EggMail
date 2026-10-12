using System.Net;
using System.Security.Authentication;
using System.Text;
using Mta.Tls.MtaSts;
using Mta.Tls.Tests.Support;

namespace Mta.Tls.Tests;

public class MtaStsFetcherTests
{
    private const string Policy = "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmax_age: 86400\r\n";

    private static MtaStsPolicyFetcher Create(FakeHttpHandler handler, MtaStsFetchOptions? options = null) => new(handler, options);

    [Fact]
    public async Task Fetches_from_the_well_known_https_url()
    {
        var handler = new FakeHttpHandler(_ => FakeHttpHandler.Text(Policy));
        var result = await Create(handler).FetchAsync("Example.COM.");

        Assert.True(result.IsSuccess);
        Assert.Equal(MtaStsMode.Enforce, result.Policy!.Mode);
        Assert.Null(result.ResultType);
        var uri = Assert.Single(handler.RequestUris);
        Assert.Equal("https://mta-sts.example.com/.well-known/mta-sts.txt", uri.ToString());
        Assert.Equal(HttpMethod.Get, Assert.Single(handler.Requests).Method);
    }

    [Theory]
    [InlineData("text/plain")]
    [InlineData("TEXT/PLAIN; charset=UTF-8")]
    [InlineData("text/plain; charset=us-ascii")]
    [InlineData("text/plain; charset=\"utf-8\"")]
    public async Task Accepts_text_plain_variants(string contentType)
    {
        var result = await Create(new FakeHttpHandler(_ => FakeHttpHandler.Text(Policy, contentType))).FetchAsync("example.com");
        Assert.True(result.IsSuccess);
    }

    [Theory]
    [InlineData("text/html")]
    [InlineData("application/json")]
    [InlineData("application/octet-stream")]
    [InlineData("text/plain; charset=iso-8859-2")]
    public async Task Rejects_wrong_content_type_or_charset(string contentType)
    {
        var result = await Create(new FakeHttpHandler(_ => FakeHttpHandler.Text(Policy, contentType))).FetchAsync("example.com");
        Assert.Equal(MtaStsFetchFailure.ContentType, result.Failure);
        Assert.Equal(TlsResultType.StsPolicyFetchError, result.ResultType);
    }

    [Fact]
    public async Task Rejects_missing_content_type()
    {
        var handler = new FakeHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Policy) { Headers = { ContentType = null } } });
        var result = await Create(handler).FetchAsync("example.com");
        Assert.Equal(MtaStsFetchFailure.ContentType, result.Failure);
    }

    [Theory]
    [InlineData(HttpStatusCode.MovedPermanently)]
    [InlineData(HttpStatusCode.Found)]
    [InlineData(HttpStatusCode.TemporaryRedirect)]
    [InlineData(HttpStatusCode.PermanentRedirect)]
    public async Task Redirects_are_rejected_and_not_followed(HttpStatusCode status)
    {
        var handler = new FakeHttpHandler(_ =>
        {
            var r = new HttpResponseMessage(status);
            r.Headers.Location = new Uri("https://evil.example.net/policy");
            return r;
        });
        var result = await Create(handler).FetchAsync("example.com");

        Assert.Equal(MtaStsFetchFailure.Redirected, result.Failure);
        Assert.Single(handler.RequestUris);
    }

    [Fact]
    public async Task A_response_for_a_different_uri_counts_as_a_redirect()
    {
        // Simulates a handler that follows redirects on its own.
        var handler = new FakeHttpHandler(request =>
        {
            var r = FakeHttpHandler.Text(Policy);
            r.RequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://elsewhere.example.net/mta-sts.txt");
            return r;
        });
        var result = await Create(handler).FetchAsync("example.com");
        Assert.Equal(MtaStsFetchFailure.Redirected, result.Failure);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.NoContent)]
    [InlineData(HttpStatusCode.Created)]
    public async Task Only_http_200_is_accepted(HttpStatusCode status)
    {
        var result = await Create(new FakeHttpHandler(_ => FakeHttpHandler.Text(Policy, status: status))).FetchAsync("example.com");
        Assert.Equal(MtaStsFetchFailure.HttpStatus, result.Failure);
        Assert.Equal(TlsResultType.StsPolicyFetchError, result.ResultType);
    }

    [Fact]
    public async Task Oversized_body_is_rejected_by_content_length()
    {
        string body = Policy + new string('#', MtaStsPolicyParser.MaxPolicyBytes);
        var result = await Create(new FakeHttpHandler(_ => FakeHttpHandler.Text(body))).FetchAsync("example.com");
        Assert.Equal(MtaStsFetchFailure.TooLarge, result.Failure);
    }

    [Fact]
    public async Task Oversized_streamed_body_without_content_length_is_rejected()
    {
        var handler = new FakeHttpHandler(_ =>
        {
            var content = new PushStreamLikeContent(MtaStsPolicyParser.MaxPolicyBytes + 10);
            content.Headers.TryAddWithoutValidation("Content-Type", "text/plain");
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        });
        var result = await Create(handler).FetchAsync("example.com");
        Assert.Equal(MtaStsFetchFailure.TooLarge, result.Failure);
    }

    [Fact]
    public async Task A_body_exactly_at_the_limit_is_read()
    {
        string padding = "# " + new string('x', MtaStsPolicyParser.MaxPolicyBytes - Policy.Length - 4);
        string body = Policy + padding + "\r\n";
        Assert.True(Encoding.UTF8.GetByteCount(body) <= MtaStsPolicyParser.MaxPolicyBytes);
        var result = await Create(new FakeHttpHandler(_ => FakeHttpHandler.Text(body))).FetchAsync("example.com");
        // The padding line has no colon, so the policy is syntactically invalid, but it must not be rejected as too large.
        Assert.Equal(MtaStsFetchFailure.InvalidPolicy, result.Failure);
        Assert.Equal(TlsResultType.StsPolicyInvalid, result.ResultType);
    }

    [Fact]
    public async Task Timeout_is_reported_and_does_not_throw()
    {
        var handler = new FakeHttpHandler(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return FakeHttpHandler.Text(Policy);
        });
        var result = await Create(handler, new MtaStsFetchOptions { Timeout = TimeSpan.FromMilliseconds(100) }).FetchAsync("example.com");
        Assert.Equal(MtaStsFetchFailure.Timeout, result.Failure);
    }

    [Fact]
    public async Task Caller_cancellation_propagates()
    {
        var handler = new FakeHttpHandler(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return FakeHttpHandler.Text(Policy);
        });
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await Create(handler).FetchAsync("example.com", cts.Token));
    }

    [Fact]
    public async Task Tls_certificate_failure_is_classified_as_webpki_invalid()
    {
        var handler = new FakeHttpHandler((_, _) => throw new HttpRequestException("ssl", new AuthenticationException("The remote certificate is invalid")));
        var result = await Create(handler).FetchAsync("example.com");
        Assert.Equal(MtaStsFetchFailure.TlsValidationFailed, result.Failure);
        Assert.Equal(TlsResultType.StsWebpkiInvalid, result.ResultType);
    }

    [Fact]
    public async Task Connection_failure_is_a_fetch_error()
    {
        var handler = new FakeHttpHandler((_, _) => throw new HttpRequestException("connection refused"));
        var result = await Create(handler).FetchAsync("example.com");
        Assert.Equal(MtaStsFetchFailure.ConnectionFailed, result.Failure);
    }

    [Fact]
    public async Task Invalid_policy_body_is_reported_as_invalid()
    {
        var result = await Create(new FakeHttpHandler(_ => FakeHttpHandler.Text("hello world"))).FetchAsync("example.com");
        Assert.Equal(MtaStsFetchFailure.InvalidPolicy, result.Failure);
        Assert.DoesNotContain("hello", result.Detail);
    }

    [Theory]
    [InlineData("")]
    [InlineData("exa mple.com")]
    [InlineData("example.com/../evil")]
    [InlineData("example.com:8443")]
    [InlineData("user@example.com")]
    [InlineData("192.0.2.1")]
    [InlineData("-bad.example.com")]
    public async Task Invalid_domains_never_reach_the_network(string domain)
    {
        var handler = new FakeHttpHandler(_ => FakeHttpHandler.Text(Policy));
        var result = await Create(handler).FetchAsync(domain);
        Assert.Equal(MtaStsFetchFailure.InvalidDomain, result.Failure);
        Assert.Empty(handler.RequestUris);
    }

    [Fact]
    public async Task Idn_domains_are_converted_to_a_labels()
    {
        var handler = new FakeHttpHandler(_ => FakeHttpHandler.Text(Policy));
        await Create(handler).FetchAsync("münchen.example");
        Assert.Equal("https://mta-sts.xn--mnchen-3ya.example/.well-known/mta-sts.txt", Assert.Single(handler.RequestUris).ToString());
    }

    [Fact]
    public async Task Invalid_utf8_body_is_an_invalid_policy()
    {
        var content = new ByteArrayContent([0x76, 0x65, 0xFF, 0xFE]);
        content.Headers.TryAddWithoutValidation("Content-Type", "text/plain");
        var result = await Create(new FakeHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = content })).FetchAsync("example.com");
        Assert.Equal(MtaStsFetchFailure.InvalidPolicy, result.Failure);
    }

    [Fact]
    public void Default_constructor_builds_a_hardened_handler()
    {
        using var fetcher = new MtaStsPolicyFetcher();
        Assert.NotNull(fetcher);
    }

    /// <summary>Content without a known length that produces <c>length</c> bytes.</summary>
    private sealed class PushStreamLikeContent(int length) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context) =>
            stream.WriteAsync(new byte[length]).AsTask();

        protected override bool TryComputeLength(out long len)
        {
            len = 0;
            return false;
        }
    }
}
