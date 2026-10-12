using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Mta.Core;
using Mta.Dns;
using Mta.Tls.MtaSts;

namespace Mta.Tls.Tests.Support;

public sealed class TestClock : IClock
{
    private DateTimeOffset _now;

    public TestClock(DateTimeOffset? start = null) => _now = start ?? new DateTimeOffset(2026, 10, 12, 12, 0, 0, TimeSpan.Zero);

    public DateTimeOffset UtcNow => _now;

    public long Timestamp => _now.Ticks;

    public void Advance(TimeSpan by) => _now += by;

    public void Set(DateTimeOffset value) => _now = value;
}

/// <summary>An HTTP handler that answers from a delegate and records requests.</summary>
public sealed class FakeHttpHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _respond;

    public FakeHttpHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) => _respond = respond;

    public FakeHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : this((r, _) => Task.FromResult(respond(r)))
    {
    }

    public ConcurrentQueue<Uri> RequestUris { get; } = new();

    public ConcurrentQueue<HttpRequestMessage> Requests { get; } = new();

    public byte[]? LastRequestBody { get; private set; }

    public string? LastRequestContentType { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        RequestUris.Enqueue(request.RequestUri!);
        Requests.Enqueue(request);
        if (request.Content is not null)
        {
            LastRequestBody = await request.Content.ReadAsByteArrayAsync(cancellationToken);
            LastRequestContentType = request.Content.Headers.ContentType?.ToString();
        }

        var response = await _respond(request, cancellationToken);
        response.RequestMessage ??= request;
        return response;
    }

    public static HttpResponseMessage Text(string body, string contentType = "text/plain; charset=utf-8", HttpStatusCode status = HttpStatusCode.OK)
    {
        var content = new ByteArrayContent(Encoding.UTF8.GetBytes(body));
        content.Headers.TryAddWithoutValidation("Content-Type", contentType);
        return new HttpResponseMessage(status) { Content = content };
    }
}

public sealed class FakePolicyFetcher : IMtaStsPolicyFetcher
{
    public Func<string, MtaStsFetchResult> OnFetch { get; set; } = _ => new MtaStsFetchResult(null, MtaStsFetchFailure.ConnectionFailed, "not configured");

    public int Calls;

    public ValueTask<MtaStsFetchResult> FetchAsync(string domain, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref Calls);
        return ValueTask.FromResult(OnFetch(domain));
    }

    public static MtaStsFetchResult Ok(string body)
    {
        Assert.True(MtaStsPolicyParser.TryParse(body, out var policy, out string? error), error);
        return new MtaStsFetchResult(policy, MtaStsFetchFailure.None, null);
    }
}

/// <summary>A DNS resolver whose answers tests can change between calls.</summary>
public sealed class ScriptedDnsResolver : IDnsResolver
{
    private readonly ConcurrentDictionary<(string, DnsRecordType), Func<DnsResponse>> _answers = new();

    public int Queries;

    public ScriptedDnsResolver Set(string name, DnsRecordType type, DnsResponse response) => Set(name, type, () => response);

    public ScriptedDnsResolver Set(string name, DnsRecordType type, Func<DnsResponse> response)
    {
        _answers[(name.ToLowerInvariant(), type)] = response;
        return this;
    }

    public ScriptedDnsResolver SetTxt(string name, params string[] texts) =>
        Set(name, DnsRecordType.TXT, new DnsResponse { Answers = texts.Select(t => (DnsRecord)new TxtRecord(name, 300, t)).ToArray() });

    public ScriptedDnsResolver Remove(string name, DnsRecordType type)
    {
        _answers.TryRemove((name.ToLowerInvariant(), type), out _);
        return this;
    }

    public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref Queries);
        if (_answers.TryGetValue((name.TrimEnd('.').ToLowerInvariant(), type), out var f))
        {
            return ValueTask.FromResult(f());
        }

        return ValueTask.FromResult(new DnsResponse { Rcode = DnsRcode.NameError, Ttl = 300 });
    }
}

public sealed class ThrowingDnsResolver : IDnsResolver
{
    public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default) =>
        throw new DnsException("simulated transport failure");
}
