using System.Net;
using System.Text;
using Mta.Core;
using Mta.Host.Tls;
using Mta.Storage;

namespace Mta.Host.Tests;

/// <summary>Test protector: reversible and purpose-bound, not secret.</summary>
internal sealed class TestProtector : ISecretProtector
{
    public byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose) => [.. Encoding.UTF8.GetBytes(purpose + "|"), .. plaintext.ToArray()];

    public byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose)
    {
        byte[] prefix = Encoding.UTF8.GetBytes(purpose + "|");
        if (!protectedData.StartsWith(prefix)) { throw new System.Security.Cryptography.CryptographicException("wrong purpose"); }
        return protectedData[prefix.Length..].ToArray();
    }
}

public class TlsMaterialTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 12, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Self_signed_certificate_roundtrips_through_protected_storage()
    {
        var protector = new TestProtector();
        var record = CertificateMaterial.CreateSelfSigned("mx.example.com", protector, Now);
        Assert.Equal("selfsigned", record.Source);
        Assert.Contains("mx.example.com", record.Subjects);
        Assert.True(record.NotAfter - record.NotBefore > TimeSpan.FromDays(364));
        Assert.DoesNotContain("PRIVATE KEY", record.ChainPem);
        var (leaf, intermediates) = CertificateMaterial.Load(record, protector);
        Assert.True(leaf.HasPrivateKey);
        Assert.Empty(intermediates);
        Assert.Contains("mx.example.com", CertificateMaterial.SubjectsOf(leaf));
        // A different purpose cannot unprotect the key (purpose separation).
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => protector.Unprotect(record.PrivateKeyProtected, SecretPurposes.DkimKey));
    }

    [Theory]
    [InlineData("example.com", "example.com", true)]
    [InlineData("EXAMPLE.com", "example.COM.", true)]
    [InlineData("*.example.com", "mx.example.com", true)]
    [InlineData("*.example.com", "a.b.example.com", false)]
    [InlineData("*.example.com", "example.com", false)]
    [InlineData("mx.example.com", "example.com", false)]
    public void Name_matching(string pattern, string host, bool expected) => Assert.Equal(expected, CertificateMaterial.Matches(pattern, host));

    private static CertificateRecord Cert(DateTimeOffset notBefore, DateTimeOffset notAfter, params string[] subjects) =>
        new(Ids.New(), "default", subjects, notBefore, notAfter, "", [], "acme", "T", true, 1, notBefore);

    [Fact]
    public void Renewal_decisions()
    {
        string[] names = ["mx.example.com"];
        Assert.True(AcmeRenewalService.NeedsRenewal(null, names, Now, 1.0 / 3));
        var fresh = Cert(Now.AddDays(-1), Now.AddDays(89), "mx.example.com");
        Assert.False(AcmeRenewalService.NeedsRenewal(fresh, names, Now, 1.0 / 3));
        var old = Cert(Now.AddDays(-65), Now.AddDays(25), "mx.example.com");           // 25 of 90 days left, below one third
        Assert.True(AcmeRenewalService.NeedsRenewal(old, names, Now, 1.0 / 3));
        Assert.True(AcmeRenewalService.NeedsRenewal(fresh, ["mx.example.com", "extra.example.com"], Now, 1.0 / 3));   // domain set changed
        Assert.False(AcmeRenewalService.NeedsRenewal(fresh, ["MX.Example.com"], Now, 1.0 / 3));                       // case-insensitive
    }

    [Fact]
    public void Backoff_grows_and_is_capped()
    {
        Assert.Equal(TimeSpan.FromMinutes(10), AcmeRenewalService.Backoff(1));
        Assert.Equal(TimeSpan.FromMinutes(20), AcmeRenewalService.Backoff(2));
        Assert.Equal(TimeSpan.FromMinutes(40), AcmeRenewalService.Backoff(3));
        Assert.Equal(TimeSpan.FromHours(6), AcmeRenewalService.Backoff(20));
    }

    private sealed class FakeCloudflare : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Path, string? Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string path = request.RequestUri!.PathAndQuery;
            Requests.Add((request.Method, path, request.Content is null ? null : await request.Content.ReadAsStringAsync(ct)));
            Assert.Equal("Bearer tok", request.Headers.Authorization!.ToString());
            string json;
            if (request.Method == HttpMethod.Get && !path.Contains("name=example.com")) { json = "{\"result\":[]}"; }
            else if (request.Method == HttpMethod.Get) { json = "{\"result\":[{\"id\":\"zone1\",\"name\":\"example.com\"}]}"; }
            else if (request.Method == HttpMethod.Post) { json = "{\"result\":{\"id\":\"rec9\"}}"; }
            else { json = "{}"; }
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json) };
        }
    }

    [Fact]
    public async Task Cloudflare_provider_walks_up_to_the_zone_and_creates_and_deletes_records()
    {
        var handler = new FakeCloudflare();
        var cf = new CloudflareDnsChallengeProvider(new HttpClient(handler), "tok");
        string handle = await cf.CreateTxtAsync("_acme-challenge.sub.example.com", "abc123", default);
        Assert.Equal("zone1/rec9", handle);
        Assert.Contains(handler.Requests, r => r.Method == HttpMethod.Get && r.Path.Contains("name=sub.example.com"));
        Assert.Contains(handler.Requests, r => r.Method == HttpMethod.Get && r.Path.Contains("name=example.com"));
        var post = handler.Requests.Single(r => r.Method == HttpMethod.Post);
        Assert.Equal("/client/v4/zones/zone1/dns_records", post.Path);
        Assert.Contains("\"content\":\"abc123\"", post.Body);
        Assert.Contains("\"type\":\"TXT\"", post.Body);
        await cf.DeleteTxtAsync(handle, default);
        Assert.Contains(handler.Requests, r => r.Method == HttpMethod.Delete && r.Path == "/client/v4/zones/zone1/dns_records/rec9");
    }
}
