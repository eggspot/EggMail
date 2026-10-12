using Mta.Auth.Dmarc;
using Mta.Dns;
using static Mta.Auth.Tests.TestZone;

namespace Mta.Auth.Tests.Dmarc;

public class DmarcReportAuthorizerTests
{
    private static DmarcReportUri Uri(string text)
    {
        Assert.True(DmarcReportUri.TryParse(text, out var uri));
        return uri;
    }

    [Fact]
    public async Task Same_organizational_domain_needs_no_dns()
    {
        var authorizer = new DmarcReportAuthorizer(new ThrowingResolver());
        Assert.Equal(DmarcReportAuthorization.Authorized, await authorizer.CheckAsync("example.com", Uri("mailto:dmarc@reports.example.com")));
        Assert.Equal(DmarcReportAuthorization.Authorized, await authorizer.CheckAsync("mail.example.co.uk", Uri("mailto:dmarc@example.co.uk")));
    }

    [Fact]
    public async Task Third_party_without_record_is_not_authorized()
    {
        var authorizer = new DmarcReportAuthorizer(Build(Z()));
        Assert.Equal(DmarcReportAuthorization.NotAuthorized, await authorizer.CheckAsync("example.com", Uri("mailto:r@thirdparty.net")));
    }

    [Fact]
    public async Task Third_party_with_record_is_authorized_and_uses_the_documented_name()
    {
        Assert.Equal("example.com._report._dmarc.thirdparty.net", DmarcReportAuthorizer.AuthorizationRecordName("Example.COM.", "ThirdParty.net"));
        var authorizer = new DmarcReportAuthorizer(Build(Z("example.com._report._dmarc.thirdparty.net TXT v=DMARC1")));
        Assert.Equal(DmarcReportAuthorization.Authorized, await authorizer.CheckAsync("example.com", Uri("mailto:r@thirdparty.net")));
    }

    [Fact]
    public async Task Record_for_another_policy_domain_does_not_authorize()
    {
        var authorizer = new DmarcReportAuthorizer(Build(Z("other.org._report._dmarc.thirdparty.net TXT v=DMARC1")));
        Assert.Equal(DmarcReportAuthorization.NotAuthorized, await authorizer.CheckAsync("example.com", Uri("mailto:r@thirdparty.net")));
    }

    [Fact]
    public async Task Non_dmarc_txt_does_not_authorize()
    {
        var authorizer = new DmarcReportAuthorizer(Build(Z("example.com._report._dmarc.thirdparty.net TXT hello")));
        Assert.Equal(DmarcReportAuthorization.NotAuthorized, await authorizer.CheckAsync("example.com", Uri("mailto:r@thirdparty.net")));
    }

    [Fact]
    public async Task Verification_record_with_rua_restricts_addresses()
    {
        var authorizer = new DmarcReportAuthorizer(Build(Z("example.com._report._dmarc.thirdparty.net TXT v=DMARC1; rua=mailto:ok@thirdparty.net")));
        Assert.Equal(DmarcReportAuthorization.Authorized, await authorizer.CheckAsync("example.com", Uri("mailto:OK@thirdparty.net")));
        Assert.Equal(DmarcReportAuthorization.NotAuthorized, await authorizer.CheckAsync("example.com", Uri("mailto:other@thirdparty.net")));
    }

    [Fact]
    public async Task Dns_errors_are_temporary()
    {
        var servfail = new DmarcReportAuthorizer(Build(Z("example.com._report._dmarc.thirdparty.net SERVFAIL TXT")));
        Assert.Equal(DmarcReportAuthorization.TempError, await servfail.CheckAsync("example.com", Uri("mailto:r@thirdparty.net")));
        var thrown = new DmarcReportAuthorizer(new ThrowingResolver());
        Assert.Equal(DmarcReportAuthorization.TempError, await thrown.CheckAsync("example.com", Uri("mailto:r@thirdparty.net")));
    }

    [Fact]
    public async Task Non_mailto_uris_are_not_applicable()
    {
        var authorizer = new DmarcReportAuthorizer(Build(Z()));
        Assert.Equal(DmarcReportAuthorization.NotApplicable, await authorizer.CheckAsync("example.com", Uri("https://example.com/report")));
    }

    [Fact]
    public async Task Filter_keeps_only_authorized_addresses()
    {
        var authorizer = new DmarcReportAuthorizer(Build(Z("example.com._report._dmarc.good.net TXT v=DMARC1")));
        var kept = await authorizer.FilterAuthorizedAsync("example.com",
            [Uri("mailto:a@example.com"), Uri("mailto:b@good.net"), Uri("mailto:c@evil.net"), Uri("https://example.com/x")]);
        Assert.Equal(["a@example.com", "b@good.net"], kept.Select(u => u.MailAddress));
    }

    private sealed class ThrowingResolver : IDnsResolver
    {
        public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default) =>
            throw new DnsException("timeout");
    }
}
