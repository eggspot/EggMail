using System.Net;

namespace Mta.Smtp.Client.Tests;

/// <summary>An idle connection is only handed to a target that asked for the same security: same credentials, same validation.</summary>
public class PoolKeyTests
{
    private static readonly SmtpClientOptions Options = new() { HeloName = "client.test", BannerTimeout = TimeSpan.FromSeconds(30), CommandTimeout = TimeSpan.FromSeconds(30) };

    private static SmtpRemoteTarget Target(SmtpCredentials? credentials = null, SmtpTlsPolicy? tls = null, string host = "relay.example") =>
        new() { Host = host, Address = IPAddress.Loopback, Port = 587, Tls = tls ?? SmtpTlsPolicy.Opportunistic, Credentials = credentials };

    private static SmtpCredentials Cred(string user, string password) => new() { UserName = user, Password = password };

    [Fact]
    public void The_key_tells_passwords_of_the_same_user_apart_and_never_contains_one()
    {
        string a = Target(Cred("relay", "secret-one")).PoolKey;
        string b = Target(Cred("relay", "secret-two")).PoolKey;
        Assert.NotEqual(a, b);
        Assert.Equal(a, Target(Cred("relay", "secret-one")).PoolKey);
        Assert.NotEqual(a, Target(Cred("other", "secret-one")).PoolKey);
        Assert.NotEqual(a, Target().PoolKey);
        Assert.DoesNotContain("secret-one", a);
        Assert.DoesNotContain("secret-two", b);
    }

    [Fact]
    public void The_key_tells_apart_policies_that_validate_differently()
    {
        static bool Always(object s, System.Security.Cryptography.X509Certificates.X509Certificate? c, System.Security.Cryptography.X509Certificates.X509Chain? ch, System.Net.Security.SslPolicyErrors e) => true;
        var anyCert = new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = true, PoolIdentity = "0.0.1.1.3072.mx.example.." };
        var verified = new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = true, ValidationCallback = Always, PoolIdentity = "3.1.1.1.3072.mx.example.." };
        var otherHost = new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = true, ValidationCallback = Always, PoolIdentity = "3.1.1.1.3072.other.example.." };
        var sameAgain = new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = true, ValidationCallback = Always, PoolIdentity = "3.1.1.1.3072.mx.example.." };
        Assert.NotEqual(Target(tls: anyCert).PoolKey, Target(tls: verified).PoolKey);
        Assert.NotEqual(Target(tls: verified).PoolKey, Target(tls: otherHost).PoolKey);
        Assert.Equal(Target(tls: verified).PoolKey, Target(tls: sameAgain).PoolKey);
    }

    [Fact]
    public async Task A_connection_authenticated_with_one_password_is_not_reused_for_another()
    {
        await using var server = new RealServer();
        await using var pool = new SmtpConnectionPool(Options);
        var tls = new SmtpTlsPolicy { Mode = SmtpTlsMode.Implicit, Require = true, TargetHost = "localhost", ValidationCallback = (_, _, _, _) => true };
        await using (var lease = await pool.RentAsync(server.Target(tls, new SmtpCredentials { UserName = "relay", Password = "secret" }, implicitTls: true)))
        {
            Assert.True(lease.Connection.TlsSession.Used);
        }

        Assert.Equal(1, pool.IdleConnections);

        // The rotated (here: wrong) password gets its own, fresh connection, which the server then refuses: it was not served by the idle authenticated one.
        var refused = await Assert.ThrowsAsync<SmtpGreetingRejectedException>(async () =>
            await pool.RentAsync(server.Target(tls, new SmtpCredentials { UserName = "relay", Password = "rotated" }, implicitTls: true)));
        Assert.Equal(535, refused.Reply.Code);

        // The same credentials still reuse the idle connection.
        int connections = server.Handler.Connections;
        await using var again = await pool.RentAsync(server.Target(tls, new SmtpCredentials { UserName = "relay", Password = "secret" }, implicitTls: true));
        Assert.Equal(connections, server.Handler.Connections); // no new connection: the idle one was reused
    }

    [Fact]
    public async Task A_connection_made_without_validation_is_not_reused_for_a_policy_that_validates()
    {
        await using var server = new RealServer();
        await using var pool = new SmtpConnectionPool(Options);
        var encryptOnly = new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = true, TargetHost = "localhost", PoolIdentity = "2.0.0.1.3072.localhost.." };
        await using (var lease = await pool.RentAsync(server.Target(encryptOnly)))
        {
            Assert.True(lease.Connection.TlsSession.Used);
        }

        Assert.Equal(1, server.Handler.Connections);
        var verify = new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = true, TargetHost = "localhost", ValidationCallback = (_, _, _, _) => true, PoolIdentity = "3.1.1.1.3072.localhost.." };
        await using (var lease = await pool.RentAsync(server.Target(verify)))
        {
            Assert.True(lease.Connection.TlsSession.Used);
        }

        Assert.Equal(2, server.Handler.Connections); // a new connection, validated by its own handshake
        await using var reused = await pool.RentAsync(server.Target(encryptOnly));
        Assert.Equal(2, server.Handler.Connections); // the encrypt-only identity still finds its own idle connection
    }
}
