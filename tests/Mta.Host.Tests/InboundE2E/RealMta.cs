using System.Net;
using System.Text;
using Mta.Core;
using Mta.Smtp.Client;

namespace Mta.Host.Tests.InboundE2E;

internal static class RealMta
{
    public static SmtpRemoteTarget Target(int port, bool startTls = false, bool requireTls = false) => new()
    {
        Host = "localhost",
        Address = IPAddress.Loopback,
        Port = port,
        Tls = startTls
            ? new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = requireTls, TargetHost = "localhost", ValidationCallback = (_, _, _, _) => true }
            : SmtpTlsPolicy.Disabled,
    };

    public static SmtpClientOptions Options(bool chunking = false, string helo = "client.sender.test") => new()
    {
        HeloName = helo,
        PreferChunking = chunking,
        BannerTimeout = TimeSpan.FromSeconds(30),
        CommandTimeout = TimeSpan.FromSeconds(30),
        EndOfDataTimeout = TimeSpan.FromSeconds(30),
        DataBlockTimeout = TimeSpan.FromSeconds(30),
        DataInitiationTimeout = TimeSpan.FromSeconds(30),
        TlsHandshakeTimeout = TimeSpan.FromSeconds(30),
    };

    public static SmtpEnvelope Envelope(string from, params string[] to) =>
        new(from.Length == 0 ? EmailAddress.Null : EmailAddress.Parse(from), to.Select(r => EmailAddress.Parse(r)).ToArray(), false, false);

    public static async Task<(SmtpSendResult Result, SmtpTlsSession Tls)> SendAsync(int port, string from, string[] to, string message, bool startTls = false, bool chunking = false)
    {
        await using SmtpClientConnection connection = await SmtpClientConnection.ConnectAsync(Target(port, startTls), Options(chunking));
        SmtpSendResult result = await connection.SendAsync(Envelope(from, to), Encoding.UTF8.GetBytes(message));
        SmtpTlsSession tls = connection.TlsSession;
        await connection.QuitAsync();
        return (result, tls);
    }
}
