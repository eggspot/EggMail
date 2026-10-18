using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace Mta.Host.Tests.Inbound;

/// <summary>
/// A scripted remote MTA: speaks SMTP to the server under test byte by byte, so a test can send exactly what a hostile or sloppy sender would
/// (pipelined commands, a bare LF, a command behind STARTTLS) and see the raw replies.
/// </summary>
internal sealed class FakeMta : IAsyncDisposable
{
    private readonly TcpClient _tcp = new();
    private Stream _stream = null!;
    private readonly StringBuilder _pending = new();

    public static async Task<FakeMta> ConnectAsync(int port, bool expectGreeting = true)
    {
        var mta = new FakeMta();
        await mta._tcp.ConnectAsync(System.Net.IPAddress.Loopback, port);
        mta._stream = mta._tcp.GetStream();
        if (expectGreeting)
        {
            Reply greeting = await mta.ReadReplyAsync();
            Assert.Equal(220, greeting.Code);
        }

        return mta;
    }

    /// <summary>The stream as it is now (the TLS stream after an upgrade): for a test that drives the handshake itself.</summary>
    public Stream UnderlyingStream => _stream;

    public sealed record Reply(int Code, string Text, IReadOnlyList<string> Lines)
    {
        public string Enhanced => Text.Split(' ', 2)[0];
        public override string ToString() => $"{Code} {Text}";
    }

    public async Task<Reply> ReadReplyAsync()
    {
        var lines = new List<string>();
        while (true)
        {
            string line = await ReadLineAsync();
            lines.Add(line);
            if (line.Length >= 4 && line[3] == ' ')
            {
                return new Reply(int.Parse(line[..3]), line[4..], lines);
            }

            if (line.Length < 4)
            {
                throw new InvalidOperationException("Not a reply line: '" + line + "'");
            }
        }
    }

    private async Task<string> ReadLineAsync()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var one = new byte[1];
        while (true)
        {
            int nl = _pending.ToString().IndexOf('\n', StringComparison.Ordinal);
            if (nl >= 0)
            {
                string line = _pending.ToString(0, nl).TrimEnd('\r');
                _pending.Remove(0, nl + 1);
                return line;
            }

            int n = await _stream.ReadAsync(one, cts.Token);
            if (n == 0)
            {
                throw new EndOfStreamException("The server closed the connection. Pending: '" + _pending + "'");
            }

            _pending.Append((char)one[0]);
        }
    }

    public async Task SendRawAsync(string text, bool utf8 = false)
    {
        byte[] bytes = (utf8 ? Encoding.UTF8 : Encoding.Latin1).GetBytes(text);
        await _stream.WriteAsync(bytes);
        await _stream.FlushAsync();
    }

    public async Task<Reply> CommandAsync(string command, bool utf8 = false)
    {
        await SendRawAsync(command + "\r\n", utf8);
        return await ReadReplyAsync();
    }

    public async Task<Reply> EhloAsync(string name = "mail.sender.test") => await CommandAsync("EHLO " + name);

    public async Task<Reply> MailFromAsync(string address, string parameters = "") =>
        await CommandAsync("MAIL FROM:<" + address + ">" + (parameters.Length > 0 ? " " + parameters : ""));

    public async Task<Reply> RcptAsync(string address) => await CommandAsync("RCPT TO:<" + address + ">");

    /// <summary>DATA, the message (dot-stuffed here) and the end-of-data line; returns the reply to the end of DATA (or the refusal of DATA itself).</summary>
    public async Task<Reply> DataAsync(string message)
    {
        Reply start = await CommandAsync("DATA");
        if (start.Code != 354)
        {
            return start;
        }

        var sb = new StringBuilder();
        foreach (string line in (message.EndsWith("\r\n", StringComparison.Ordinal) ? message[..^2] : message).Split("\r\n"))
        {
            sb.Append(line.StartsWith('.') ? "." + line : line).Append("\r\n");
        }

        await SendRawAsync(sb + ".\r\n");
        return await ReadReplyAsync();
    }

    /// <summary>The whole transaction for one recipient; returns the reply to the end of DATA, or the first refusal on the way.</summary>
    public async Task<Reply> SendAsync(string from, string to, string message, string mailParameters = "")
    {
        Reply r = await MailFromAsync(from, mailParameters);
        if (r.Code != 250)
        {
            return r;
        }

        r = await RcptAsync(to);
        if (r.Code != 250)
        {
            return r;
        }

        return await DataAsync(message);
    }

    public async Task<bool> StartTlsAsync()
    {
        Reply r = await CommandAsync("STARTTLS");
        if (r.Code != 220)
        {
            return false;
        }

        var ssl = new SslStream(_stream, leaveInnerStreamOpen: false, (_, _, _, _) => true);
        await ssl.AuthenticateAsClientAsync("localhost");
        _stream = ssl;
        _pending.Clear();
        return true;
    }

    public async Task QuitAsync()
    {
        try
        {
            await CommandAsync("QUIT");
        }
        catch (Exception ex) when (ex is IOException or EndOfStreamException or SocketException)
        {
        }
    }

    /// <summary>Whether the server has closed the connection (reads until the end of the stream).</summary>
    public async Task<bool> IsClosedByServerAsync()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var buffer = new byte[256];
        try
        {
            while (true)
            {
                int n = await _stream.ReadAsync(buffer, cts.Token);
                if (n == 0)
                {
                    return true;
                }
            }
        }
        catch (IOException)
        {
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    public ValueTask DisposeAsync()
    {
        _tcp.Dispose();
        return ValueTask.CompletedTask;
    }
}
