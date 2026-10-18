using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Secrets;
using Mta.Host.Tls;
using Mta.Storage;
using Mta.Storage.InMemory;

namespace Mta.Host.Tests.Security;

/// <summary>
/// Security regression tests for secrets that leave or enter the process outside the API (docs/security-test-map.md, SECRET-3 to SECRET-5): the
/// Cloudflare token, and the key that wraps the Data Protection ring. The in-house review, not an independent audit.
/// </summary>
public sealed class OutboundSecretsTests : IDisposable
{
    private const string Token = "CLOUDFLARE-TOKEN-k4Rv9pQ2xN7sT1bW";

    private readonly List<(TcpListener Listener, List<string> Heads)> _servers = [];

    public void Dispose()
    {
        foreach (var (listener, _) in _servers) { listener.Stop(); }
    }

    /// <summary>A loopback HTTP server that records the request heads it gets and answers each with the given raw response.</summary>
    private (int Port, List<string> Heads) Serve(Func<int, string> response)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var heads = new List<string>();
        _servers.Add((listener, heads));
        int count = 0;
        _ = Task.Run(async () =>
        {
            while (true)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(); }
                catch (Exception ex) when (ex is ObjectDisposedException or SocketException or InvalidOperationException) { return; }
                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try
                        {
                            var stream = client.GetStream();
                            var buffer = new byte[16 * 1024];
                            var text = new StringBuilder();
                            while (!text.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
                            {
                                int n = await stream.ReadAsync(buffer);
                                if (n == 0) { return; }
                                text.Append(Encoding.ASCII.GetString(buffer, 0, n));
                            }

                            lock (heads) { heads.Add(text.ToString()); }
                            int index = Interlocked.Increment(ref count) - 1;
                            await stream.WriteAsync(Encoding.ASCII.GetBytes(response(index)));
                        }
                        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
                    }
                });
            }
        });
        return (((IPEndPoint)listener.LocalEndpoint).Port, heads);
    }

    [Fact]
    public async Task The_cloudflare_token_goes_only_to_the_configured_api_and_is_not_handed_on_by_a_redirect()
    {
        var elsewhere = Serve(_ => "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
        var api = Serve(_ => $"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{elsewhere.Port}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        var provider = new CloudflareDnsChallengeProvider(new HttpClient(), Token, $"http://127.0.0.1:{api.Port}/client/v4/");

        await Assert.ThrowsAnyAsync<Exception>(async () => await provider.CreateTxtAsync("_acme-challenge.example.com", "value", default));

        lock (api.Heads) { Assert.Contains("Authorization: Bearer " + Token, string.Join('\n', api.Heads), StringComparison.Ordinal); }
        lock (elsewhere.Heads) { Assert.DoesNotContain(Token, string.Join('\n', elsewhere.Heads), StringComparison.Ordinal); }
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(500)]
    public async Task A_failure_of_the_cloudflare_api_is_reported_without_the_token_or_the_echo_of_the_request(int status)
    {
        var api = Serve(_ => $"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: 60\r\nConnection: close\r\n\r\n{{\"errors\":[{{\"message\":\"Authorization: Bearer {Token}\"}}]}}  ");
        var provider = new CloudflareDnsChallengeProvider(new HttpClient(), Token, $"http://127.0.0.1:{api.Port}/client/v4/");

        Exception ex = await Assert.ThrowsAnyAsync<Exception>(async () => await provider.CreateTxtAsync("_acme-challenge.example.com", "value", default));

        Assert.DoesNotContain(Token, ex.ToString(), StringComparison.Ordinal);   // the text of the exception ends up in the log and the dashboard
    }

    [Fact]
    public async Task The_key_that_wraps_the_data_protection_ring_is_in_no_message_a_start_can_produce()
    {
        string dir = Directory.CreateTempSubdirectory("eggmail-kms-sec-").FullName;
        try
        {
            await using var storage = new InMemoryStorage(new StorageOptions());
            await storage.InitializeAsync(default);
            byte[] key = RandomNumberGenerator.GetBytes(32);
            string keyFile = Path.Combine(dir, "ring.key");
            await File.WriteAllTextAsync(keyFile, Convert.ToBase64String(key));
            if (!OperatingSystem.IsWindows()) { File.SetUnixFileMode(keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            var messages = new List<string>();

            SecretsSection Kms(string? file = null, string? inline = null) => new() { KeyProtection = KeyProtectionMode.Kms, KmsProvider = "LocalKey", KmsKeyFile = file, KmsKey = inline };
            ISecretProtector protector = SecretsFactory.Create(Kms(keyFile), storage.Config);
            byte[] cipher = protector.Protect("a secret"u8, SecretPurposes.DkimKey);

            // Wrong key, no key, a key of the wrong size, an unreadable file, warnings about weak ways to supply it: every message names the problem, none shows a key.
            byte[] other = RandomNumberGenerator.GetBytes(32);
            string otherFile = Path.Combine(dir, "other.key");
            await File.WriteAllTextAsync(otherFile, Convert.ToBase64String(other));
            string shortFile = Path.Combine(dir, "short.key");
            await File.WriteAllTextAsync(shortFile, Convert.ToBase64String(new byte[8]));
            foreach (SecretsSection section in new[] { Kms(otherFile), Kms(shortFile), Kms(Path.Combine(dir, "missing.key")), Kms(), Kms(inline: Convert.ToBase64String(other)), Kms(inline: "not-base64-at-all-" + Convert.ToHexString(other)) })
            {
                try { SecretsFactory.Create(section, storage.Config); }
                catch (Exception ex) { messages.Add(ex.ToString()); }

                messages.AddRange(KeyWrapProviders.Warnings(section));
            }

            messages.Add(string.Join('\n', (await storage.Config.GetSettingsAsync(null, default)).Select(s => s.Key + "=" + s.ValueJson)));   // what the store holds: only wrapped keys
            string all = string.Join('\n', messages);
            foreach (byte[] secret in new[] { key, other })
            {
                Assert.DoesNotContain(Convert.ToBase64String(secret), all, StringComparison.Ordinal);
                Assert.DoesNotContain(Convert.ToHexString(secret), all, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(Convert.ToBase64String(secret).TrimEnd('='), all, StringComparison.Ordinal);
            }

            Assert.Equal("a secret"u8.ToArray(), protector.Unprotect(cipher, SecretPurposes.DkimKey));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);   // created by this test
        }
    }
}
