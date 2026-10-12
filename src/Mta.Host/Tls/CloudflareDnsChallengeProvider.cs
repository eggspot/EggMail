using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace Mta.Host.Tls;

/// <summary>DNS-01 challenge records through the Cloudflare API (first provider, decision 19). The token needs Zone:Read and DNS:Edit.</summary>
public sealed class CloudflareDnsChallengeProvider : IDnsChallengeProvider
{
    private readonly HttpClient _http;
    private readonly Dictionary<string, string> _zoneCache = new(StringComparer.OrdinalIgnoreCase);

    public CloudflareDnsChallengeProvider(HttpClient http, string apiToken, string baseUrl = "https://api.cloudflare.com/client/v4/")
    {
        _http = http;
        _http.BaseAddress = new Uri(baseUrl);
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiToken);
    }

    public async ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken ct)
    {
        string zone = await FindZoneAsync(fqdn, ct).ConfigureAwait(false);
        using var response = await _http.PostAsJsonAsync($"zones/{zone}/dns_records", new { type = "TXT", name = fqdn, content = value, ttl = 60 }, ct).ConfigureAwait(false);
        string id = await ReadResultIdAsync(response, "create TXT record", ct).ConfigureAwait(false);
        return $"{zone}/{id}";
    }

    public async ValueTask DeleteTxtAsync(string handle, CancellationToken ct)
    {
        int slash = handle.IndexOf('/');
        using var response = await _http.DeleteAsync($"zones/{handle[..slash]}/dns_records/{handle[(slash + 1)..]}", ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode && (int)response.StatusCode != 404)
        {
            throw new AcmeException($"Cloudflare: deleting the TXT record failed with HTTP {(int)response.StatusCode}");
        }
    }

    private async Task<string> FindZoneAsync(string fqdn, CancellationToken ct)
    {
        string[] labels = fqdn.TrimEnd('.').Split('.');
        for (int i = 0; i < labels.Length - 1; i++)
        {
            string candidate = string.Join('.', labels.Skip(i));
            if (_zoneCache.TryGetValue(candidate, out var cached))
            {
                return cached;
            }

            using var response = await _http.GetAsync($"zones?name={Uri.EscapeDataString(candidate)}&status=active", ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new AcmeException($"Cloudflare: zone lookup failed with HTTP {(int)response.StatusCode}");
            }

            using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false), cancellationToken: ct).ConfigureAwait(false);
            if (doc.RootElement.TryGetProperty("result", out var result) && result.ValueKind == JsonValueKind.Array && result.GetArrayLength() > 0)
            {
                string id = result[0].GetProperty("id").GetString()!;
                _zoneCache[candidate] = id;
                return id;
            }
        }

        throw new AcmeException($"Cloudflare: no active zone found for {fqdn} (does the API token have access?)");
    }

    private static async Task<string> ReadResultIdAsync(HttpResponseMessage response, string what, CancellationToken ct)
    {
        using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false), cancellationToken: ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode || !doc.RootElement.TryGetProperty("result", out var result) || !result.TryGetProperty("id", out var id))
        {
            throw new AcmeException($"Cloudflare: could not {what} (HTTP {(int)response.StatusCode})");
        }

        return id.GetString()!;
    }
}
