using System.Net;
using Mta.Host.Tls;

namespace Mta.Host.Tests.Acme;

/// <summary>
/// <see cref="CloudflareDnsChallengeProvider"/> against the in-process <see cref="FakeCloudflare"/> (api.cloudflare.com v4's envelope, tokens, zones, TXT records, paging):
/// zone selection, several values at one name, idempotent create and delete, every kind of error answer, retries and what is waited for between them, damaged answers, and
/// the token staying out of every message. Nothing sleeps: the provider's waits are recorded.
/// </summary>
public class CloudflareDnsChallengeProviderTests
{
    private const string Zone = "example.com";
    private readonly FakeCloudflare _cf = new();
    private readonly List<TimeSpan> _pauses = [];

    private CloudflareDnsChallengeProvider Provider(string token = FakeCloudflare.ValidToken, HttpMessageHandler? handler = null) =>
        new(new HttpClient(handler ?? _cf), token, pause: (delay, ct) =>
        {
            ct.ThrowIfCancellationRequested();
            _pauses.Add(delay);
            return Task.CompletedTask;
        });

    private static string Name(string host) => "_acme-challenge." + host;

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Zones

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("mx.example.com", "example.com")]
    [InlineData("a.b.example.com", "example.com")]
    [InlineData("sub.example.com", "sub.example.com")]
    [InlineData("mx.sub.example.com", "sub.example.com")]
    [InlineData("deep.mx.sub.example.com", "sub.example.com")]
    [InlineData("xn--bcher-kva.example.com", "example.com")]
    public async Task The_record_goes_into_the_most_specific_zone_the_account_has(string host, string expectedZone)
    {
        _cf.AddZone("example.com");
        _cf.AddZone("sub.example.com");
        _cf.AddZone("com");

        string handle = await Provider().CreateTxtAsync(Name(host), "value-1", default);

        var record = Assert.Single(_cf.RecordsIn(expectedZone));
        Assert.Equal(("TXT", Name(host), "value-1"), (record.Type, record.Name, record.Content));
        Assert.Equal($"{_cf.ZoneId(expectedZone)}/{record.Id}", handle);
    }

    [Fact]
    public async Task The_zone_lookup_asks_from_the_most_specific_name_up_skipping_the_underscore_label()
    {
        _cf.AddZone(Zone);

        await Provider().CreateTxtAsync(Name("mx.sub." + Zone), "v", default);

        Assert.Equal(
            ["/client/v4/zones?name=mx.sub.example.com&status=active", "/client/v4/zones?name=sub.example.com&status=active", "/client/v4/zones?name=example.com&status=active"],
            _cf.Requests.Where(r => r.Route == "zones").Select(r => r.PathAndQuery));
    }

    [Fact]
    public async Task The_zone_is_remembered_so_the_second_record_of_an_order_does_not_look_it_up_again()
    {
        _cf.AddZone(Zone);
        var provider = Provider();

        await provider.CreateTxtAsync(Name(Zone), "one", default);
        int lookups = _cf.Count("zones");
        await provider.CreateTxtAsync(Name(Zone), "two", default);

        Assert.Equal(lookups, _cf.Count("zones"));
    }

    [Fact]
    public async Task A_name_normalised_the_way_the_CA_writes_it_is_stored_lower_case_without_a_trailing_dot()
    {
        _cf.AddZone(Zone);

        await Provider().CreateTxtAsync("_ACME-Challenge.MX.Example.COM.", "v", default);

        Assert.Equal(Name("mx.example.com"), Assert.Single(_cf.RecordsIn(Zone)).Name);
    }

    [Fact]
    public async Task No_zone_for_the_name_a_pending_zone_and_a_zone_the_token_cannot_see_are_all_a_clear_error_naming_the_name()
    {
        _cf.AddZone("pending.test", status: "pending");
        string hidden = _cf.AddZone("hidden.test");
        _cf.Tokens["scoped"] = new CloudflareToken(OnlyZones: new HashSet<string> { _cf.ZoneId("pending.test") });

        foreach (var (name, token) in new[] { (Name("mx.nowhere.test"), FakeCloudflare.ValidToken), (Name("mx.pending.test"), FakeCloudflare.ValidToken), (Name("mx.hidden.test"), "scoped") })
        {
            var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider(token).CreateTxtAsync(name, "v", default).AsTask());
            Assert.Contains("no active zone found for " + name, ex.Message);
            Assert.Contains("does the API token have access", ex.Message);
        }

        Assert.NotEmpty(hidden);
        Assert.Equal(0, _cf.RecordCount);
    }

    [Fact]
    public async Task Zone_lookups_pick_the_zone_of_that_exact_name_even_if_the_API_returns_something_else()
    {
        _cf.AddZone(Zone);
        _cf.Respond("zones", _ => FakeCloudflare.Json(HttpStatusCode.OK, FakeCloudflare.Envelope(new System.Text.Json.Nodes.JsonArray(
            new System.Text.Json.Nodes.JsonObject { ["id"] = "deadbeef", ["name"] = "other.test", ["status"] = "active" }))), times: 3);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name("mx.example.com"), "v", default).AsTask());

        Assert.Contains("no active zone found", ex.Message);
        Assert.Equal(0, _cf.RecordCount);
    }

    [Fact]
    public async Task A_zone_that_was_deleted_after_it_was_remembered_is_looked_up_again_by_the_next_order()
    {
        string oldId = _cf.AddZone(Zone);
        var provider = Provider();
        await provider.CreateTxtAsync(Name(Zone), "first", default);
        _cf.Fail("records.create", 404, 7003, "Could not route to /zones/x/dns_records, perhaps your object identifier is invalid?");

        var ex = await Assert.ThrowsAsync<AcmeException>(() => provider.CreateTxtAsync(Name(Zone), "second", default).AsTask());

        Assert.Contains("HTTP 404", ex.Message);
        Assert.Contains("7003", ex.Message);
        int lookups = _cf.Count("zones");
        await provider.CreateTxtAsync(Name(Zone), "third", default); // looks the zone up again, finds it, works
        Assert.True(_cf.Count("zones") > lookups);
        Assert.NotEmpty(oldId);
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Creating and deleting

    [Fact]
    public async Task Every_request_carries_the_bearer_token_and_a_created_record_is_a_TXT_with_a_short_ttl()
    {
        _cf.AddZone(Zone);
        var provider = Provider();

        string handle = await provider.CreateTxtAsync(Name(Zone), "the-digest", default);
        await provider.DeleteTxtAsync(handle, default);

        Assert.All(_cf.Requests, r => Assert.Equal("Bearer " + FakeCloudflare.ValidToken, r.Authorization));
        var create = Assert.Single(_cf.Requests, r => r.Route == "records.create");
        Assert.Equal("TXT", create.Body!["type"]!.GetValue<string>());
        Assert.Equal(Name(Zone), create.Body["name"]!.GetValue<string>());
        Assert.Equal("the-digest", create.Body["content"]!.GetValue<string>());
        Assert.Equal(60, create.Body["ttl"]!.GetValue<int>());
        Assert.Empty(_cf.RecordsIn(Zone));
    }

    [Fact]
    public async Task Several_values_at_one_name_are_separate_records_deleted_one_at_a_time()
    {
        _cf.AddZone(Zone);
        var provider = Provider();

        string wildcard = await provider.CreateTxtAsync(Name(Zone), "digest-of-wildcard", default);
        string bare = await provider.CreateTxtAsync(Name(Zone), "digest-of-base", default);

        Assert.NotEqual(wildcard, bare);
        Assert.Equal(["digest-of-base", "digest-of-wildcard"], _cf.ResolveTxt(Name(Zone)).Order(StringComparer.Ordinal));
        await provider.DeleteTxtAsync(wildcard, default);
        Assert.Equal(["digest-of-base"], _cf.ResolveTxt(Name(Zone)));
        await provider.DeleteTxtAsync(bare, default);
        Assert.Empty(_cf.ResolveTxt(Name(Zone)));
    }

    [Fact]
    public async Task Deleting_twice_or_deleting_what_is_gone_is_not_an_error()
    {
        _cf.AddZone(Zone);
        var provider = Provider();
        string handle = await provider.CreateTxtAsync(Name(Zone), "v", default);

        await provider.DeleteTxtAsync(handle, default);
        await provider.DeleteTxtAsync(handle, default);
        await provider.DeleteTxtAsync($"{_cf.ZoneId(Zone)}/ffffffffffffffffffffffffffffffff", default);

        Assert.Equal(2, _cf.Requests.Count(r => r.Route == "records.delete" && r.Status == 404));
    }

    [Theory]
    [InlineData("")]
    [InlineData("no-slash")]
    [InlineData("/record-only")]
    [InlineData("zone-only/")]
    public async Task A_damaged_handle_is_an_error_and_sends_nothing(string handle)
    {
        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().DeleteTxtAsync(handle, default).AsTask());

        Assert.Contains("handle is damaged", ex.Message);
        Assert.Empty(_cf.Requests);
    }

    [Theory]
    [InlineData("a/../../zones")]
    [InlineData("zone/rec?x=1")]
    [InlineData("zone/rec/extra")]
    [InlineData("zo ne/rec")]
    public async Task A_handle_cannot_change_the_path_of_the_request(string handle)
    {
        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().DeleteTxtAsync(handle, default).AsTask());

        Assert.Contains("not usable", ex.Message);
        Assert.Empty(_cf.Requests);
    }

    [Fact]
    public async Task An_id_in_an_answer_that_would_change_a_path_is_never_used()
    {
        _cf.AddZone(Zone);
        _cf.Respond("records.create", _ => FakeCloudflare.Json(HttpStatusCode.OK, FakeCloudflare.Envelope(new System.Text.Json.Nodes.JsonObject { ["id"] = "../../zones" })));

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.Contains("has no record id", ex.Message);
    }

    [Fact]
    public async Task A_record_that_is_there_already_is_adopted_and_deleted_with_the_order()
    {
        _cf.AddZone(Zone);
        string leftover = _cf.AddRecord(Zone, "TXT", Name(Zone), "same-digest"); // from an order that could not clean up
        var provider = Provider();

        string handle = await provider.CreateTxtAsync(Name(Zone), "same-digest", default);

        Assert.Equal($"{_cf.ZoneId(Zone)}/{leftover}", handle);
        Assert.Single(_cf.RecordsIn(Zone));
        await provider.DeleteTxtAsync(handle, default);
        Assert.Empty(_cf.RecordsIn(Zone));
    }

    [Fact]
    public async Task Adopting_looks_through_all_the_pages_of_records_at_the_name_when_the_server_caps_the_page_size()
    {
        _cf.AddZone(Zone);
        _cf.MaxPerPage = 2;
        for (int i = 0; i < 5; i++)
        {
            _cf.AddRecord(Zone, "TXT", Name(Zone), "other-" + i);
        }

        string target = _cf.AddRecord(Zone, "TXT", Name(Zone), "target");

        string handle = await Provider().CreateTxtAsync(Name(Zone), "target", default);

        Assert.EndsWith("/" + target, handle);
        Assert.Equal(3, _cf.Count("records.list")); // 2 per page: the target is the sixth of six records, on the third page
    }

    [Fact]
    public async Task A_create_whose_answer_was_lost_leaves_one_record_after_the_retry()
    {
        _cf.AddZone(Zone);
        _cf.AfterApplying("records.create", _ => FakeCloudflare.Raw(HttpStatusCode.BadGateway, "<html>502</html>", "text/html"));

        string handle = await Provider().CreateTxtAsync(Name(Zone), "v", default);

        var record = Assert.Single(_cf.RecordsIn(Zone)); // the first POST took effect; the second found it identical and adopted it
        Assert.EndsWith("/" + record.Id, handle);
        Assert.Equal([TimeSpan.FromSeconds(1)], _pauses);
    }

    [Fact]
    public async Task A_delete_whose_answer_was_lost_is_repeated_and_the_record_is_gone()
    {
        _cf.AddZone(Zone);
        var provider = Provider();
        string handle = await provider.CreateTxtAsync(Name(Zone), "v", default);
        _cf.AfterApplying("records.delete", _ => FakeCloudflare.Raw(HttpStatusCode.GatewayTimeout, "", "text/html"));

        await provider.DeleteTxtAsync(handle, default);

        Assert.Empty(_cf.RecordsIn(Zone));
        Assert.Equal(2, _cf.Count("records.delete")); // the repeat found the record already deleted (404): as good as deleted
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Errors

    [Fact]
    public async Task A_bad_token_is_a_403_with_Cloudflares_words_and_a_hint_and_is_not_retried()
    {
        _cf.AddZone(Zone);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider("revoked-or-mistyped-token").CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.Contains("HTTP 403", ex.Message);
        Assert.Contains("9109: Invalid access token", ex.Message);
        Assert.Contains("Zone:Read", ex.Message);
        Assert.DoesNotContain("revoked-or-mistyped-token", ex.Message);
        Assert.Equal(1, _cf.Count("zones"));
        Assert.Empty(_pauses);
        Assert.False(ex.Transient);
    }

    [Fact]
    public async Task A_token_that_may_read_zones_but_not_edit_DNS_fails_at_the_record_with_Cloudflares_words()
    {
        _cf.AddZone(Zone);
        _cf.Tokens["read-only"] = new CloudflareToken(EditDns: false);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider("read-only").CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.Contains("could not create the TXT record", ex.Message);
        Assert.Contains("HTTP 403", ex.Message);
        Assert.Contains("10000: Authentication error", ex.Message);
        Assert.Equal(0, _cf.RecordCount);
    }

    [Fact]
    public async Task A_token_without_zone_read_cannot_find_the_zone()
    {
        _cf.AddZone(Zone);
        _cf.Tokens["dns-only"] = new CloudflareToken(ReadZones: false);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider("dns-only").CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.Contains("could not look up the zone", ex.Message);
        Assert.Contains("HTTP 403", ex.Message);
        Assert.Contains("Zone:Read", ex.Message);
    }

    [Fact]
    public async Task A_400_with_an_error_envelope_is_reported_with_all_its_errors_up_to_three()
    {
        _cf.AddZone(Zone);
        _cf.Respond("records.create", _ => FakeCloudflare.Json(HttpStatusCode.BadRequest, new System.Text.Json.Nodes.JsonObject
        {
            ["success"] = false,
            ["errors"] = new System.Text.Json.Nodes.JsonArray(
                new System.Text.Json.Nodes.JsonObject { ["code"] = 9005, ["message"] = "first" },
                new System.Text.Json.Nodes.JsonObject { ["code"] = 9006, ["message"] = "second" },
                new System.Text.Json.Nodes.JsonObject { ["code"] = 9007, ["message"] = "third" },
                new System.Text.Json.Nodes.JsonObject { ["code"] = 9008, ["message"] = "fourth" }),
        }));

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.Contains("HTTP 400, 9005: first; 9006: second; 9007: third)", ex.Message);
        Assert.DoesNotContain("fourth", ex.Message);
        Assert.False(ex.Transient);
    }

    [Fact]
    public async Task A_200_that_says_success_false_is_a_failure()
    {
        _cf.AddZone(Zone);
        _cf.Respond("records.create", _ => FakeCloudflare.Json(HttpStatusCode.OK, new System.Text.Json.Nodes.JsonObject
        {
            ["success"] = false,
            ["errors"] = new System.Text.Json.Nodes.JsonArray(new System.Text.Json.Nodes.JsonObject { ["code"] = 1004, ["message"] = "DNS Validation Error" }),
            ["result"] = new System.Text.Json.Nodes.JsonObject { ["id"] = "abc" },
        }));

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.Contains("1004: DNS Validation Error", ex.Message);
    }

    [Fact]
    public async Task Control_characters_and_enormous_texts_in_Cloudflares_errors_are_cut_to_printable_ASCII()
    {
        _cf.AddZone(Zone);
        _cf.Fail("records.create", 400, 1, "line one\r\nline two\u0007 é" + new string('x', 5000));

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.DoesNotContain('\n', ex.Message);
        Assert.DoesNotContain('\r', ex.Message);
        Assert.All(ex.Message, c => Assert.InRange(c, ' ', '~'));
        Assert.True(ex.Message.Length < 600, ex.Message.Length.ToString());
    }

    [Fact]
    public async Task A_message_that_repeats_the_token_is_redacted()
    {
        _cf.AddZone(Zone);
        _cf.Fail("records.create", 400, 1, "bad header Authorization: Bearer " + FakeCloudflare.ValidToken);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.DoesNotContain(FakeCloudflare.ValidToken, ex.Message);
        Assert.Contains("[token]", ex.Message);
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Rate limits, server errors, the network

    [Fact]
    public async Task A_rate_limit_with_a_short_retry_after_is_waited_for_and_the_request_repeated()
    {
        _cf.AddZone(Zone);
        _cf.Fail("zones", 429, 971, "Rate limited", retryAfterSeconds: 2);

        await Provider().CreateTxtAsync(Name(Zone), "v", default);

        Assert.Equal([TimeSpan.FromSeconds(2)], _pauses);
        Assert.Single(_cf.RecordsIn(Zone));
    }

    [Fact]
    public async Task A_rate_limit_without_retry_after_backs_off_one_then_two_seconds_and_gives_up_after_three_attempts()
    {
        _cf.AddZone(Zone);
        _cf.Fail("zones", 429, 971, "Rate limited", times: 10);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.Contains("HTTP 429", ex.Message);
        Assert.Contains("971: Rate limited", ex.Message);
        Assert.True(ex.Transient);
        Assert.Equal(3, _cf.Count("zones"));
        Assert.Equal([TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2)], _pauses);
    }

    [Fact]
    public async Task A_long_retry_after_ends_the_call_at_once_carrying_the_wait_for_the_renewal_back_off()
    {
        _cf.AddZone(Zone);
        _cf.Fail("zones", 429, 971, "Rate limited", retryAfterSeconds: 300);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.Equal(TimeSpan.FromMinutes(5), ex.RetryAfter);
        Assert.Contains("asks to wait 300 seconds", ex.Message);
        Assert.Equal(1, _cf.Count("zones"));
        Assert.Empty(_pauses);
        // The renewal service waits at least that long before the next order.
        Assert.Equal(TimeSpan.FromMinutes(10), AcmeRenewalService.WaitAfterFailure(1, ex)); // the back-off is longer than five minutes
        Assert.Equal(TimeSpan.FromMinutes(5), ex.RetryAfter);
    }

    [Theory]
    [InlineData(500)]
    [InlineData(502)]
    [InlineData(503)]
    [InlineData(504)]
    public async Task A_server_error_is_retried_and_a_recovery_is_taken(int status)
    {
        _cf.AddZone(Zone);
        _cf.Fail("zones", status, 0, "Internal Server Error", times: 2);

        await Provider().CreateTxtAsync(Name(Zone), "v", default);

        Assert.Equal([TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2)], _pauses);
        Assert.Single(_cf.RecordsIn(Zone));
    }

    [Fact]
    public async Task A_server_error_that_does_not_go_away_is_a_transient_failure_after_three_attempts()
    {
        _cf.AddZone(Zone);
        _cf.Fail("records.create", 500, 0, "Internal Server Error", times: 10);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.True(ex.Transient);
        Assert.Contains("HTTP 500", ex.Message);
        Assert.Equal(3, _cf.Count("records.create"));
    }

    [Fact]
    public async Task A_timeout_is_retried_and_three_in_a_row_are_a_transient_failure()
    {
        _cf.AddZone(Zone);
        _cf.Throw("zones", new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout of 30 seconds elapsing.", new TimeoutException()), times: 2);
        var provider = Provider();

        await provider.CreateTxtAsync(Name(Zone), "v", default);

        Assert.Equal([TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2)], _pauses);
        _cf.Throw("records.create", new TaskCanceledException("timeout", new TimeoutException()), times: 3);
        var ex = await Assert.ThrowsAsync<AcmeException>(() => provider.CreateTxtAsync(Name(Zone), "w", default).AsTask());
        Assert.True(ex.Transient);
        Assert.Contains("no answer in time", ex.Message);
    }

    [Fact]
    public async Task A_reset_connection_is_retried_and_its_message_never_carries_the_token()
    {
        _cf.AddZone(Zone);
        _cf.Throw("zones", new HttpRequestException("The SSL connection could not be established (Authorization: Bearer " + FakeCloudflare.ValidToken + ")"), times: 3);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.True(ex.Transient);
        Assert.Contains("could not look up the zone", ex.Message);
        Assert.DoesNotContain(FakeCloudflare.ValidToken, ex.Message);
        Assert.Equal(3, _cf.Count("zones"));
    }

    [Fact]
    public async Task Cancelling_is_a_cancellation_not_a_failure_and_nothing_is_retried()
    {
        _cf.AddZone(Zone);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Provider().CreateTxtAsync(Name(Zone), "v", cts.Token).AsTask());

        Assert.Empty(_cf.Requests);
        Assert.Empty(_pauses);
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Answers that are not what the API documents

    [Fact]
    public async Task An_HTML_error_page_from_a_proxy_is_a_failure_that_says_the_answer_was_not_Cloudflares()
    {
        _cf.AddZone(Zone);
        _cf.Respond("zones", _ => FakeCloudflare.Raw(HttpStatusCode.BadGateway, "<html><body>502 Bad Gateway</body></html>", "text/html"), times: 3);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.Contains("HTTP 502", ex.Message);
        Assert.Contains("not a Cloudflare JSON envelope", ex.Message);
        Assert.DoesNotContain("<html>", ex.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{\"success\":true,\"result\":[")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("\"text\"")]
    public async Task A_200_with_a_body_that_is_not_the_envelope_is_never_taken_for_a_zone(string body)
    {
        _cf.AddZone(Zone);
        _cf.Respond("zones", _ => FakeCloudflare.Raw(HttpStatusCode.OK, body), times: 5);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name("mx.example.com"), "v", default).AsTask());

        Assert.Contains("could not look up the zone (HTTP 200, the answer was not a Cloudflare JSON envelope)", ex.Message);
        Assert.Equal(0, _cf.RecordCount);
    }

    [Fact]
    public async Task An_envelope_without_a_result_finds_no_zone()
    {
        _cf.AddZone(Zone);
        _cf.Respond("zones", _ => FakeCloudflare.Raw(HttpStatusCode.OK, "{}"), times: 5);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name("mx.example.com"), "v", default).AsTask());

        Assert.Contains("no active zone found", ex.Message);
    }

    [Theory]
    [InlineData("{\"success\":true,\"result\":null}")]
    [InlineData("{\"success\":true,\"result\":{}}")]
    [InlineData("{\"success\":true,\"result\":{\"id\":12}}")]
    [InlineData("{\"success\":true,\"result\":[1,2]}")]
    [InlineData("not json at all")]
    public async Task A_create_answer_without_a_usable_record_id_is_a_failure(string body)
    {
        _cf.AddZone(Zone);
        _cf.Respond("records.create", _ => FakeCloudflare.Raw(HttpStatusCode.OK, body));

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name(Zone), "v", default).AsTask());

        Assert.StartsWith("Cloudflare:", ex.Message);
    }

    [Fact]
    public async Task An_enormous_answer_is_not_read_beyond_a_megabyte_and_is_a_failure()
    {
        _cf.AddZone(Zone);
        var served = new CountingZeroStream(512L * 1024 * 1024); // 512 MiB on offer, produced only as it is read
        _cf.Respond("zones", _ =>
        {
            var content = new StreamContent(served);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = content };
        }, times: 5);

        var ex = await Assert.ThrowsAsync<AcmeException>(() => Provider().CreateTxtAsync(Name("mx.example.com"), "v", default).AsTask());

        Assert.Contains("the answer was not a Cloudflare JSON envelope", ex.Message);
        Assert.InRange(served.BytesRead, 1, 2 * 1024 * 1024); // it stopped reading at the cap instead of buffering what the server kept sending
    }

    private sealed class CountingZeroStream(long length) : Stream
    {
        private long _read;

        public long BytesRead => Interlocked.Read(ref _read);

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => length;

        public override long Position { get => _read; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            int n = (int)Math.Min(buffer.Length, length - _read);
            buffer[..n].Fill((byte)'x');
            Interlocked.Add(ref _read, n);
            return n;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => ValueTask.FromResult(Read(buffer.Span));

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task A_delete_that_Cloudflare_refuses_is_an_error_the_runner_will_log_and_a_404_is_not()
    {
        _cf.AddZone(Zone);
        var provider = Provider();
        string handle = await provider.CreateTxtAsync(Name(Zone), "v", default);
        _cf.Fail("records.delete", 403, 10000, "Authentication error");

        var ex = await Assert.ThrowsAsync<AcmeException>(() => provider.DeleteTxtAsync(handle, default).AsTask());

        Assert.Contains("could not delete the TXT record", ex.Message);
        Assert.Contains("HTTP 403", ex.Message);
        Assert.Single(_cf.RecordsIn(Zone)); // left behind; the runner's warning names the handle
    }

    // ---------------------------------------------------------------------------------------------------------------------------------
    // The token

    [Theory]
    [InlineData(FakeCloudflare.ValidToken + "\n")]
    [InlineData("  " + FakeCloudflare.ValidToken + "\r\n")]
    [InlineData("\t" + FakeCloudflare.ValidToken)]
    public async Task A_token_with_the_line_end_or_blanks_it_was_pasted_with_works(string pasted)
    {
        _cf.AddZone(Zone);

        await Provider(pasted).CreateTxtAsync(Name(Zone), "v", default);

        Assert.All(_cf.Requests, r => Assert.Equal("Bearer " + FakeCloudflare.ValidToken, r.Authorization));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("two words")]
    [InlineData("inner\nnewline-secret-part")]
    [InlineData("närrow-secret-token")]
    public void A_token_that_cannot_be_sent_is_refused_at_once_without_echoing_it(string token)
    {
        var ex = Assert.Throws<ArgumentException>(() => new CloudflareDnsChallengeProvider(new HttpClient(_cf), token));

        Assert.DoesNotContain("secret", ex.Message);
        Assert.DoesNotContain("two words", ex.Message);
        Assert.Contains("Acme:CloudflareApiToken", ex.Message);
    }

    [Fact]
    public async Task The_token_is_in_no_message_whatever_goes_wrong()
    {
        _cf.AddZone(Zone);
        var provider = Provider();
        var messages = new List<string>();
        foreach (var script in new Action[]
        {
            () => _cf.Fail("zones", 403, 9109, "Invalid access token", times: 1),
            () => _cf.Fail("zones", 429, 971, "Rate limited", times: 3),
            () => _cf.Respond("zones", _ => FakeCloudflare.Raw(HttpStatusCode.BadGateway, "echo " + FakeCloudflare.ValidToken, "text/plain"), times: 3),
            () => _cf.Throw("zones", new HttpRequestException("Bearer " + FakeCloudflare.ValidToken), times: 3),
            () => _cf.Throw("zones", new TaskCanceledException("timeout", new TimeoutException()), times: 3),
        })
        {
            script();
            var ex = await Assert.ThrowsAsync<AcmeException>(() => provider.CreateTxtAsync(Name("mx.example.com"), "v", default).AsTask());
            messages.Add(ex.Message);
            messages.Add(ex.ToString().Split("---> ", 2)[0]);
        }

        Assert.All(messages, m => Assert.DoesNotContain(FakeCloudflare.ValidToken, m));
    }

    // ---------------------------------------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(1, 0, 600)]
    [InlineData(1, 120, 600)]
    [InlineData(1, 3600, 3600)]
    [InlineData(1, 10 * 86400, 86400)]
    [InlineData(4, 600, 4800)]
    public void A_retry_after_on_a_failed_order_lengthens_the_back_off_within_a_day(int failures, int retryAfterSeconds, int expectedSeconds)
    {
        var error = new AcmeException("Cloudflare: could not create the TXT record (HTTP 429)", transient: true, retryAfter: retryAfterSeconds == 0 ? null : TimeSpan.FromSeconds(retryAfterSeconds));

        Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), AcmeRenewalService.WaitAfterFailure(failures, error));
    }

    [Fact]
    public void Another_kind_of_exception_has_the_plain_back_off()
    {
        Assert.Equal(TimeSpan.FromMinutes(20), AcmeRenewalService.WaitAfterFailure(2, new InvalidOperationException("x")));
    }
}
