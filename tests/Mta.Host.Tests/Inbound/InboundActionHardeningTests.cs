using System.Net;
using System.Text;
using System.Text.Json;
using Mta.Core;
using Mta.Host.Inbound;
using Mta.Storage;

namespace Mta.Host.Tests.Inbound;

/// <summary>The cases of the independent review of the route action runner: owners, claims, shutdown, failures nobody planned for, notices and payload size.</summary>
[Collection("inbound-actions")]
public class InboundActionHardeningTests
{
    private static async Task WaitUntilAsync(Func<Task<bool>> condition)
    {
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        while (!await condition().ConfigureAwait(false))
        {
            await Task.Delay(5, limit.Token);
        }
    }

    [Fact]
    public async Task Every_runner_has_an_owner_name_of_its_own_even_when_they_start_in_the_same_millisecond()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        string[] owners = Enumerable.Range(0, 200).Select(_ => h.CreateRunner().Owner).ToArray();

        Assert.Equal(200, owners.Distinct().Count());
        Assert.All(owners, o => Assert.Matches("^inbound-[0-9a-f]{32}$", o));   // a whole GUID, not the millisecond field of a time-ordered one
    }

    [Fact]
    public async Task A_runner_that_claims_a_row_again_after_its_lease_ran_out_does_not_let_the_first_attempt_overwrite_the_second()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        var hold = new TaskCompletionSource();
        var inFlight = new TaskCompletionSource();
        int calls = 0;
        h.Receiver.Respond(HttpStatusCode.OK, HttpStatusCode.InternalServerError);   // the held first attempt answers last, so it gets the 500
        h.Receiver.Gate = async () =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                inFlight.TrySetResult();
                await hold.Task;   // only the first attempt is held
            }
        };
        InboundMessageDraft draft = await h.ReceiveAsync();

        Task<int> first = h.Runner.RunOnceAsync(default);
        await inFlight.Task;
        h.Clock.Advance(TimeSpan.FromMinutes(3));   // the lease (2 minutes) ran out while the first attempt is still talking to its receiver
        Assert.Equal(1, await h.Runner.RunOnceAsync(default));   // the SAME runner (same owner name) claims it again: attempt 2, which succeeds
        Assert.Equal(InboundActionState.Done, (await h.GetAsync(draft.Id)).ActionState);

        hold.SetResult();
        await first;   // the first attempt ends in a 500 and tries to record a retry with its old claim token

        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Done, stored.ActionState);   // the stale completion changed nothing
        Assert.Null(stored.ActionLastError);
        Assert.Empty(h.Publisher.Published);
    }

    [Fact]
    public async Task Stopping_in_the_middle_of_an_attempt_gives_the_attempt_back_and_the_next_runner_starts_the_rung_over()
    {
        await using var h = await new InboundActionHarness(new InboundActionOptions { PollInterval = TimeSpan.FromMilliseconds(20) }).InitializeAsync();
        var inFlight = new TaskCompletionSource();
        var never = new TaskCompletionSource();
        h.Receiver.Gate = async () =>
        {
            inFlight.TrySetResult();
            await never.Task;
        };
        InboundMessageDraft draft = await h.ReceiveAsync();
        using var cts = new CancellationTokenSource();
        Task loop = h.Runner.RunAsync(cts.Token);
        await inFlight.Task;

        await cts.CancelAsync();
        await loop.WaitAsync(TimeSpan.FromSeconds(30));

        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Pending, stored.ActionState);
        Assert.Equal(0, stored.ActionAttempts);   // the attempt was not made to the end: it is not used up
        Assert.True(stored.ActionNextAttemptAt <= h.Clock.UtcNow);   // due at once
        never.SetResult();
    }

    [Fact]
    public async Task Something_nobody_planned_for_is_one_failed_attempt_on_the_ladder_not_a_lease_that_runs_out()
    {
        await using var h = await new InboundActionHarness().InitializeAsync(InboundActionKind.Forward, withForwarder: true);
        h.Forwarder.Handler = (_, _, _) => throw new InvalidOperationException("a bug on a hostile message");
        InboundMessageDraft draft = await h.ReceiveAsync();

        await h.RunAsync();

        InboundMessage stored = await h.GetAsync(draft.Id);
        Assert.Equal(InboundActionState.Pending, stored.ActionState);
        Assert.Equal("internal_error", stored.ActionLastError);
        Assert.Equal(h.Clock.UtcNow + TimeSpan.FromSeconds(10), stored.ActionNextAttemptAt);
        Assert.DoesNotContain("hostile", stored.ActionLastError, StringComparison.Ordinal);   // the exception text is for the log

        // And it reaches the end of the ladder.
        for (int i = 0; i < 3; i++)
        {
            h.Clock.Advance(TimeSpan.FromMinutes(11));
            await h.RunAsync();
        }

        Assert.Equal(InboundActionState.Failed, (await h.GetAsync(draft.Id)).ActionState);
    }

    [Fact]
    public async Task A_key_ring_that_is_down_is_a_deferral_a_secret_that_is_not_a_secret_is_final_and_nothing_is_sent_without_a_signature()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        InboundMessageDraft first = await h.ReceiveAsync();
        h.KeysDown = true;
        await h.RunAsync();
        InboundMessage deferred = await h.GetAsync(first.Id);
        Assert.Equal(InboundActionState.Pending, deferred.ActionState);
        Assert.Equal("secret_unreadable", deferred.ActionLastError);
        Assert.Empty(h.Receiver.Requests);

        h.KeysDown = false;
        h.Clock.Advance(TimeSpan.FromSeconds(10));
        await h.RunAsync();
        Assert.Equal(InboundActionState.Done, (await h.GetAsync(first.Id)).ActionState);   // the ring is back: delivered

        // A stored secret with no value at all would sign nothing.
        await h.Storage.Config.UpsertWebhookEndpointAsync(h.Endpoint with { SecretProtected = Encoding.UTF8.GetBytes("   ") }, default);
        InboundMessageDraft second = await h.ReceiveAsync();
        int before = h.Receiver.Requests.Count;
        await h.RunAsync();
        Assert.Equal(before, h.Receiver.Requests.Count);
        Assert.Equal(InboundActionState.Failed, (await h.GetAsync(second.Id)).ActionState);
    }

    [Fact]
    public async Task A_dead_receiver_makes_one_notice_a_minute_per_route_and_the_next_says_how_many_were_left_out()
    {
        await using var h = await new InboundActionHarness(new InboundActionOptions { RetrySchedule = [], Concurrency = 8, MaxConcurrencyPerTenant = 8 }).InitializeAsync();   // one attempt: a failure is final
        h.Receiver.Respond(HttpStatusCode.InternalServerError);
        for (int i = 0; i < 5; i++)
        {
            await h.ReceiveAsync();
        }

        await h.RunAsync();

        Assert.Single(h.Publisher.Published);   // five messages gave up, the tenant is told once
        Assert.Equal(5, (await h.Storage.Inbound.SearchAsync(new InboundMessageQuery(h.TenantId, ActionState: InboundActionState.Failed), default)).Items.Count);   // every message still shows its failure

        h.Clock.Advance(TimeSpan.FromMinutes(2));
        await h.ReceiveAsync();
        await h.RunAsync();
        Assert.Equal(2, h.Publisher.Published.Count);
        Assert.Equal(4, JsonDocument.Parse(h.Publisher.Published.Last().Draft.PayloadJson).RootElement.GetProperty("data").GetProperty("suppressed").GetInt32());
        Assert.False(JsonDocument.Parse(h.Publisher.Published.First().Draft.PayloadJson).RootElement.GetProperty("data").TryGetProperty("suppressed", out _));
    }

    [Fact]
    public async Task The_counts_of_the_gauge_come_from_two_cheap_counts_and_are_not_taken_while_inbound_is_off()
    {
        await using var h = await new InboundActionHarness(new InboundActionOptions { PollInterval = TimeSpan.FromMilliseconds(20) }).InitializeAsync();
        h.InboundEnabled = false;
        await h.ReceiveAsync();
        using var cts = new CancellationTokenSource();
        Task loop = h.Runner.RunAsync(cts.Token);
        await WaitUntilAsync(async () => (await h.GetAsync((await h.Storage.Inbound.SearchAsync(new InboundMessageQuery(h.TenantId), default)).Items[0].Id)).ActionLastError == "inbound_disabled");   // it deferred the message, which needs no count
        Assert.Null(h.Runner.LatestCounts);

        h.InboundEnabled = true;
        h.Runner.Wake();
        await WaitUntilAsync(() => Task.FromResult(h.Runner.LatestCounts is not null));
        Assert.Equal(1, h.Runner.LatestCounts!.Pending);
        await cts.CancelAsync();
        await loop.WaitAsync(TimeSpan.FromSeconds(30));
    }

    // ---- the payload

    private static byte[] ManyAttachments(int count)
    {
        var sb = new StringBuilder("From: a@sender.test\r\nTo: b@example.com\r\nSubject: many\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n");
        for (int i = 0; i < count; i++)
        {
            sb.Append("--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"f").Append(i).Append(".bin\"\r\n\r\nx\r\n");
        }

        sb.Append("--b--\r\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    [Fact]
    public async Task At_most_200_attachments_are_listed_in_the_payload()
    {
        await using var h = await new InboundActionHarness().InitializeAsync();
        await h.ReceiveAsync(ManyAttachments(250));

        await h.RunAsync();

        JsonElement attachments = JsonDocument.Parse(Assert.Single(h.Receiver.Requests).Body).RootElement.GetProperty("data").GetProperty("attachments");
        Assert.Equal(InboundWebhookPayload.MaxAttachmentsListed, attachments.GetArrayLength());
    }

    [Fact]
    public void The_whole_document_is_capped_not_only_the_text_html_goes_first_and_truncated_says_so()
    {
        // 200,000 characters that JSON escapes to six bytes each: far over the cap as a whole, though each part is under MaxTextBytes.
        string heavy = new('ü', 200_000);
        byte[] raw = Encoding.UTF8.GetBytes($"From: a@sender.test\r\nSubject: s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{heavy}\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>{heavy}</p>\r\n--b--\r\n");
        InboundMessage message = new(
            Ids.New(), Ids.New(), Ids.New(), "example.com", DateTimeOffset.UtcNow, "203.0.113.9", "h", true, "a@sender.test", "b@example.com", "s", raw.Length, InboundAuthResults.NotChecked,
            InboundDmarcDisposition.None, null, InboundActionKind.Webhook, InboundActionState.Pending, 1, null, null, null, null, true);
        var limits = new InboundWebhookLimits(256 * 1024, null, MaxPayloadBytes: 1024 * 1024);

        byte[] json = InboundWebhookPayload.BuildJson(message, raw, "evt_x", limits);

        Assert.True(json.Length <= limits.MaxPayloadBytes, $"{json.Length} bytes");
        JsonElement body = JsonDocument.Parse(json).RootElement.GetProperty("data").GetProperty("message");
        Assert.True(body.GetProperty("truncated").GetBoolean());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("html").ValueKind);   // the HTML is dropped first
        Assert.Equal(JsonValueKind.String, body.GetProperty("text").ValueKind);
    }
}
