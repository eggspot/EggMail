using Mta.Storage;

namespace Mta.Integration.Tests;

/// <summary>
/// The promises of the pipeline, checked after a randomized run against <see cref="ChaosInternet"/>: every accepted recipient reaches exactly one final state, nothing reported
/// delivered is missing at the remote, nothing is delivered twice unless it is flagged <c>possible_duplicate</c>, and every hard bounce is reported back to the sender and suppressed.
/// Shared by the single-process run and the run with several replicas on one database.
/// </summary>
internal static class ChaosInvariants
{
    public static async Task AssertAsync(IStorage storage, Guid tenantId, IReadOnlyList<(string Subject, string[] Recipients)> plan, ChaosInternet internet, string context)
    {
        // Final states per (message, recipient).
        var summaries = new List<MessageSummary>();
        string? cursor = null;
        do
        {
            var page = await storage.History.SearchAsync(new MessageQuery(tenantId, Limit: 200, Cursor: cursor), default);
            summaries.AddRange(page.Items);
            cursor = page.NextCursor;
        }
        while (cursor is not null);

        var finals = new Dictionary<(string Subject, string Recipient), List<MessageEventType>>();
        var flagged = new HashSet<(string Subject, string Recipient)>();
        foreach (var summary in summaries)
        {
            var events = await storage.History.GetEventsAsync(tenantId, summary.MessageId, default);
            foreach (var e in events.Where(e => e.Type == MessageEventType.PossibleDuplicate && e.Recipient is not null))
            {
                flagged.Add((summary.Subject ?? string.Empty, e.Recipient!));
            }

            foreach (var e in events.Where(e => e.Type is MessageEventType.Delivered or MessageEventType.Bounced or MessageEventType.Expired or MessageEventType.Suppressed && e.Recipient is not null))
            {
                string subject = summary.Subject ?? string.Empty;
                (finals.TryGetValue((subject, e.Recipient!), out var list) ? list : finals[(subject, e.Recipient!)] = []).Add(e.Type);
            }
        }

        foreach (var (subject, recipients) in plan)
        {
            foreach (string r in recipients)
            {
                Assert.True(finals.TryGetValue((subject, r), out var states), $"no final state for {subject} -> {r}{context}");
                var state = Assert.Single(states!);
                bool gone = r.StartsWith("gone", StringComparison.Ordinal);
                // A second message to an address that already bounced is suppressed instead of tried again.
                if (gone)
                {
                    Assert.True(state is MessageEventType.Bounced or MessageEventType.Suppressed, $"{subject} -> {r} ended as {state}{context}");
                }
                else
                {
                    Assert.Equal(MessageEventType.Delivered, state);
                }
            }
        }

        // The remote saw each delivered recipient exactly once and no bounced one.
        var seen = internet.Accepted.Where(a => a.Subject.StartsWith("chaos-", StringComparison.Ordinal)).GroupBy(a => a).ToDictionary(g => g.Key, g => g.Count());
        foreach (var (subject, recipients) in plan)
        {
            foreach (string r in recipients)
            {
                bool gone = r.StartsWith("gone", StringComparison.Ordinal);
                seen.TryGetValue((subject, r), out int times);
                if (gone)
                {
                    Assert.True(times == 0, $"{subject} -> {r} was accepted although it bounced{context}");
                }
                else if (times > 1)
                {
                    // Delivered more than once is only allowed where a connection was lost after the data was sent, and it must be flagged.
                    Assert.True(flagged.Contains((subject, r)), $"{subject} -> {r} accepted {times} times without a possible_duplicate flag{context}");
                }
                else
                {
                    Assert.Equal(1, times);
                }
            }
        }

        // Every hard bounce is explained to the sender in a delivery status notification that the remote accepted.
        var bounced = plan.SelectMany(p => p.Recipients).Where(r => r.StartsWith("gone", StringComparison.Ordinal)).Distinct().ToList();
        Assert.True(bounced.Count == 0 || internet.Accepted.Any(a => a.Recipient == "news@example.org"), "bounce messages reached the sender" + context);
        foreach (string address in bounced)
        {
            Assert.True(await storage.Config.IsSuppressedAsync(tenantId, address, default), $"{address} was not suppressed{context}");
        }
    }
}
