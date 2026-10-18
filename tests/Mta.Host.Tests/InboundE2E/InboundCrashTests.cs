using System.Collections.Concurrent;
using Mta.Host.Tests.Inbound;
using Mta.Storage;
using Npgsql;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>
/// A server that stops in the middle of receiving mail, on SQLite and on PostgreSQL: every message a sender was told <c>250</c> for is there afterwards, nothing is half stored, and a message exists twice
/// only when a sender did not get to see the <c>250</c> of the first attempt and sent it again (SMTP gives no way around that, design section 11.2). The senders are real concurrent connections that
/// retry the way an MTA does; the stop is the runtime and the storage closed with no flush, then opened again over the same files or database on a new port.
/// </summary>
public abstract class InboundCrashTests(LabBackend backend)
{
    private sealed class Ledger
    {
        public readonly ConcurrentDictionary<string, int> Acknowledged = new();
        public readonly ConcurrentDictionary<string, int> Ambiguous = new();
        public readonly ConcurrentDictionary<string, int> Deferred = new();
        public int TotalAcknowledged;
    }

    private static async Task SendUntilAcknowledgedAsync(InboundLab lab, Func<int> port, Ledger ledger, string id, CancellationToken stop)
    {
        string message = InboundLab.Message(subject: id, body: new string('x', 3_000) + "\r\n");
        while (!stop.IsCancellationRequested)
        {
            bool dataSent = false;
            try
            {
                await using FakeMta mta = await FakeMta.ConnectAsync(port(), expectGreeting: false);
                FakeMta.Reply greeting = await mta.ReadReplyAsync();
                if (greeting.Code != 220)
                {
                    ledger.Deferred.AddOrUpdate(id, 1, (_, n) => n + 1);
                    await Task.Delay(20, stop);
                    continue;
                }

                Assert.Equal(250, (await mta.EhloAsync("mail.sender.test")).Code);
                FakeMta.Reply r = await mta.MailFromAsync("bob@sender.test");
                if (r.Code == 250)
                {
                    r = await mta.RcptAsync("support@example.org");
                }

                if (r.Code == 250)
                {
                    dataSent = true;   // from here on a lost connection leaves the sender not knowing
                    r = await mta.DataAsync(message);
                }

                if (r.Code == 250)
                {
                    ledger.Acknowledged.AddOrUpdate(id, 1, (_, n) => n + 1);
                    Interlocked.Increment(ref ledger.TotalAcknowledged);
                    return;
                }

                dataSent = false;   // a reply was read: the sender knows this attempt did not store anything
                ledger.Deferred.AddOrUpdate(id, 1, (_, n) => n + 1);
                Assert.True(r.Code / 100 == 4, $"{id}: {r}");   // a stop is only ever a temporary failure for the sender
            }
            catch (Exception ex) when (ex is IOException or EndOfStreamException or System.Net.Sockets.SocketException or ObjectDisposedException or InvalidOperationException)
            {
                if (dataSent)
                {
                    ledger.Ambiguous.AddOrUpdate(id, 1, (_, n) => n + 1);
                }
                else
                {
                    ledger.Deferred.AddOrUpdate(id, 1, (_, n) => n + 1);
                }
            }

            await Task.Delay(20, stop);
        }
    }

    // The clock of the lab stands still, so a per-minute limit would never lift: these tests are about the stop, not about the limits.
    internal static LabOptions Open() => new() { Inbound = new Mta.Host.Configuration.InboundSection { Enabled = true, CheckSpfForInternalClients = true, MaxMessagesPerMinute = 1_000_000, MaxMessagesPerMinutePerRemote = 1_000_000 } };

    private async Task RunAsync(Func<InboundLab, Task> stopTheServer)
    {
        await using InboundLab? lab = await InboundLab.StartAsync(backend, Open());
        if (lab is null)
        {
            return;
        }

        var ledger = new Ledger();
        using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(2));   // a hang guard, not a timing assertion
        int currentPort = lab.Port;
        string[] ids = [.. Enumerable.Range(0, 120).Select(i => $"crash-{i:D3}")];
        Task[] senders = Enumerable.Range(0, 6).Select(worker => Task.Run(async () =>
        {
            for (int i = worker; i < ids.Length; i += 6)
            {
                await SendUntilAcknowledgedAsync(lab, () => Volatile.Read(ref currentPort), ledger, ids[i], stop.Token);
            }
        })).ToArray();

        // Stop the server once a good part of the mail is in, with the senders still at work.
        while (Volatile.Read(ref ledger.TotalAcknowledged) < 40 && !senders.All(s => s.IsCompleted))
        {
            await Task.Delay(5);
        }

        int acknowledgedBefore = Volatile.Read(ref ledger.TotalAcknowledged);
        await stopTheServer(lab);
        Volatile.Write(ref currentPort, lab.Port);
        await Task.WhenAll(senders);

        IReadOnlyList<InboundMessage> stored = await lab.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, Limit: 200));
        Assert.True(acknowledgedBefore >= 1);
        foreach (string id in ids)
        {
            InboundMessage[] copies = [.. stored.Where(m => m.Subject == id)];
            int acknowledged = ledger.Acknowledged.GetValueOrDefault(id);
            int ambiguous = ledger.Ambiguous.GetValueOrDefault(id);
            Assert.Equal(1, acknowledged);   // every sender ended with a 250
            Assert.True(copies.Length >= 1, $"{id}: acknowledged and not stored");
            Assert.True(copies.Length <= 1 + ambiguous, $"{id}: stored {copies.Length} times after {ambiguous} attempts whose answer was lost");
            foreach (InboundMessage copy in copies)
            {
                Assert.True(copy.HasRaw);
                string raw = await lab.RawAsync(copy);   // the body is there, whole
                Assert.EndsWith(new string('x', 3_000) + "\r\n\r\n", raw, StringComparison.Ordinal);
                Assert.Equal(InboundActionState.Done, copy.ActionState);
            }
        }

        Assert.InRange(stored.Count, ids.Length, ids.Length + ledger.Ambiguous.Values.Sum());
        Assert.Equal(stored.Count, stored.Select(m => m.Id).Distinct().Count());
        Assert.All(stored, m => Assert.Contains(m.Subject!, ids));   // nothing but what was sent: no phantom rows
        // The server is fully usable afterwards.
        Assert.Equal(250, (await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: "after the stop"))).Code);
        await lab.AssertNothingWasSentAsync();
    }

    [Fact]
    public async Task A_stop_with_no_flush_in_the_middle_of_receiving_loses_no_acknowledged_message()
    {
        await RunAsync(lab => lab.RestartAsync(crash: true));
    }

    [Fact]
    public async Task A_graceful_restart_in_the_middle_of_receiving_loses_no_acknowledged_message()
    {
        await RunAsync(lab => lab.RestartAsync(crash: false));
    }
}

/// <summary>PostgreSQL only: the database server drops every connection of the receiver while mail is arriving.</summary>
public sealed class PostgresInboundConnectionLossTests
{
    // The test's own reads share the pool with the receiver: the last kill may have closed a connection the pool still holds, and the first read on it fails. A client would read again.
    private static async Task<T> ReadAgainAsync<T>(Func<Task<T>> read)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                return await read();
            }
            catch (Exception ex) when (attempt < 5 && ex is not Xunit.Sdk.XunitException)
            {
                await Task.Delay(50);
            }
        }
    }

    [Fact]
    public async Task Connections_dropped_by_the_database_server_while_mail_arrives_give_the_sender_a_temporary_failure_and_never_a_half_stored_message()
    {
        await using InboundLab? lab = await InboundLab.StartAsync(LabBackend.Postgres, InboundCrashTests.Open());
        if (lab is null)
        {
            return;
        }

        string connectionString = lab.StorageOptions.Postgres.RuntimeConnectionString!;
        var database = new NpgsqlConnectionStringBuilder(connectionString).Database;
        using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        int acknowledged = 0, temporary = 0;
        var ids = Enumerable.Range(0, 80).Select(i => $"drop-{i:D3}").ToArray();
        Task[] senders = Enumerable.Range(0, 4).Select(worker => Task.Run(async () =>
        {
            for (int i = worker; i < ids.Length; i += 4)
            {
                while (!stop.IsCancellationRequested)
                {
                    FakeMta.Reply reply = await lab.SendAsync("bob@sender.test", "support@example.org", InboundLab.Message(subject: ids[i], body: new string('y', 2_000) + "\r\n"));
                    if (reply.Code == 250)
                    {
                        Interlocked.Increment(ref acknowledged);
                        break;
                    }

                    Assert.Equal(4, reply.Code / 100);   // the database being gone is a temporary failure for the sender: 451 or 452, never a refusal
                    Interlocked.Increment(ref temporary);
                    await Task.Delay(10, stop.Token);
                }
            }
        })).ToArray();

        // Drop every other connection to the database a few times while the senders work.
        for (int round = 0; round < 5 && !senders.All(s => s.IsCompleted); round++)
        {
            await Task.Delay(40);
            await using var admin = new NpgsqlConnection(Mta.Storage.Postgres.Tests.PostgresTestServer.Instance.AdminConnectionString);
            await admin.OpenAsync();
            await using var kill = new NpgsqlCommand("select pg_terminate_backend(pid) from pg_stat_activity where datname = @db and pid <> pg_backend_pid()", admin);
            kill.Parameters.AddWithValue("db", database!);
            await kill.ExecuteScalarAsync();
        }

        await Task.WhenAll(senders);

        IReadOnlyList<InboundMessage> stored = await ReadAgainAsync(() => lab.MessagesAsync(InboundLab.Acme, new InboundMessageQuery(InboundLab.Acme, Limit: 200)));
        Assert.Equal(ids.Length, acknowledged);
        Assert.Equal(ids.OrderBy(x => x, StringComparer.Ordinal), stored.Select(m => m.Subject!).Order(StringComparer.Ordinal));   // each exactly once: the sender always saw the answer here
        foreach (InboundMessage m in stored)
        {
            Assert.True(m.HasRaw);
            Assert.NotNull(await ReadAgainAsync(async () => await lab.Storage.Inbound.GetRawAsync(InboundLab.Acme, m.Id, default)));
        }
    }
}

public sealed class SqliteInboundCrashTests() : InboundCrashTests(LabBackend.Sqlite);

public sealed class PostgresInboundCrashTests() : InboundCrashTests(LabBackend.Postgres);
