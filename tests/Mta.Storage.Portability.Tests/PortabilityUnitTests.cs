using System.Security.Cryptography;
using System.Text;
using Mta.Core;
using Mta.Storage.Transfer;

namespace Mta.Storage.Portability.Tests;

public class PortabilityUnitTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "eggmail-unit-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, true);
        }
    }

    private static BundleManifest Manifest() => new() { SwitchId = Ids.New(), CreatedAt = DateTimeOffset.UtcNow, CreatedBy = "test" };

    [Fact]
    public void Row_checksums_do_not_depend_on_the_order_rows_arrive_in()
    {
        string[] rows = Enumerable.Range(0, 200).Select(i => $"row-{i}").ToArray();
        var a = new TableChecksum();
        foreach (string r in rows) { a.AddRow(r); }
        var b = new TableChecksum();
        foreach (string r in rows.Reverse()) { b.AddRow(r); }
        var c = new TableChecksum();
        foreach (string r in rows.Skip(1)) { c.AddRow(r); }

        Assert.Equal(a.Checksum, b.Checksum);
        Assert.Equal(200, a.Rows);
        Assert.NotEqual(a.Checksum, c.Checksum);
        Assert.Null(a.SecretDigest);
    }

    [Fact]
    public void A_checksum_resumes_from_its_manifest_form()
    {
        var a = new TableChecksum();
        a.AddRow("x");
        a.AddRow("y");
        BundleTable saved = a.ToManifest("t", "history");
        TableChecksum resumed = TableChecksum.Resume(saved.Rows, saved.Checksum, saved.SecretDigest);
        resumed.AddRow("z");
        a.AddRow("z");
        Assert.Equal(a.Checksum, resumed.Checksum);
        Assert.Equal(3, resumed.Rows);
    }

    [Fact]
    public void Secret_digests_bind_the_secret_to_its_row_and_column_and_to_the_key()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] secret = "s3cret"u8.ToArray();
        TableChecksum Make(byte[] k, string row, string column, byte[] plain)
        {
            var t = new TableChecksum();
            t.AddSecret(k, row, column, plain);
            return t;
        }

        string baseline = Make(key, "row1", "col", secret).SecretDigest!;
        Assert.Equal(baseline, Make(key, "row1", "col", secret).SecretDigest);
        Assert.NotEqual(baseline, Make(key, "row2", "col", secret).SecretDigest);
        Assert.NotEqual(baseline, Make(key, "row1", "other", secret).SecretDigest);
        Assert.NotEqual(baseline, Make(key, "row1", "col", "other"u8.ToArray()).SecretDigest);
        Assert.NotEqual(baseline, Make(RandomNumberGenerator.GetBytes(32), "row1", "col", secret).SecretDigest);
    }

    [Fact]
    public void Hash_sums_wrap_around_and_reject_bad_input()
    {
        var sum = new HashSum();
        byte[] all = Enumerable.Repeat((byte)0xFF, 32).ToArray();
        sum.Add(all);
        byte[] one = new byte[32];
        one[31] = 1;
        sum.Add(one);
        Assert.Equal(new string('0', 64), sum.Hex); // 2^256 - 1 + 1 = 0 (mod 2^256)
        Assert.Throws<FormatException>(() => HashSum.Parse("abcd"));
    }

    [Fact]
    public async Task Body_packs_round_trip_and_reject_truncation_and_foreign_files()
    {
        using var writer = new BundleWriter(_dir, Manifest());
        byte[][] bodies = [[], [1, 2, 3], new byte[100_000], Encoding.ASCII.GetBytes("Subject: x\r\n\r\nbody")];
        RandomNumberGenerator.Fill(bodies[2]);
        await using (BodyPackWriter pack = writer.OpenBodies("queue/x.00001.bodies", "message_spool"))
        {
            foreach (byte[] b in bodies) { await pack.WriteAsync(b, default); }
        }

        await writer.CompleteAsync(default);
        BundleReader reader = await BundleReader.OpenAsync(_dir, default);
        BundleFile file = Assert.Single(reader.Manifest.Files);
        Assert.Equal("bodies", file.Kind);
        Assert.Equal("message_spool", file.Table);
        Assert.Equal(4, file.Rows);
        await reader.VerifyFileAsync(file, default);

        await using (BodyPackReader read = await BodyPackReader.OpenAsync(reader.PathOf(file.Path), default))
        {
            foreach (byte[] expected in bodies) { Assert.Equal(expected, await read.ReadNextAsync(default)); }
            Assert.Null(await read.ReadNextAsync(default));
        }

        string path = reader.PathOf(file.Path);
        byte[] bytes = await File.ReadAllBytesAsync(path);
        await File.WriteAllBytesAsync(path, bytes[..^5]);
        await using (BodyPackReader read = await BodyPackReader.OpenAsync(path, default))
        {
            await read.ReadNextAsync(default);
            await read.ReadNextAsync(default);
            await read.ReadNextAsync(default);
            await Assert.ThrowsAsync<BundleException>(async () => await read.ReadNextAsync(default));
        }

        await Assert.ThrowsAsync<BundleException>(() => BodyPackReader.OpenAsync(reader.PathOf("manifest.json"), default));
        await Assert.ThrowsAsync<BundleException>(() => reader.VerifyFileAsync(file, default)); // size now differs
    }

    [Fact]
    public async Task A_bundle_can_be_reopened_to_add_files_and_the_manifest_is_replaced_atomically()
    {
        BundleManifest manifest = Manifest();
        using (var writer = new BundleWriter(_dir, manifest))
        {
            await using (LineFileWriter lines = writer.OpenLines("history/t/2026-01-01.00001.ndjson", "t", "2026-01-01", "2026-01-01"))
            {
                await lines.WriteLineAsync("{\"a\":1}", default);
            }

            await writer.CheckpointAsync(default);
        }

        using (BundleWriter again = await BundleWriter.OpenForAppendAsync(_dir, default))
        {
            Assert.Single(again.Manifest.Files);
            File.WriteAllText(Path.Combine(_dir, "history", "t", "half-written.ndjson"), "x");
            Assert.Equal(1, again.DeleteUnlistedUnder("history"));
            await using (LineFileWriter lines = again.OpenLines("history/t/2026-01-02.00001.ndjson", "t", "2026-01-02", "2026-01-02"))
            {
                await lines.WriteLineAsync("{\"a\":2}", default);
            }

            await again.CheckpointAsync(default);
        }

        Assert.False(File.Exists(Path.Combine(_dir, "manifest.json.tmp")));
        BundleReader reader = await BundleReader.OpenAsync(_dir, default);
        Assert.Equal(2, reader.Manifest.Files.Count);
        Assert.True((await reader.VerifyAsync(default)).Ok);
        Assert.Equal(["{\"a\":1}"], await reader.ReadLinesAsync("history/t/2026-01-01.00001.ndjson", default).ToListAsync());
        await Assert.ThrowsAsync<BundleException>(() => BundleWriter.OpenForAppendAsync(Path.Combine(_dir, "nothing"), default));
    }

    [Fact]
    public void Effective_settings_name_every_behavioral_default_and_show_differences()
    {
        var defaults = EffectiveSettings.Describe(new StorageOptions());
        Assert.Equal("Full", defaults["History:Mode"]);
        Assert.Equal("30", defaults["Retention:MetadataDays"]);
        Assert.Equal("7", defaults["Content:RetentionDays"]);
        Assert.Equal("5.00:00:00", defaults["Queue:MaxLifetime"]);
        var changed = new StorageOptions { Retention = new RetentionOptions { MetadataDays = 14 }, History = new HistoryOptions { Mode = HistoryMode.StatsOnly } };
        var diffs = EffectiveSettings.Differences(new StorageOptions(), changed);
        Assert.Contains(diffs, d => d.Key == "Retention:MetadataDays" && d.From == "30" && d.To == "14");
        Assert.Contains(diffs, d => d.Key == "History:Mode" && d.To == "StatsOnly");
        Assert.Empty(EffectiveSettings.Differences(new StorageOptions(), new StorageOptions()));
    }

    [Fact]
    public void The_gate_closes_exactly_for_a_fenced_source_and_an_unactivated_target()
    {
        Guid id = Guid.NewGuid();
        SwitchStateRecord S(string role, string state) => new(id, role, state, DateTimeOffset.UtcNow, null);
        Assert.Null(SwitchGate.Evaluate(null));
        foreach ((string role, string state) in new[] { (SwitchRoles.Source, SwitchStates.Active), (SwitchRoles.Source, SwitchStates.Draining), (SwitchRoles.Source, SwitchStates.Quiescing), (SwitchRoles.Target, SwitchStates.Active) })
        {
            Assert.Null(SwitchGate.Evaluate(S(role, state)));
        }

        foreach ((string role, string state) in new[] { (SwitchRoles.Source, SwitchStates.Fenced), (SwitchRoles.Source, SwitchStates.Finalized), (SwitchRoles.Target, SwitchStates.Importing), (SwitchRoles.Target, SwitchStates.Verified), (SwitchRoles.Target, SwitchStates.Confirmed) })
        {
            Assert.Contains(id.ToString(), SwitchGate.Evaluate(S(role, state)));
        }

        var gate = new SwitchGate();
        gate.Apply(S(SwitchRoles.Source, SwitchStates.Fenced));
        Assert.True(gate.IsClosed);
        Assert.Equal(id, gate.SwitchId);
        Assert.Throws<StorageFencedException>(gate.ThrowIfClosed);
        gate.Apply(null);
        Assert.False(gate.IsClosed);
        gate.ThrowIfClosed();
    }

    [Fact]
    public void Every_transferable_table_has_a_unique_name_and_a_consistent_description()
    {
        Assert.Equal(TransferTables.All.Count, TransferTables.All.Select(t => t.Name).Distinct().Count());
        Assert.All(TransferTables.All.Where(t => t.PerDay), t => Assert.Equal(TransferPart.History, t.Part));
        Assert.All(TransferTables.Of(TransferPart.History), t => Assert.True(t.PerDay));
        Assert.Equal(["delivery_queue", "webhook_outbox", "inbound_message"], TransferTables.All.Where(t => t.HasHold).Select(t => t.Name));
        Assert.Equal(["message_spool", "inbound_message_raw", "message_raw_retained"], TransferTables.All.Where(t => t.Body is not null).Select(t => t.Name));
        Assert.Equal(["dkim_key", "webhook_endpoint", "relay_route", "certificate", "acme_account"], TransferTables.All.Where(t => t.Secrets.Count > 0).Select(t => t.Name));
        Assert.Equal(TransferTables.All.OrderBy(t => (int)t.Part).Select(t => t.Name), TransferTables.All.Select(t => t.Name)); // import order: config, stats, queue, history
        Assert.Throws<KeyNotFoundException>(() => TransferTables.ByName("lease"));
    }
}
