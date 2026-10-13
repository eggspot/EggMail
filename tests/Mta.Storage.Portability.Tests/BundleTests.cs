using System.Text;
using Mta.Core;
using Mta.Storage.Portability;

namespace Mta.Storage.Portability.Tests;

/// <summary>Runs alone: the memory-bounds test measures the whole process's heap, which other test classes running in parallel would inflate.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ExclusiveHeapCollection
{
    public const string Name = "exclusive-heap";
}

[Collection(ExclusiveHeapCollection.Name)]
public class BundleTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "eggmail-bundle-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) { Directory.Delete(_dir, true); }
    }

    private sealed record Row(Guid Id, string Name, int Count, DateTimeOffset At, string? Optional, BundleColor Color);

    private enum BundleColor { Red, Blue }

    private static BundleManifest NewManifest() => new()
    {
        SwitchId = Ids.New(), CreatedAt = DateTimeOffset.UtcNow, CreatedBy = "test",
        Source = new BundleSource { Backend = "sqlite", HistoryMode = "full", SchemaVersion = "1", AppVersion = "0.1.0" },
        EffectiveSettings = new Dictionary<string, string> { ["History:Mode"] = "Full" },
    };

    [Fact]
    public async Task Write_verify_and_read_back_ndjson_and_binary_files()
    {
        var rows = Enumerable.Range(0, 500).Select(i => new Row(Ids.New(), $"name ü {i}", i, DateTimeOffset.UnixEpoch.AddSeconds(i), i % 2 == 0 ? null : "x", i % 3 == 0 ? BundleColor.Blue : BundleColor.Red)).ToList();
        using (var w = new BundleWriter(_dir, NewManifest()))
        {
            await using (var f = w.OpenNdjson<Row>("config/things.ndjson"))
            {
                foreach (var r in rows) { await f.WriteAsync(r, default); }
            }

            await w.WriteBinaryAsync("queue/bodies/a.eml", Encoding.ASCII.GetBytes("Subject: x\r\n\r\nbody\r\n"), default);
            await w.CompleteAsync(default);
        }

        var reader = await BundleReader.OpenAsync(_dir, default);
        var report = await reader.VerifyAsync(default);
        Assert.True(report.Ok, string.Join("; ", report.Problems));
        Assert.Equal(2, report.FilesChecked);
        var file = reader.Manifest.Files.Single(f => f.Path == "config/things.ndjson");
        Assert.Equal(500, file.Rows);
        var back = new List<Row>();
        await foreach (var r in reader.ReadNdjsonAsync<Row>("config/things.ndjson", default)) { back.Add(r); }
        Assert.Equal(rows, back);
        Assert.Equal("Full", reader.Manifest.EffectiveSettings["History:Mode"]);
    }

    [Fact]
    public async Task Verification_detects_modified_missing_and_extra_files()
    {
        using (var w = new BundleWriter(_dir, NewManifest()))
        {
            await using (var f = w.OpenNdjson<Row>("config/a.ndjson")) { await f.WriteAsync(new Row(Ids.New(), "a", 1, DateTimeOffset.UtcNow, null, BundleColor.Red), default); }
            await w.WriteBinaryAsync("queue/bodies/b.eml", "hello"u8.ToArray(), default);
            await w.CompleteAsync(default);
        }

        var reader = await BundleReader.OpenAsync(_dir, default);
        Assert.True((await reader.VerifyAsync(default)).Ok);

        File.AppendAllText(Path.Combine(_dir, "config/a.ndjson"), " ");
        var r1 = await reader.VerifyAsync(default);
        Assert.False(r1.Ok);
        Assert.Contains(r1.Problems, p => p.StartsWith("config/a.ndjson") && p.Contains("SHA-256"));

        File.Delete(Path.Combine(_dir, "queue/bodies/b.eml"));
        Assert.Contains((await reader.VerifyAsync(default)).Problems, p => p.Contains("missing"));

        File.WriteAllText(Path.Combine(_dir, "extra.txt"), "x");
        Assert.Contains((await reader.VerifyAsync(default)).Problems, p => p.Contains("not listed"));
    }

    [Theory]
    [InlineData("1.0.0", true)]
    [InlineData("1.7.3", true)]
    [InlineData("2.0.0", false)]
    [InlineData("0.9.0", false)]
    [InlineData("nonsense", false)]
    public void Format_compatibility(string version, bool ok) => Assert.Equal(ok, BundleManifest.IsCompatible(version, out _));

    [Fact]
    public async Task Newer_major_is_refused_and_unknown_members_are_ignored()
    {
        Directory.CreateDirectory(_dir);
        await File.WriteAllTextAsync(Path.Combine(_dir, "manifest.json"), "{\"formatVersion\":\"2.0.0\"}");
        var ex = await Assert.ThrowsAsync<BundleException>(() => BundleReader.OpenAsync(_dir, default));
        Assert.Contains("newer", ex.Message);

        await File.WriteAllTextAsync(Path.Combine(_dir, "manifest.json"), "{\"formatVersion\":\"1.9.0\",\"futureField\":{\"a\":1},\"files\":[]}");
        var reader = await BundleReader.OpenAsync(_dir, default);
        Assert.Equal("1.9.0", reader.Manifest.FormatVersion);

        await File.WriteAllTextAsync(Path.Combine(_dir, "rows.ndjson"), "{\"id\":\"00000000-0000-0000-0000-000000000001\",\"name\":\"n\",\"count\":1,\"at\":\"2026-01-01T00:00:00+00:00\",\"color\":\"red\",\"newColumn\":42}\n");
        var rows = new List<Row>();
        await foreach (var r in reader.ReadNdjsonAsync<Row>("rows.ndjson", default)) { rows.Add(r); }
        Assert.Single(rows);
    }

    [Fact]
    public async Task Bad_manifests_and_paths_are_rejected()
    {
        Directory.CreateDirectory(_dir);
        await Assert.ThrowsAsync<BundleException>(() => BundleReader.OpenAsync(_dir, default));                                     // no manifest
        await File.WriteAllTextAsync(Path.Combine(_dir, "manifest.json"), "{ not json");
        await Assert.ThrowsAsync<BundleException>(() => BundleReader.OpenAsync(_dir, default));
        await File.WriteAllTextAsync(Path.Combine(_dir, "manifest.json"), "{\"formatVersion\":\"1.0.0\",\"files\":[{\"path\":\"../evil\",\"sha256\":\"\",\"bytes\":0}]}");
        var ex = await Assert.ThrowsAsync<BundleException>(() => BundleReader.OpenAsync(_dir, default));
        Assert.Contains("escapes", ex.Message);

        using var w = new BundleWriter(Path.Combine(_dir, "sub"), NewManifest());
        Assert.Throws<ArgumentException>(() => w.OpenNdjson<Row>("../outside.ndjson"));
    }

    [Fact]
    public void Writer_refuses_a_non_empty_directory()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "x"), "x");
        Assert.Throws<IOException>(() => new BundleWriter(_dir, NewManifest()));
    }

    [Fact]
    public async Task Large_ndjson_streams_with_bounded_memory()
    {
        using (var w = new BundleWriter(_dir, NewManifest()))
        {
            await using (var f = w.OpenNdjson<Row>("history/events.ndjson"))
            {
                for (int i = 0; i < 100_000; i++) { await f.WriteAsync(new Row(Ids.New(), "event " + i, i, DateTimeOffset.UnixEpoch, null, BundleColor.Red), default); }
            }

            await w.CompleteAsync(default);
        }

        long before = GC.GetTotalMemory(true);
        var reader = await BundleReader.OpenAsync(_dir, default);
        long n = 0;
        await foreach (var _ in reader.ReadNdjsonAsync<Row>("history/events.ndjson", default)) { n++; }
        Assert.Equal(100_000, n);
        Assert.True(GC.GetTotalMemory(true) - before < 50_000_000);
        Assert.True((await reader.VerifyAsync(default)).Ok);
    }

    [Fact]
    public async Task Secrets_roundtrip_with_passphrase_and_never_appear_in_clear()
    {
        const string pass = "correct horse battery staple";
        byte[] secret = Encoding.UTF8.GetBytes("-----BEGIN PRIVATE KEY----- super secret dkim key material");
        byte[] protectedKey;
        var manifest = NewManifest();
        using (var w = new BundleWriter(_dir, manifest))
        {
            var protector = BundleSecretProtector.CreateForExport(w, manifest.Secrets, pass);
            protectedKey = protector.Protect(secret, SecretPurposes.DkimKey);
            await using (var f = w.OpenNdjson<SecretRow>("config/dkim.ndjson")) { await f.WriteAsync(new SecretRow("d1", Convert.ToBase64String(protectedKey)), default); }
            await w.AddExistingFileAsync(manifest.Secrets.CertificateFile, default);
            foreach (string file in Directory.EnumerateFiles(w.ResolvePath(manifest.Secrets.KeyRingDirectory))) { await w.AddExistingFileAsync(Path.GetRelativePath(w.Root, file), default); }
            await w.CompleteAsync(default);
        }

        // Nothing on disk contains the plaintext.
        foreach (string file in Directory.EnumerateFiles(_dir, "*", SearchOption.AllDirectories))
        {
            Assert.DoesNotContain("super secret", File.ReadAllText(file, Encoding.Latin1));
        }

        var reader = await BundleReader.OpenAsync(_dir, default);
        Assert.True((await reader.VerifyAsync(default)).Ok);
        var importer = BundleSecretProtector.OpenForImport(reader, pass);
        Assert.Equal(secret, importer.Unprotect(protectedKey, SecretPurposes.DkimKey));
        // Purpose separation inside the bundle.
        Assert.Throws<BundleException>(() => importer.Unprotect(protectedKey, SecretPurposes.WebhookSecret));
        // A wrong passphrase fails cleanly.
        Assert.Throws<BundleException>(() => BundleSecretProtector.OpenForImport(reader, "wrong passphrase 123"));
        // Short passphrases are refused at export.
        Assert.Throws<ArgumentException>(() => BundleSecretProtector.OpenForImport(reader, "short"));
    }

    private sealed record SecretRow(string Id, string Protected);
}
