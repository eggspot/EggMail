using System.Text;
using Mta.Core;

namespace Mta.Storage.Portability.Tests;

/// <summary>
/// Security regression tests for the switch bundle (docs/security-test-map.md, PATH-2): a bundle is a directory somebody may have tampered with, so a
/// path inside it can never lead out of it, for reading or for writing, and a file that is not in the manifest is noticed.
/// The in-house review, not an independent audit.
/// </summary>
public class BundleSecurityTests : IDisposable
{
    private readonly string _parent = Path.Combine(Path.GetTempPath(), "eggmail-bundle-sec-" + Guid.NewGuid().ToString("N"));
    private string Dir => Path.Combine(_parent, "bundle");

    public BundleSecurityTests() => Directory.CreateDirectory(Dir);

    public void Dispose()
    {
        if (Directory.Exists(_parent)) { Directory.Delete(_parent, true); }   // created by this test
    }

    private static BundleManifest NewManifest() => new()
    {
        SwitchId = Ids.New(), CreatedAt = DateTimeOffset.UtcNow, CreatedBy = "test",
        Source = new BundleSource { Backend = "sqlite", HistoryMode = "full", SchemaVersion = "1", AppVersion = "0.1.0" },
        EffectiveSettings = new Dictionary<string, string>(),
    };

    [Theory]
    [InlineData("../evil")]
    [InlineData("a/../../evil")]
    [InlineData("config/../../../evil")]
    [InlineData("/etc/passwd")]
    [InlineData("//etc/passwd")]
    [InlineData("..")]
    [InlineData("../bundle-sibling/x")]
    [InlineData("a/./../../x")]
    public async Task A_manifest_that_lists_a_path_outside_the_bundle_is_refused_when_the_bundle_is_opened(string path)
    {
        string json = "{\"formatVersion\":\"1.0.0\",\"files\":[{\"path\":" + System.Text.Json.JsonSerializer.Serialize(path) + ",\"sha256\":\"\",\"bytes\":0}]}";
        await File.WriteAllTextAsync(Path.Combine(Dir, "manifest.json"), json);

        var ex = await Assert.ThrowsAsync<BundleException>(() => BundleReader.OpenAsync(Dir, default));

        Assert.Contains("escapes", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("../outside.ndjson")]
    [InlineData("/etc/passwd")]
    [InlineData("config/../../outside.ndjson")]
    public async Task No_caller_can_read_a_file_outside_the_bundle_through_the_reader(string path)
    {
        await File.WriteAllTextAsync(Path.Combine(_parent, "outside.ndjson"), "{\"secret\":true}\n");
        await File.WriteAllTextAsync(Path.Combine(Dir, "manifest.json"), "{\"formatVersion\":\"1.0.0\",\"files\":[]}");
        BundleReader reader = await BundleReader.OpenAsync(Dir, default);

        Assert.Throws<BundleException>(() => reader.PathOf(path));
        await Assert.ThrowsAsync<BundleException>(async () =>
        {
            await foreach (var _ in reader.ReadNdjsonAsync<System.Text.Json.JsonElement>(path, default)) { }
        });
    }

    [Theory]
    [InlineData("../evil.ndjson")]
    [InlineData("/tmp/evil.ndjson")]
    [InlineData("a/../../evil.ndjson")]
    public async Task No_caller_can_write_a_file_outside_the_bundle_through_the_writer(string path)
    {
        string writeTo = Path.Combine(_parent, "w");
        using var writer = new BundleWriter(writeTo, NewManifest());

        Assert.Throws<ArgumentException>(() => writer.ResolvePath(path));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => writer.WriteBinaryAsync(path, new byte[] { 1 }, default));
        Assert.Throws<ArgumentException>(() => writer.OpenNdjson<int>(path));
        Assert.False(File.Exists(Path.Combine(_parent, "evil.ndjson")));
    }

    [Fact]
    public async Task A_bundle_directory_given_with_a_trailing_separator_is_the_same_bundle_and_still_confines_paths()
    {
        string root = Path.Combine(_parent, "slash");
        using (var w = new BundleWriter(root + Path.DirectorySeparatorChar, NewManifest()))
        {
            await w.WriteBinaryAsync("queue/a.eml", Encoding.ASCII.GetBytes("Subject: x\r\n\r\nbody\r\n"), default);
            await w.CompleteAsync(default);
        }

        BundleReader reader = await BundleReader.OpenAsync(root + Path.DirectorySeparatorChar, default);
        Assert.True((await reader.VerifyAsync(default)).Ok);
        Assert.Throws<BundleException>(() => reader.PathOf("../outside"));
        Assert.EndsWith(Path.Combine("slash", "queue", "a.eml"), reader.PathOf("queue/a.eml"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_file_that_is_in_the_bundle_directory_but_not_in_the_manifest_is_reported_and_a_changed_file_is_too()
    {
        string root = Path.Combine(_parent, "ok");
        using (var w = new BundleWriter(root, NewManifest()))
        {
            await w.WriteBinaryAsync("queue/a.eml", Encoding.ASCII.GetBytes("Subject: x\r\n\r\nbody\r\n"), default);
            await w.CompleteAsync(default);
        }

        await File.WriteAllTextAsync(Path.Combine(root, "queue", "planted.eml"), "planted");
        var planted = await (await BundleReader.OpenAsync(root, default)).VerifyAsync(default);
        Assert.False(planted.Ok);
        Assert.Contains(planted.Problems, p => p.Contains("planted.eml", StringComparison.Ordinal) && p.Contains("not listed", StringComparison.Ordinal));

        File.Delete(Path.Combine(root, "queue", "planted.eml"));
        await File.WriteAllTextAsync(Path.Combine(root, "queue", "a.eml"), "Subject: tampered\r\n\r\nbody\r\n");
        var tampered = await (await BundleReader.OpenAsync(root, default)).VerifyAsync(default);
        Assert.False(tampered.Ok);
        Assert.Contains(tampered.Problems, p => p.Contains("a.eml", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_bundle_is_written_only_into_an_empty_directory_so_it_never_overwrites_something_that_was_there()
    {
        string occupied = Path.Combine(_parent, "occupied");
        Directory.CreateDirectory(occupied);
        await File.WriteAllTextAsync(Path.Combine(occupied, "precious.txt"), "keep");

        Assert.ThrowsAny<Exception>(() => new BundleWriter(occupied, NewManifest()));

        Assert.Equal("keep", await File.ReadAllTextAsync(Path.Combine(occupied, "precious.txt")));
    }
}
