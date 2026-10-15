namespace Mta.Host.Tests;

public class DockerfileTests
{
    private static string RepoFile(string name)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "EggMail.slnx")))
        {
            dir = dir.Parent;
        }

        return Path.Combine(dir?.FullName ?? throw new InvalidOperationException("EggMail.slnx not found above " + AppContext.BaseDirectory), name);
    }

    /// <summary>
    /// An environment variable is a deployment-supplied value, and the backend switch never rewrites those: it prints a cutover patch instead of
    /// writing <c>bootstrap.json</c>. If the image itself set the storage pointer (<c>Storage__Backend</c>, <c>Sqlite__DataDirectory</c>), the
    /// one-container quick start could never switch automatically. The defaults already are SQLite and <c>/data</c>.
    /// </summary>
    [Fact]
    public void The_image_does_not_set_the_storage_pointer_through_the_environment()
    {
        string text = string.Join('\n', File.ReadAllLines(RepoFile("Dockerfile")).Where(l => !l.TrimStart().StartsWith('#')));

        Assert.DoesNotContain("Storage__Backend", text);
        Assert.DoesNotContain("Sqlite__DataDirectory", text);
        Assert.Equal(Mta.Storage.StorageBackend.Sqlite, new Mta.Storage.StorageOptions().Backend);
        Assert.Equal("/data", new Mta.Storage.StorageOptions().Sqlite.DataDirectory);
    }
}
