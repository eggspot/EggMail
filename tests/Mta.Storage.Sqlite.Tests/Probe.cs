using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Mta.Storage.Model;

namespace Mta.Storage.Sqlite.Tests;

public static class CrashWriterChild
{
    public const string Argument = "--crash-writer";

    public static Task<int> RunAsync(string[] args) => Task.FromResult(0);
}

public class Probe
{
    [Fact]
    public void Print_scripts()
    {
        var hooks = SqliteModelHooks.Instance;
        string s1 = new HistoryDbContext(new DbContextOptionsBuilder<HistoryDbContext>().UseSqlite("Data Source=:memory:").Options, hooks).Database.GenerateCreateScript();
        string s2 = new QueueDbContext(new DbContextOptionsBuilder<QueueDbContext>().UseSqlite("Data Source=:memory:").Options, hooks).Database.GenerateCreateScript();
        string s3 = new ConfigDbContext(new DbContextOptionsBuilder<ConfigDbContext>().UseSqlite("Data Source=:memory:").Options, hooks).Database.GenerateCreateScript();
        File.WriteAllText("/private/tmp/claude-501/-Users-hv-work-eg-src-EggMail/969335bb-951c-4991-9c29-d0e9b0bac74f/scratchpad/probe-history.sql", s1);
        File.WriteAllText("/private/tmp/claude-501/-Users-hv-work-eg-src-EggMail/969335bb-951c-4991-9c29-d0e9b0bac74f/scratchpad/probe-queue.sql", s2);
        File.WriteAllText("/private/tmp/claude-501/-Users-hv-work-eg-src-EggMail/969335bb-951c-4991-9c29-d0e9b0bac74f/scratchpad/probe-config.sql", s3);

        using var c = new SqliteConnection("Data Source=:memory:");
        c.Open();
        var cmd = c.CreateCommand();
        cmd.CommandText = "select sqlite_version(), typeof(@g), @g, typeof(@b)";
        cmd.Parameters.AddWithValue("@g", Guid.Parse("0123abcd-0000-7000-8000-000000000001"));
        cmd.Parameters.AddWithValue("@b", true);
        using var r = cmd.ExecuteReader();
        r.Read();
        File.WriteAllText("/private/tmp/claude-501/-Users-hv-work-eg-src-EggMail/969335bb-951c-4991-9c29-d0e9b0bac74f/scratchpad/probe-misc.txt", $"{r.GetString(0)} {r.GetString(1)} {r.GetString(2)} {r.GetString(3)}");
    }
}
