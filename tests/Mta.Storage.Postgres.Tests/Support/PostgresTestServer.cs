using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Npgsql;

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// A PostgreSQL server for the tests, found in this order:
/// <list type="number">
/// <item><c>EGGMAIL_TEST_POSTGRES</c>: a connection string to an existing server (CI provides one). The role needs CREATEDB (and
/// CREATEROLE for the role-split tests). Only databases named <c>eggmail_test_*</c> are ever created or dropped.</item>
/// <item>A throwaway cluster started from locally installed binaries (<c>initdb</c> and <c>postgres</c>; directory from
/// <c>EGGMAIL_TEST_PG_BIN</c>, Homebrew, <c>/usr/lib/postgresql/*/bin</c> or <c>PATH</c>): <c>initdb</c> into a temp directory,
/// random free localhost port, trust authentication, no unix socket, fsync off (it is disposable).</item>
/// <item>Neither: <see cref="UnavailableReason"/> says so and the tests are reported as skipped, not failed.</item>
/// </list>
/// The cluster is owned by this test process: its directory holds <c>owner.pid</c>, the server is stopped by its own pid when the
/// process exits, and clusters left behind by a killed earlier run (owner process gone) are stopped and removed by pid at
/// startup. No broad process kill is ever issued, and nothing outside <c>eggmail-pgtest-*</c> temp directories is touched.
/// </summary>
internal sealed class PostgresTestServer
{
    private const string DirectoryPrefix = "eggmail-pgtest-";
    private const string TemplateDatabase = "eggmail_test_template";

    private static readonly Lazy<(PostgresTestServer? Server, string? Reason)> Shared = new(Start, LazyThreadSafetyMode.ExecutionAndPublication);

    private readonly string? _directory;
    private readonly Process? _process;
    private readonly string _adminConnectionString;
    private int _stopped;

    private PostgresTestServer(string adminConnectionString, string? directory, Process? process, string description)
    {
        _adminConnectionString = adminConnectionString;
        _directory = directory;
        _process = process;
        Description = description;
    }

    /// <summary>Why no server is available (null when one is).</summary>
    public static string? UnavailableReason => Shared.Value.Reason;

    public static PostgresTestServer Instance => Shared.Value.Server ?? throw new InvalidOperationException("No PostgreSQL available: " + Shared.Value.Reason);

    public string Description { get; }

    /// <summary>A connection string to the maintenance database as the administrator.</summary>
    public string AdminConnectionString => _adminConnectionString;

    /// <summary>Creates an empty-schema-ready database (a copy of the migrated template) and returns its connection string for the administrator role.</summary>
    public async Task<TestDatabase> CreateDatabaseAsync()
    {
        string name = "eggmail_test_" + Guid.NewGuid().ToString("N")[..16];
        await using var admin = new NpgsqlConnection(_adminConnectionString);
        await admin.OpenAsync();
        await using (var cmd = new NpgsqlCommand($"CREATE DATABASE {name} TEMPLATE {TemplateDatabase}", admin))
        {
            await cmd.ExecuteNonQueryAsync();
        }

        var builder = new NpgsqlConnectionStringBuilder(_adminConnectionString) { Database = name, Pooling = true, MaxPoolSize = 8 };
        return new TestDatabase(this, name, builder.ConnectionString);
    }

    internal async Task DropDatabaseAsync(string name)
    {
        if (!name.StartsWith("eggmail_test_", StringComparison.Ordinal) || name == TemplateDatabase)
        {
            throw new InvalidOperationException("Refusing to drop a database this fixture did not create: " + name);
        }

        try
        {
            await using var admin = new NpgsqlConnection(_adminConnectionString);
            await admin.OpenAsync();
            await using var cmd = new NpgsqlCommand($"DROP DATABASE IF EXISTS {name} WITH (FORCE)", admin);
            await cmd.ExecuteNonQueryAsync();
        }
        catch (Exception ex) when (ex is NpgsqlException or InvalidOperationException)
        {
            // A leftover test database is harmless; the whole cluster is deleted at exit.
        }
    }

    /// <summary>Creates a role (cluster-wide) for the permission tests; names are prefixed so they are recognisable.</summary>
    public async Task CreateRoleAsync(string name, bool login = true)
    {
        await using var admin = new NpgsqlConnection(_adminConnectionString);
        await admin.OpenAsync();
        await using var cmd = new NpgsqlCommand($"CREATE ROLE {name} {(login ? "LOGIN" : "NOLOGIN")}", admin);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task DropRoleAsync(string name)
    {
        try
        {
            await using var admin = new NpgsqlConnection(_adminConnectionString);
            await admin.OpenAsync();
            await using var cmd = new NpgsqlCommand($"DROP ROLE IF EXISTS {name}", admin);
            await cmd.ExecuteNonQueryAsync();
        }
        catch (NpgsqlException)
        {
        }
    }

    public string ConnectionStringFor(string database, string user)
    {
        var builder = new NpgsqlConnectionStringBuilder(_adminConnectionString) { Database = database, Username = user, Pooling = true, MaxPoolSize = 8 };
        return builder.ConnectionString;
    }

    // Startup

    private static (PostgresTestServer?, string?) Start()
    {
        try
        {
            string? external = Environment.GetEnvironmentVariable("EGGMAIL_TEST_POSTGRES");
            if (!string.IsNullOrWhiteSpace(external))
            {
                var server = new PostgresTestServer(external, null, null, "external server from EGGMAIL_TEST_POSTGRES");
                server.PrepareTemplateAsync().GetAwaiter().GetResult();
                return (server, null);
            }

            string? bin = FindBinaries();
            if (bin is null)
            {
                return (null, "No PostgreSQL available: initdb/postgres were not found (set EGGMAIL_TEST_PG_BIN to their directory) and EGGMAIL_TEST_POSTGRES is not set.");
            }

            StopStaleClusters();
            return (StartCluster(bin), null);
        }
        catch (Exception ex)
        {
            return (null, "PostgreSQL for the tests could not be started: " + ex.Message);
        }
    }

    private static string? FindBinaries()
    {
        var candidates = new List<string>();
        if (Environment.GetEnvironmentVariable("EGGMAIL_TEST_PG_BIN") is { Length: > 0 } fromEnv)
        {
            candidates.Add(fromEnv);
        }

        candidates.Add("/opt/homebrew/opt/postgresql@18/bin");
        candidates.Add("/opt/homebrew/opt/postgresql@17/bin");
        candidates.Add("/opt/homebrew/opt/postgresql@16/bin");
        candidates.Add("/usr/local/opt/postgresql@18/bin");
        candidates.Add("/usr/local/opt/postgresql@17/bin");
        candidates.Add("/usr/local/opt/postgresql@16/bin");
        if (Directory.Exists("/usr/lib/postgresql"))
        {
            candidates.AddRange(Directory.GetDirectories("/usr/lib/postgresql").OrderByDescending(d => d, StringComparer.Ordinal).Select(d => Path.Combine(d, "bin")));
        }

        candidates.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries));
        string exe = OperatingSystem.IsWindows() ? ".exe" : "";
        return candidates.FirstOrDefault(d => File.Exists(Path.Combine(d, "initdb" + exe)) && File.Exists(Path.Combine(d, "postgres" + exe)));
    }

    private static PostgresTestServer StartCluster(string bin)
    {
        string root = Path.Combine(Path.GetTempPath(), DirectoryPrefix + Guid.NewGuid().ToString("N")[..8]);
        string data = Path.Combine(root, "data");
        Directory.CreateDirectory(root);
        using (Process self = Process.GetCurrentProcess())
        {
            File.WriteAllText(Path.Combine(root, "owner.pid"), self.Id.ToString(CultureInfo.InvariantCulture) + "\n" + self.StartTime.ToUniversalTime().Ticks.ToString(CultureInfo.InvariantCulture));
        }

        string exe = OperatingSystem.IsWindows() ? ".exe" : "";
        Run(Path.Combine(bin, "initdb" + exe), ["-D", data, "-U", "postgres", "-A", "trust", "--no-sync", "-E", "UTF8", "--no-locale"], root);

        int port = FreePort();
        var psi = new ProcessStartInfo(Path.Combine(bin, "postgres" + exe))
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        foreach (string arg in new[]
        {
            "-D", data, "-p", port.ToString(CultureInfo.InvariantCulture),
            "-c", "listen_addresses=127.0.0.1", "-c", "unix_socket_directories=",
            "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off",
            "-c", "max_connections=500", "-c", "shared_buffers=128MB", "-c", "max_wal_size=2GB",
            "-c", "log_min_messages=warning", "-c", "autovacuum_naptime=5s",
        })
        {
            psi.ArgumentList.Add(arg);
        }

        Process process = Process.Start(psi) ?? throw new InvalidOperationException("postgres did not start");
        var log = new StreamWriter(Path.Combine(root, "server.log")) { AutoFlush = true };
        process.ErrorDataReceived += (_, e) => { lock (log) { log.WriteLine(e.Data); } };
        process.OutputDataReceived += (_, e) => { lock (log) { log.WriteLine(e.Data); } };
        process.BeginErrorReadLine();
        process.BeginOutputReadLine();

        string admin = new NpgsqlConnectionStringBuilder { Host = "127.0.0.1", Port = port, Username = "postgres", Database = "postgres", Pooling = false, Timeout = 5 }.ConnectionString;
        var server = new PostgresTestServer(admin, root, process, $"throwaway cluster {Path.GetFileName(root)} on 127.0.0.1:{port} ({bin})");
        AppDomain.CurrentDomain.ProcessExit += (_, _) => server.Stop();
        Console.CancelKeyPress += (_, _) => server.Stop();
        StartWatchdog(process.Id, root);

        DateTime deadline = DateTime.UtcNow.AddSeconds(60);
        while (true)
        {
            if (process.HasExited)
            {
                server.Stop();
                throw new InvalidOperationException("postgres exited during startup (exit code " + process.ExitCode.ToString(CultureInfo.InvariantCulture) + ")");
            }

            try
            {
                using var probe = new NpgsqlConnection(admin);
                probe.Open();
                break;
            }
            catch (NpgsqlException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(100);
            }
        }

        server.PrepareTemplateAsync().GetAwaiter().GetResult();
        return server;
    }

    /// <summary>
    /// The test host is often killed without running <c>ProcessExit</c> (the runner stops it hard), which would leave the
    /// cluster running. A tiny shell loop, started detached, waits for <em>this</em> process to disappear and then stops exactly
    /// the postmaster we started (by pid, fast shutdown first, kill as fallback) and removes the cluster directory. It names
    /// no process other than the two pids it is given.
    /// </summary>
    private static void StartWatchdog(int postmasterPid, string directory)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        const string Script =
            "while kill -0 \"$1\" 2>/dev/null; do sleep 1; done; " +
            "kill -INT \"$2\" 2>/dev/null; " +
            "i=0; while kill -0 \"$2\" 2>/dev/null && [ $i -lt 15 ]; do sleep 1; i=$((i+1)); done; " +
            "kill -0 \"$2\" 2>/dev/null && kill -KILL \"$2\" 2>/dev/null; " +
            "sleep 1; case \"$(basename \"$3\")\" in eggmail-pgtest-*) rm -rf \"$3\";; esac";
        var psi = new ProcessStartInfo("/bin/sh")
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add(Script);
        psi.ArgumentList.Add("watchdog");
        psi.ArgumentList.Add(Environment.ProcessId.ToString(CultureInfo.InvariantCulture));
        psi.ArgumentList.Add(postmasterPid.ToString(CultureInfo.InvariantCulture));
        psi.ArgumentList.Add(directory);
        try
        {
            Process? watchdog = Process.Start(psi);
            watchdog?.StandardInput.Close();
        }
        catch (System.ComponentModel.Win32Exception)
        {
            // no /bin/sh: the stale-cluster cleanup of the next run is the fallback
        }
    }

    /// <summary>Creates the template database and migrates it once; every test database is a cheap copy of it.</summary>
    private async Task PrepareTemplateAsync()
    {
        await using var admin = new NpgsqlConnection(_adminConnectionString);
        await admin.OpenAsync();
        await using (var drop = new NpgsqlCommand($"DROP DATABASE IF EXISTS {TemplateDatabase} WITH (FORCE)", admin))
        {
            await drop.ExecuteNonQueryAsync();
        }

        await using (var create = new NpgsqlCommand($"CREATE DATABASE {TemplateDatabase}", admin))
        {
            await create.ExecuteNonQueryAsync();
        }

        string templateConnection = new NpgsqlConnectionStringBuilder(_adminConnectionString) { Database = TemplateDatabase, Pooling = false }.ConnectionString;
        await PostgresMigrator.MigrateAsync(templateConnection, null, CancellationToken.None);
    }

    private static void StopStaleClusters()
    {
        foreach (string dir in Directory.GetDirectories(Path.GetTempPath(), DirectoryPrefix + "*"))
        {
            try
            {
                string pidFile = Path.Combine(dir, "owner.pid");
                if (File.Exists(pidFile))
                {
                    string[] lines = File.ReadAllLines(pidFile);
                    if (lines.Length >= 1 && int.TryParse(lines[0], CultureInfo.InvariantCulture, out int ownerPid) && IsAlive(ownerPid, lines.Length > 1 ? lines[1] : null))
                    {
                        continue; // another test run in progress
                    }
                }

                string postmaster = Path.Combine(dir, "data", "postmaster.pid");
                if (File.Exists(postmaster) && int.TryParse(File.ReadLines(postmaster).First(), CultureInfo.InvariantCulture, out int pgPid))
                {
                    try
                    {
                        using Process p = Process.GetProcessById(pgPid);
                        if (p.ProcessName.Contains("postgres", StringComparison.OrdinalIgnoreCase))
                        {
                            // Only the postmaster recorded in this dead run's own directory.
                            p.Kill();
                            p.WaitForExit(10_000);
                        }
                    }
                    catch (ArgumentException)
                    {
                        // already gone
                    }
                }

                Thread.Sleep(300); // let orphaned backends notice the postmaster is gone
                Directory.Delete(dir, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // best effort
            }
        }

    }

    private static bool IsAlive(int pid, string? startTicks)
    {
        try
        {
            using Process p = Process.GetProcessById(pid);
            if (p.HasExited)
            {
                return false;
            }

            // Guard against pid reuse: the recorded start time must match.
            return startTicks is null || !long.TryParse(startTicks, CultureInfo.InvariantCulture, out long ticks)
                || Math.Abs(p.StartTime.ToUniversalTime().Ticks - ticks) < TimeSpan.TicksPerSecond * 2;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static void Run(string file, string[] args, string workingDirectory)
    {
        var psi = new ProcessStartInfo(file) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false, WorkingDirectory = workingDirectory };
        foreach (string a in args)
        {
            psi.ArgumentList.Add(a);
        }

        using Process p = Process.Start(psi)!;
        string err = p.StandardError.ReadToEnd();
        p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0)
        {
            throw new InvalidOperationException($"{Path.GetFileName(file)} failed: {err}");
        }
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        try
        {
            return ((IPEndPoint)l.LocalEndpoint).Port;
        }
        finally
        {
            l.Stop();
        }
    }

    /// <summary>Stops the postmaster this fixture started (by its own pid) and deletes the cluster directory. Idempotent.</summary>
    private void Stop()
    {
        if (Interlocked.Exchange(ref _stopped, 1) != 0 || _process is null)
        {
            return;
        }

        try
        {
            NpgsqlConnection.ClearAllPools();
            if (!_process.HasExited)
            {
                // SIGINT = "fast" shutdown; the kill is only the fallback, and only for our own child.
                using Process? kill = Process.Start(new ProcessStartInfo("/bin/kill", ["-INT", _process.Id.ToString(CultureInfo.InvariantCulture)]) { UseShellExecute = false });
                kill?.WaitForExit(5000);
                if (!_process.WaitForExit(15_000))
                {
                    _process.Kill(entireProcessTree: false);
                    _process.WaitForExit(10_000);
                }
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
        }

        try
        {
            if (_directory is not null)
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>One test database; dropped on dispose.</summary>
internal sealed class TestDatabase(PostgresTestServer server, string name, string connectionString) : IAsyncDisposable
{
    public string Name { get; } = name;

    /// <summary>Connection string as the administrator (the schema owner in the default single-role setup).</summary>
    public string ConnectionString { get; } = connectionString;

    public PostgresTestServer Server { get; } = server;

    public async ValueTask DisposeAsync()
    {
        await Server.DropDatabaseAsync(Name);
    }
}
