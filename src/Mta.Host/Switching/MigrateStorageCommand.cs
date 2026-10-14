using System.Text;
using Microsoft.Extensions.Configuration;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Host.Secrets;
using Mta.Storage;
using Mta.Storage.Portability;
using Mta.Storage.Transfer;

namespace Mta.Host.Switching;

/// <summary>
/// <c>mta migrate-storage &lt;subcommand&gt;</c> (design §4.6): the command line entry point of the switch engine. It runs offline,
/// against the stores named by the configuration (the source is the storage the configuration points at; the target is described
/// by <c>--to</c> plus the <c>SwitchTarget:*</c> settings). A SQLite data directory is locked while the command works, which
/// proves that the server that owns it is stopped.
/// </summary>
public static class MigrateStorageCommand
{
    public const int Ok = 0;
    public const int ConfigError = 2;
    public const int NotReady = 3;
    public const int Refused = 4;
    public const int IntegrityFailure = 5;
    public const int UsageError = 64;

    public const string DefaultPassphraseVariable = "EGGMAIL_BUNDLE_PASSPHRASE";

    private static readonly string[] Subcommands = ["preflight", "export", "import", "verify", "confirm", "activate", "rollback", "finalize", "status"];
    private static readonly HashSet<string> ValueOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "to", "bundle", "quiesce-timeout", "passphrase-file", "passphrase-env", "bootstrap-file", "target-dir", "wait",
    };

    private static readonly HashSet<string> Flags = new(StringComparer.OrdinalIgnoreCase)
    {
        "drain", "quiesce", "skip-history", "history-only", "history-after-activation", "dry-run", "accept-unprotected-keys", "source-only", "delete-bundle", "help",
    };

    public static string Usage => """
        Usage: mta migrate-storage <subcommand> [options]

        Subcommands (in the order of a switch):
          preflight   check the source and the target; nothing is changed
          export      stop accepting (--drain, the default, or --quiesce), fence the source and write the bundle
          import      import the bundle into the empty target
          verify      re-check the bundle and the target against the manifest
          confirm     confirm the verified target
          activate    write the new storage pointer to the bootstrap file, or print the cutover patch
          rollback    before activation: discard the target, clear the fence and marks, resume the source
          finalize    after the target is active: mark the source finalized (the old data is never deleted)
          status      where the switch stands

        Options:
          --to postgres|sqlite          the target backend (the target settings go under SwitchTarget:, for example
                                        --SwitchTarget:Sqlite:DataDirectory=/data2 or --target-dir /data2)
          --bundle <dir>                the bundle directory
          --drain | --quiesce           how to hand over queued mail (default --drain)
          --quiesce-timeout <seconds>   how long in-flight deliveries may finish (default Switch:QuiesceTimeoutSeconds, 30)
          --wait <seconds>              with --drain: wait this long for the queue to empty
          --skip-history                leave per-message history out (export) or do not import it (import)
          --history-only                import only history (the backfill after activation)
          --history-after-activation    record that history is copied after activation
          --dry-run                     run the checks and stop
          --passphrase-file <file>      the export passphrase, from a file
          --passphrase-env <NAME>       ... or from this environment variable (default EGGMAIL_BUNDLE_PASSPHRASE)
          --accept-unprotected-keys     acknowledge a target with Secrets:KeyProtection=None
          --source-only                 rollback: clear only the source
          --delete-bundle               finalize: delete the bundle directory
          --bootstrap-file <file>       the bootstrap file to write (default: <data directory>/bootstrap.json)
          --Key=value                   any configuration key

        The passphrase is never accepted on the command line. SQLite data directories must not be in use: stop the server first.
        """;

    private sealed class Parsed
    {
        public string? Subcommand;
        public readonly Dictionary<string, string> Values = new(StringComparer.OrdinalIgnoreCase);
        public readonly HashSet<string> Set = new(StringComparer.OrdinalIgnoreCase);
        public readonly List<string> ConfigArgs = [];
        public string? Error;

        public bool Has(string flag) => Set.Contains(flag);

        public string? Get(string name) => Values.TryGetValue(name, out string? v) ? v : null;
    }

    private static Parsed Parse(string[] args)
    {
        var p = new Parsed();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            if (!a.StartsWith("--", StringComparison.Ordinal))
            {
                if (p.Subcommand is null)
                {
                    p.Subcommand = a;
                }
                else
                {
                    p.Error ??= $"Unexpected argument '{a}'.";
                }

                continue;
            }

            string body = a[2..];
            string name = body;
            string? inline = null;
            int eq = body.IndexOf('=');
            if (eq >= 0)
            {
                name = body[..eq];
                inline = body[(eq + 1)..];
            }

            if (name.Equals("passphrase", StringComparison.OrdinalIgnoreCase))
            {
                p.Error ??= "The passphrase is never accepted on the command line (it would end up in the process list and shell history). Use --passphrase-file or --passphrase-env.";
                if (inline is null && i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                {
                    i++; // its value is not a subcommand either
                }
            }
            else if (ValueOptions.Contains(name))
            {
                if (inline is null)
                {
                    if (i + 1 >= args.Length)
                    {
                        p.Error ??= $"--{name} needs a value.";
                        continue;
                    }

                    inline = args[++i];
                }

                p.Values[name] = inline;
            }
            else if (Flags.Contains(name) && inline is null)
            {
                p.Set.Add(name);
            }
            else if (eq >= 0)
            {
                p.ConfigArgs.Add(a); // a configuration override
            }
            else
            {
                p.Error ??= $"Unknown option '{a}'.";
            }
        }

        return p;
    }

    private sealed class Opened(IStorage storage, SwitchEndpoint endpoint, DataDirectoryLock? directoryLock) : IAsyncDisposable
    {
        public IStorage Storage { get; } = storage;

        public SwitchEndpoint Endpoint { get; } = endpoint;

        public async ValueTask DisposeAsync()
        {
            await Storage.DisposeAsync().ConfigureAwait(false);
            directoryLock?.Dispose();
        }
    }

    private static async Task<Opened> OpenAsync(MtaConfig config, CancellationToken ct)
    {
        DataDirectoryLock? directoryLock = config.Storage.Backend == StorageBackend.Sqlite ? DataDirectoryLock.Acquire(config.Storage.Sqlite.DataDirectory) : null;
        try
        {
            IStorage storage = StorageFactory.Create(config.Storage, SystemClock.Instance, NullMtaLog.Instance);
            await storage.InitializeAsync(ct).ConfigureAwait(false);
            ISecretProtector secrets = SecretsFactory.Create(config.Secrets, storage.Config);
            var endpoint = new SwitchEndpoint
            {
                Storage = storage,
                Secrets = secrets,
                Options = config.Storage,
                KeysProtectedAtRest = config.Secrets.KeyProtection != KeyProtectionMode.None,
            };
            return new Opened(storage, endpoint, directoryLock);
        }
        catch
        {
            directoryLock?.Dispose();
            throw;
        }
    }

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error, Func<string, string?>? getEnvironment = null, CancellationToken cancellationToken = default)
    {
        getEnvironment ??= Environment.GetEnvironmentVariable;
        Parsed p = Parse(args);
        if (p.Has("help") || (p.Subcommand is null && p.Error is null))
        {
            await output.WriteLineAsync(Usage).ConfigureAwait(false);
            return p.Has("help") ? Ok : UsageError;
        }

        if (p.Error is not null || p.Subcommand is null || !Subcommands.Contains(p.Subcommand, StringComparer.OrdinalIgnoreCase))
        {
            await error.WriteLineAsync(p.Error ?? $"Unknown subcommand '{p.Subcommand}'.").ConfigureAwait(false);
            await error.WriteLineAsync("Run 'mta migrate-storage --help' for usage.").ConfigureAwait(false);
            return UsageError;
        }

        string command = p.Subcommand.ToLowerInvariant();
        string? bootstrapFile = p.Get("bootstrap-file");
        string bootstrapPath = bootstrapFile ?? ConfigLoader.ResolveBootstrapPath(args: p.ConfigArgs);

        // Once the pointer was rewritten by 'activate', the configuration on disk describes the target; the commands that still
        // concern the source (rollback, finalize, status) read the pointer as it was before.
        string? original = command is "activate" or "rollback" or "finalize" or "status" ? SwitchActivator.PendingOriginalBootstrap(bootstrapPath) : null;
        IConfigurationRoot root = ConfigLoader.Build(p.ConfigArgs.ToArray(), Path.GetDirectoryName(Path.GetFullPath(bootstrapPath)), bootstrapFileOverride: original);
        LoadedConfig loaded = ConfigLoader.Load(root);
        if (!loaded.IsValid)
        {
            foreach (string e in loaded.Errors)
            {
                await error.WriteLineAsync("configuration error: " + e).ConfigureAwait(false);
            }

            return ConfigError;
        }

        StorageBackend? to = null;
        if (p.Get("to") is { } toText)
        {
            if (!SwitchTargetConfiguration.TryParseBackend(toText, out StorageBackend backend))
            {
                await error.WriteLineAsync($"--to must be 'postgres' or 'sqlite', not '{toText}'.").ConfigureAwait(false);
                return UsageError;
            }

            to = backend;
        }

        bool needsTargetFlag = command is "activate" or "rollback" or "finalize";
        if (needsTargetFlag && to is null && !(command == "rollback" && p.Has("source-only")))
        {
            await error.WriteLineAsync($"'{command}' needs --to (the target backend and its SwitchTarget:* settings).").ConfigureAwait(false);
            return UsageError;
        }

        MtaConfig sourceConfig = loaded.Config;
        MtaConfig? targetConfig = null;
        if (to is { } targetBackend)
        {
            var targetLoaded = ConfigLoader.Load(SwitchTargetConfiguration.Build(root, targetBackend, p.Get("target-dir")));
            if (!targetLoaded.IsValid)
            {
                foreach (string e in targetLoaded.Errors)
                {
                    await error.WriteLineAsync("target configuration error: " + e).ConfigureAwait(false);
                }

                return ConfigError;
            }

            targetConfig = targetLoaded.Config;
        }

        // Import, verify and confirm act on the target alone: with --to it is the described target, without it the configured storage.
        bool targetOnly = command is "import" or "verify" or "confirm";
        MtaConfig? openSource = targetOnly ? null : sourceConfig;
        MtaConfig? openTarget = targetOnly ? targetConfig ?? sourceConfig : targetConfig;
        if (command is "preflight" or "export" or "status" && to is null)
        {
            openTarget = null;
        }

        try
        {
            await using Opened? source = openSource is null ? null : await OpenAsync(openSource, cancellationToken).ConfigureAwait(false);
            await using Opened? target = openTarget is null ? null : await OpenAsync(openTarget, cancellationToken).ConfigureAwait(false);
            var activator = new SwitchActivator(root, bootstrapPath, original);
            var engine = new StorageSwitchEngine(source?.Endpoint, target?.Endpoint, OfflineHostControl.Instance, activator, SystemClock.Instance, NullMtaLog.Instance,
                new SwitchOptions { AppVersion = typeof(MigrateStorageCommand).Assembly.GetName().Version?.ToString(3) ?? "0.0.0" });
            var ctx = new CommandContext(p, output, error, getEnvironment, sourceConfig, engine, cancellationToken);
            return command switch
            {
                "preflight" => await PreflightAsync(ctx).ConfigureAwait(false),
                "export" => await ExportAsync(ctx).ConfigureAwait(false),
                "import" => await ImportAsync(ctx).ConfigureAwait(false),
                "verify" => await VerifyAsync(ctx).ConfigureAwait(false),
                "confirm" => await SimpleAsync(ctx, "Confirmed", () => engine.ConfirmAsync(cancellationToken)).ConfigureAwait(false),
                "activate" => await ActivateAsync(ctx).ConfigureAwait(false),
                "rollback" => await SimpleAsync(ctx, "Rolled back", () => engine.RollbackAsync(p.Has("source-only"), cancellationToken)).ConfigureAwait(false),
                "finalize" => await SimpleAsync(ctx, "Finalized", () => engine.FinalizeAsync(p.Has("delete-bundle"), p.Get("bundle"), cancellationToken)).ConfigureAwait(false),
                _ => await StatusAsync(ctx).ConfigureAwait(false),
            };
        }
        catch (IOException ex) when (ex.Message.Contains("data directory", StringComparison.Ordinal))
        {
            await error.WriteLineAsync(ex.Message).ConfigureAwait(false);
            return Refused;
        }
        catch (SwitchException ex)
        {
            await error.WriteLineAsync("refused: " + ex.Message).ConfigureAwait(false);
            if (ex.Report is { } report)
            {
                await PrintReportAsync(output, report).ConfigureAwait(false);
            }

            return Refused;
        }
        catch (BundleException ex)
        {
            await error.WriteLineAsync("bundle problem: " + ex.Message).ConfigureAwait(false);
            return IntegrityFailure;
        }
        catch (OperationCanceledException)
        {
            await error.WriteLineAsync("cancelled; run the command again to resume.").ConfigureAwait(false);
            return 130;
        }
    }

    private sealed record CommandContext(Parsed Options, TextWriter Out, TextWriter Err, Func<string, string?> Env, MtaConfig Config, StorageSwitchEngine Engine, CancellationToken Ct);

    private static async Task<string?> PassphraseAsync(CommandContext c)
    {
        string? file = c.Options.Get("passphrase-file");
        if (file is not null)
        {
            if (!File.Exists(file))
            {
                await c.Err.WriteLineAsync($"The passphrase file '{file}' does not exist.").ConfigureAwait(false);
                return null;
            }

            return (await File.ReadAllTextAsync(file, c.Ct).ConfigureAwait(false)).TrimEnd('\r', '\n');
        }

        string variable = c.Options.Get("passphrase-env") ?? DefaultPassphraseVariable;
        string? value = c.Env(variable);
        if (string.IsNullOrEmpty(value))
        {
            await c.Err.WriteLineAsync($"The export passphrase is missing: put it in a file (--passphrase-file) or in the environment variable {variable} (--passphrase-env). It is never read from the command line.").ConfigureAwait(false);
            return null;
        }

        return value;
    }

    private static string? BundleOf(CommandContext c)
    {
        string? bundle = c.Options.Get("bundle");
        if (bundle is null)
        {
            c.Err.WriteLine("--bundle <directory> is required.");
        }

        return bundle;
    }

    private static SwitchRequest RequestOf(CommandContext c, string? bundle, string? passphrase) => new()
    {
        Mode = c.Options.Has("quiesce") ? SwitchMode.Quiesce : SwitchMode.Drain,
        QuiesceTimeout = TimeSpan.FromSeconds(int.TryParse(c.Options.Get("quiesce-timeout"), out int s) && s > 0 ? s : Math.Max(1, c.Config.Switch.QuiesceTimeoutSeconds)),
        SkipHistory = c.Options.Has("skip-history"),
        HistoryAfterActivation = c.Options.Has("history-after-activation"),
        BundlePath = bundle,
        Passphrase = passphrase,
        AcceptUnprotectedTarget = c.Options.Has("accept-unprotected-keys"),
    };

    private static async Task PrintReportAsync(TextWriter o, PreflightReport report)
    {
        foreach (PreflightCheck check in report.Checks)
        {
            string tag = check.Status switch { CheckStatus.Ok => "ok     ", CheckStatus.Warning => "warning", _ => "ERROR  " };
            await o.WriteLineAsync($"  [{tag}] {check.Name}: {check.Message}").ConfigureAwait(false);
        }

        if (report.WillNotCarryOver.Count > 0)
        {
            await o.WriteLineAsync("  Will not carry over:").ConfigureAwait(false);
            foreach (string w in report.WillNotCarryOver)
            {
                await o.WriteLineAsync("    - " + w).ConfigureAwait(false);
            }
        }
    }

    private static async Task<int> PreflightAsync(CommandContext c)
    {
        PreflightReport report = await c.Engine.PreflightAsync(RequestOf(c, c.Options.Get("bundle"), null), c.Ct).ConfigureAwait(false);
        await c.Out.WriteLineAsync("Preflight:").ConfigureAwait(false);
        await PrintReportAsync(c.Out, report).ConfigureAwait(false);
        await c.Out.WriteLineAsync(report.CanProceed ? "Preflight passed." : "Preflight failed: fix the errors above.").ConfigureAwait(false);
        return report.CanProceed ? Ok : Refused;
    }

    private static async Task<int> ExportAsync(CommandContext c)
    {
        string? bundle = BundleOf(c);
        if (bundle is null)
        {
            return UsageError;
        }

        bool dryRun = c.Options.Has("dry-run");
        string? passphrase = dryRun ? null : await PassphraseAsync(c).ConfigureAwait(false);
        if (!dryRun && passphrase is null)
        {
            return UsageError;
        }

        SwitchRequest request = RequestOf(c, bundle, passphrase);
        SwitchStatus status = await c.Engine.GetStatusAsync(c.Ct).ConfigureAwait(false);
        bool inProgress = status.SourceState is SwitchStates.Draining or SwitchStates.Quiescing or SwitchStates.Fenced;
        if (!inProgress)
        {
            PreflightReport report = await c.Engine.PreflightAsync(request, c.Ct).ConfigureAwait(false);
            await c.Out.WriteLineAsync("Preflight:").ConfigureAwait(false);
            await PrintReportAsync(c.Out, report).ConfigureAwait(false);
            if (!report.CanProceed)
            {
                await c.Out.WriteLineAsync("Preflight failed: nothing was changed.").ConfigureAwait(false);
                return Refused;
            }

            if (dryRun)
            {
                await c.Out.WriteLineAsync($"Dry run: nothing was changed. A real run would {(request.Mode == SwitchMode.Quiesce ? "quiesce" : "drain")} the source, fence it and write the bundle to {Path.GetFullPath(bundle)}.").ConfigureAwait(false);
                return Ok;
            }

            status = await c.Engine.StartAsync(request, null, c.Ct).ConfigureAwait(false);
            await c.Out.WriteLineAsync($"Switch {status.SwitchId} started: source is {status.SourceState}.").ConfigureAwait(false);
        }
        else if (dryRun)
        {
            await c.Out.WriteLineAsync($"Dry run: a switch is already in progress (source {status.SourceState}); nothing was changed.").ConfigureAwait(false);
            return Ok;
        }

        if (status.SourceState == SwitchStates.Draining)
        {
            int wait = int.TryParse(c.Options.Get("wait"), out int w) ? Math.Max(0, w) : 0;
            DateTime deadline = DateTime.UtcNow.AddSeconds(wait);
            while (status.SourceState == SwitchStates.Draining && DateTime.UtcNow < deadline)
            {
                await Task.Delay(500, c.Ct).ConfigureAwait(false);
                status = await c.Engine.AdvanceAsync(c.Ct).ConfigureAwait(false);
            }

            if (status.SourceState == SwitchStates.Draining)
            {
                status = await c.Engine.AdvanceAsync(c.Ct).ConfigureAwait(false);
            }

            if (status.SourceState == SwitchStates.Draining)
            {
                await c.Out.WriteLineAsync("The source is draining: it no longer accepts mail, but its delivery queue is not empty. Offline nothing delivers it: start the application (it keeps delivering and fences itself when the queue is empty), then run 'export' again; or roll back and use --quiesce.").ConfigureAwait(false);
                return NotReady;
            }
        }

        var progress = new ConsoleProgress(c.Out);
        ExportResult export = await c.Engine.ExportAsync(new BundleRequest { BundlePath = bundle, Passphrase = passphrase!, SkipHistory = request.SkipHistory }, progress, c.Ct).ConfigureAwait(false);
        await c.Out.WriteLineAsync($"Exported {export.Rows} rows ({export.Bytes} bytes) to {export.BundlePath}; {export.QueueRowsMarked} queued rows are marked transferred.").ConfigureAwait(false);
        foreach (string note in export.Notes)
        {
            await c.Out.WriteLineAsync("  note: " + note).ConfigureAwait(false);
        }

        await c.Out.WriteLineAsync("The source is fenced and untouched. Treat the bundle as sensitive; delete it after finalizing. Next: 'import' into the target.").ConfigureAwait(false);
        return Ok;
    }

    private static async Task<int> ImportAsync(CommandContext c)
    {
        string? bundle = BundleOf(c);
        string? passphrase = await PassphraseAsync(c).ConfigureAwait(false);
        if (bundle is null || passphrase is null)
        {
            return UsageError;
        }

        ImportScope scope = c.Options.Has("history-only") ? ImportScope.HistoryOnly : c.Options.Has("skip-history") || c.Options.Has("history-after-activation") ? ImportScope.Core : ImportScope.All;
        ImportResult result = await c.Engine.ImportAsync(
            new ImportRequest { BundlePath = bundle, Passphrase = passphrase, Scope = scope, AcceptUnprotectedTarget = c.Options.Has("accept-unprotected-keys") },
            new ConsoleProgress(c.Out), c.Ct).ConfigureAwait(false);
        await c.Out.WriteLineAsync($"Imported {result.RowsApplied} rows in {result.ChunksApplied} chunks ({result.ChunksAlreadyApplied} chunks were already applied). History chunks: {result.HistoryChunksApplied} of {result.HistoryChunksTotal}.").ConfigureAwait(false);
        foreach (string note in result.Notes)
        {
            await c.Out.WriteLineAsync("  note: " + note).ConfigureAwait(false);
        }

        await c.Out.WriteLineAsync("Next: 'verify'.").ConfigureAwait(false);
        return Ok;
    }

    private static async Task<int> VerifyAsync(CommandContext c)
    {
        string? bundle = BundleOf(c);
        string? passphrase = await PassphraseAsync(c).ConfigureAwait(false);
        if (bundle is null || passphrase is null)
        {
            return UsageError;
        }

        VerifyReport report = await c.Engine.VerifyAsync(new BundleRequest { BundlePath = bundle, Passphrase = passphrase }, new ConsoleProgress(c.Out), c.Ct).ConfigureAwait(false);
        await c.Out.WriteLineAsync($"Checked {report.FilesChecked} bundle files ({report.BytesChecked} bytes); {report.QueueRowsHeld} queued rows are held until activation.").ConfigureAwait(false);
        foreach (TableVerification t in report.Tables)
        {
            await c.Out.WriteLineAsync($"  {t.Table,-24} {t.ActualRows,10} of {t.ExpectedRows,10} rows  checksum {(t.ChecksumMatches ? "ok" : "DIFFERS")}{(t.SecretsMatch is { } s ? $"  secrets {(s ? "ok" : "DIFFER")}" : string.Empty)}").ConfigureAwait(false);
        }

        foreach (string note in report.Notes)
        {
            await c.Out.WriteLineAsync("  note: " + note).ConfigureAwait(false);
        }

        if (!report.Ok)
        {
            foreach (string problem in report.Problems)
            {
                await c.Err.WriteLineAsync("  PROBLEM: " + problem).ConfigureAwait(false);
            }

            return IntegrityFailure;
        }

        await c.Out.WriteLineAsync("Verified. Next: 'confirm', then 'activate'.").ConfigureAwait(false);
        return Ok;
    }

    private static async Task<int> SimpleAsync(CommandContext c, string verb, Func<Task<SwitchStatus>> action)
    {
        SwitchStatus status = await action().ConfigureAwait(false);
        await c.Out.WriteLineAsync($"{verb}. {status.Summary}").ConfigureAwait(false);
        return Ok;
    }

    private static async Task<int> ActivateAsync(CommandContext c)
    {
        SwitchActivation activation = await c.Engine.ActivateAsync(c.Ct).ConfigureAwait(false);
        await c.Out.WriteLineAsync(activation.Summary).ConfigureAwait(false);
        if (activation.Patch is { } patch)
        {
            await c.Out.WriteLineAsync().ConfigureAwait(false);
            await c.Out.WriteLineAsync(patch).ConfigureAwait(false);
        }

        return Ok;
    }

    private static async Task<int> StatusAsync(CommandContext c)
    {
        SwitchStatus status = await c.Engine.GetStatusAsync(c.Ct).ConfigureAwait(false);
        var sb = new StringBuilder();
        sb.AppendLine($"Switch: {status.SwitchId?.ToString() ?? "none"}");
        sb.AppendLine($"Source: {status.SourceState ?? "no switch"}");
        sb.AppendLine($"Target: {status.TargetState ?? "no switch"}");
        sb.AppendLine(status.Summary);
        await c.Out.WriteAsync(sb.ToString()).ConfigureAwait(false);
        return Ok;
    }

    /// <summary>Writes a progress line when the phase changes and at most about once a second otherwise.</summary>
    private sealed class ConsoleProgress(TextWriter output) : IProgress<SwitchProgress>
    {
        private string? _phase;
        private long _last;

        public void Report(SwitchProgress value)
        {
            long now = Environment.TickCount64;
            if (value.Phase == _phase && now - _last < 1000 && value.Done < value.Total)
            {
                return;
            }

            _phase = value.Phase;
            _last = now;
            output.WriteLine($"  {value.Message}");
        }
    }
}
