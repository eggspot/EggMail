namespace Mta.Tools;

internal static class ToolsMain
{
    private const string Usage = """
        mta-tools: EggMail load generator and test sink (not for use against the public internet)

          mta-tools sink  [--port 2525] [--bind 127.0.0.1] [--tls] [--delay-ms 0] [--max-size-mb 25]
              SMTP sink that accepts and discards mail, with optional per-message delay (a sink that creates
              back-pressure, as the benchmark rules require) and optional STARTTLS with a self-signed certificate.

          mta-tools load  --port 2525 [--host 127.0.0.1] [--connections 16] [--messages 100000] [--size 2048]
                          [--rcpt 1] [--pipelining] [--starttls] [--implicit-tls] [--duration-s 0]
                          [--auth user:pass] [--label text] [--json out.json]
              Closed-loop SMTP ingest benchmark: N connections send messages as fast as the server accepts them.
              Reports accepted msgs/s, MB/s and p50/p95/p99 transaction latency (MAIL FROM to the final reply).
              Always publish durable and non-durable server configurations as a pair (docs/benchmarks.md).

              Options for soak runs (docs/soak.md):
                --persist --duration-s N   keep reconnecting through server outages (crash drills) instead of giving up
                --rate R                   pace the load to R messages per second in total (default: as fast as the server accepts)
                --size-mix 1024:55,8192:30 message sizes in bytes with weights (default: the single --size)
                --from addr                envelope and header sender (default load@bench.test)
                --rcpt-domain a.test,b.test recipient domains, used in turn (default dest.test)
                --id-prefix soak           number every message: Message-ID <soak.000000000042@sender-domain>
                --ack-log file             one line per message the server acknowledged with 250: sequence, bytes, reply text
                --stats-jsonl file         counters and interval latency percentiles every --stats-interval-s (default 10)
                --io-timeout-s N           give up on a connection that does not answer within N seconds
        """;

    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            Console.WriteLine(Usage);
            return args.Length == 0 ? 1 : 0;
        }

        var options = ArgParser.Parse(args.Skip(1));
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        try
        {
            return args[0] switch
            {
                "sink" => await SinkCommand.RunAsync(options, cts.Token),
                "load" => await LoadCommand.RunAsync(options, cts.Token),
                _ => Fail($"Unknown command '{args[0]}'.\n\n{Usage}"),
            };
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (ArgumentException ex)
        {
            return Fail(ex.Message);
        }
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 2;
    }
}

internal sealed class ArgParser
{
    private readonly Dictionary<string, string?> _values = new(StringComparer.OrdinalIgnoreCase);

    public static ArgParser Parse(IEnumerable<string> args)
    {
        var p = new ArgParser();
        string? pending = null;
        foreach (string a in args)
        {
            if (a.StartsWith("--", StringComparison.Ordinal))
            {
                if (pending is not null) { p._values[pending] = null; }
                pending = a[2..];
            }
            else if (pending is not null)
            {
                p._values[pending] = a;
                pending = null;
            }
            else
            {
                throw new ArgumentException($"Unexpected argument '{a}'.");
            }
        }

        if (pending is not null) { p._values[pending] = null; }
        return p;
    }

    public bool Flag(string name) => _values.ContainsKey(name);

    public string? Get(string name) => _values.TryGetValue(name, out var v) ? v : null;

    public int GetInt(string name, int fallback) => Get(name) is { } v ? int.Parse(v, System.Globalization.CultureInfo.InvariantCulture) : fallback;

    public double GetDouble(string name, double fallback) => Get(name) is { } v ? double.Parse(v, System.Globalization.CultureInfo.InvariantCulture) : fallback;
}
