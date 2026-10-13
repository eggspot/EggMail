using System.Text.RegularExpressions;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers.Clr;

// usage: allocstacks <file.nettrace> [frames=4] [top=40] [filter-substring] [mode=stack|owner|method]
//   stack:  leaf type <- N leaf frames
//   method: the first Mta.* (or EntityFrameworkCore / Microsoft.Data.Sqlite) frame from the leaf, with the leaf type
//   owner:  the first Mta.* frame's type only
string path = args[0];
int frames = args.Length > 1 ? int.Parse(args[1]) : 4;
int top = args.Length > 2 ? int.Parse(args[2]) : 40;
string? filter = args.Length > 3 && args[3] != "-" ? args[3] : null;
string mode = args.Length > 4 ? args[4] : "stack";

string etlx = TraceLog.CreateFromEventPipeDataFile(path, null, new TraceLogOptions { ContinueOnError = true });
using var log = new TraceLog(etlx);
var byKey = new Dictionary<string, long>();
long total = 0;
var interesting = new Regex(@"^(Mta\.|Microsoft\.EntityFrameworkCore|Microsoft\.Data\.Sqlite|SQLitePCL|System\.Net\.Security|System\.Net\.Sockets|System\.Threading\.Channels|System\.IO\.Pipelines|System\.Text\.Json)");
foreach (var e in log.Events)
{
    if (e is not GCAllocationTickTraceData t)
    {
        continue;
    }

    long amount = t.AllocationAmount64;
    total += amount;
    var names = new List<string>();
    for (var s = e.CallStack(); s != null; s = s.Caller)
    {
        string name = s.CodeAddress.FullMethodName;
        if (!string.IsNullOrEmpty(name))
        {
            names.Add(name);
        }
    }

    string key;
    if (mode == "stack")
    {
        key = t.TypeName + "  <-  " + string.Join(" <- ", names.Take(frames).Select(n => n.Length > 110 ? n[..110] : n));
    }
    else
    {
        string? first = names.FirstOrDefault(n => n.StartsWith("Mta.", StringComparison.Ordinal))
            ?? names.FirstOrDefault(n => interesting.IsMatch(n));
        if (first is null)
        {
            key = t.TypeName + "  <-  (no known frame)";
        }
        else
        {
            // Mta.Delivery.DeliveryProcessor+<AttemptAsync>d__10.MoveNext(...) -> type + method
            string method = first.Length > 130 ? first[..130] : first;
            if (mode == "owner")
            {
                int paren = method.IndexOf('(');
                method = paren > 0 ? method[..paren] : method;
                int plus = method.IndexOf('+');
                method = plus > 0 ? method[..plus] : method;
                int lastDot = method.LastIndexOf('.');
                method = lastDot > 0 && !method.Contains('+') ? method[..lastDot] : method;
                key = method;
            }
            else
            {
                key = method + "  [" + t.TypeName + "]";
            }
        }
    }

    if (filter is null || key.Contains(filter, StringComparison.OrdinalIgnoreCase))
    {
        byKey[key] = byKey.GetValueOrDefault(key) + amount;
    }
}

Console.WriteLine($"total sampled: {total / 1e6:F1} MB");
foreach (var kv in byKey.OrderByDescending(k => k.Value).Take(top))
{
    Console.WriteLine($"{kv.Value * 100.0 / total,5:F1}%  {kv.Key}");
}
