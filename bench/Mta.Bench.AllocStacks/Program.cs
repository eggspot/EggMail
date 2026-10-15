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
var typeNames = new Dictionary<ulong, string>();
if (Environment.GetEnvironmentVariable("ALLOCSTACKS_DEBUG") == "1")
{
    foreach (var g in log.Events.GroupBy(x => x.ProviderName + "/" + x.EventName).OrderByDescending(g => g.Count()).Take(60))
    {
        Console.WriteLine($"{g.Count(),9}  {g.Key}");
    }
}

foreach (var e in log.Events)
{
    if (e is TypeLoadStopTraceData loaded)
    {
        typeNames[(ulong)loaded.TypeID] = loaded.TypeName;
    }
    else if (e is GCBulkTypeTraceData bulk)
    {
        for (int i = 0; i < bulk.Count; i++)
        {
            var v = bulk.Values(i);
            typeNames[v.TypeID] = v.TypeName;
        }
    }
}

foreach (var e in log.Events)
{
    // GCAllocationTick (about one event per 100 KB, keyword 0x1) or, when the trace was recorded with the keyword 0x200000
    // (GCSampledObjectAllocationHigh), one event per object with its size: exact per-type and per-caller bytes.
    string typeName;
    long amount;
    if (e is GCAllocationTickTraceData t)
    {
        typeName = t.TypeName;
        amount = t.AllocationAmount64;
    }
    else if (e is GCSampledObjectAllocationTraceData sampled)
    {
        typeName = typeNames.GetValueOrDefault(sampled.TypeID, "?");
        amount = sampled.TotalSizeForTypeSample;
    }
    else
    {
        continue;
    }

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
        key = typeName + "  <-  " + string.Join(" <- ", names.Take(frames).Select(n => n.Length > 110 ? n[..110] : n));
    }
    else
    {
        string? first = names.FirstOrDefault(n => n.StartsWith("Mta.", StringComparison.Ordinal))
            ?? names.FirstOrDefault(n => interesting.IsMatch(n));
        if (first is null)
        {
            key = typeName + "  <-  (no known frame)";
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
                key = method + "  [" + typeName + "]";
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
