#!/usr/bin/env python3
"""Markdown summary of several runs of `Mta.Bench.Pipeline --json`: median and range per configuration.

  python3 bench/summarize-throughput.py <results directory> "<environment label>" > summary.md

Result files are named <configuration>.run<N>.json. The environment label is printed above the table verbatim, so a number can never be
read without the conditions it was measured under (docs/benchmarks.md, fairness rules). Python 3 standard library only.
"""
import glob
import json
import os
import re
import statistics
import sys


def parse_name(name):
    """<backend>-<sync>-<history>-<phase> -> (backend, sync, history, phase), or None for a name outside the matrix (a ReadyToRun run, an old name).

    sync is the SQLite synchronous mode (off, normal, full) or, for PostgreSQL, off (synchronous_commit=off) and on (the default, durable)."""
    parts = name.split("-")
    if len(parts) == 4 and parts[0] in ("sqlite", "postgres") and parts[3] in ("ingest", "delivery"):
        return tuple(parts)
    return None


def print_pairs(groups):
    """The durable/non-durable pairs side by side: a number without its pair is not a result (docs/benchmarks.md, fairness rule 2)."""
    cells = {}
    for name, runs in groups.items():
        key = parse_name(name)
        if key is None:
            continue
        backend, sync, history, phase = key
        if phase == "delivery":
            values = [r["EndToEnd"]["RecipientsPerSecond"] for r in runs if r.get("EndToEnd")]
        else:
            values = [r["Ingest"]["MessagesPerSecond"] for r in runs]
        if not values:
            continue
        middle = sorted(runs, key=lambda r: r["Ingest"]["MessagesPerSecond"])[len(runs) // 2]
        cells[(backend, history, phase, sync)] = (statistics.median(values), min(values), max(values), middle["Ingest"]["LatencyMs"]["P99"], len(values))
    if not cells:
        return
    print("### Durable and non-durable, side by side")
    print()
    print("Non-durable is SQLite `Sqlite:SyncMode=Off` (the default; safe against a process kill, not against power loss) and PostgreSQL `synchronous_commit=off`. "
          "Durable is SQLite `Full` (and `Normal`, which survives a process kill and an OS crash but may lose the last commits on power loss) and PostgreSQL with the default `synchronous_commit=on` and `fsync=on`. "
          "Ingest rows are accepted messages per second; delivery rows are recipients per second delivered end to end to the counting sink. Ratio = non-durable / durable.")
    print()
    print("| Backend | History | What | Non-durable (median, min-max) | Durable (median, min-max) | Ratio | Ingest p99 ms (non-durable / durable) |")
    print("|---|---|---|---:|---:|---:|---|")
    for backend, history, phase in sorted({(k[0], k[1], k[2]) for k in cells}):
        fast = cells.get((backend, history, phase, "off"))
        slow_syncs = ["full", "normal"] if backend == "sqlite" else ["on"]
        for sync in slow_syncs:
            slow = cells.get((backend, history, phase, sync))
            if fast is None and slow is None:
                continue
            fmt = lambda c: "not measured" if c is None else "%s (%s-%s)" % (format(round(c[0]), ","), format(round(c[1]), ","), format(round(c[2]), ","))
            if slow is None:
                continue
            ratio = "%.1fx" % (fast[0] / slow[0]) if fast and slow[0] else "n/a"
            what = "end-to-end recipients/s" if phase == "delivery" else "ingest msg/s"
            durable_name = {"full": "SQLite Full", "normal": "SQLite Normal", "on": "PostgreSQL default"}[sync]
            print("| %s | %s | %s | %s | %s: %s | %s | %s / %s |" % (
                backend, history, what, fmt(fast), durable_name, fmt(slow), ratio, fast[3] if fast else "n/a", slow[3]))
    print()


def main():
    directory, label = sys.argv[1], sys.argv[2]
    groups = {}
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        match = re.match(r"(.+)\.run\d+\.json$", os.path.basename(path))
        if not match:
            continue
        with open(path, encoding="utf-8") as handle:
            groups.setdefault(match.group(1), []).append(json.load(handle))

    print("**%s**" % label)
    print()
    machine = next(iter(groups.values()))[0]["Machine"] if groups else {}
    print("Machine as seen by the process: %s logical cores, %s, %s." % (machine.get("ProcessorCount"), machine.get("OS"), machine.get("Runtime")))
    print("Load generator, server, sink and (for the PostgreSQL rows) the database share the same machine. Each row is the median of N runs.")
    print()
    print_pairs(groups)
    print("### Every configuration")
    print()
    print("| Configuration | Runs | Ingest msg/s median (min-max) | p50 / p99 ms (median run) | Alloc B/msg | CPU ms/1000 msg | End-to-end recipients/s | Gen2 GCs |")
    print("|---|---:|---:|---|---:|---:|---:|---:|")
    for name, runs in groups.items():
        rates = [r["Ingest"]["MessagesPerSecond"] for r in runs]
        middle = sorted(runs, key=lambda r: r["Ingest"]["MessagesPerSecond"])[len(runs) // 2]
        end_to_end = [r["EndToEnd"]["RecipientsPerSecond"] for r in runs if r.get("EndToEnd")]
        print("| %s (%d msg, %d conn, %d B) | %d | %s (%s-%s) | %s / %s | %s | %s | %s | %s |" % (
            name, runs[0]["Messages"], runs[0]["Connections"], runs[0]["SizeBytes"], len(runs),
            format(round(statistics.median(rates)), ","), format(round(min(rates)), ","), format(round(max(rates)), ","),
            middle["Ingest"]["LatencyMs"]["P50"], middle["Ingest"]["LatencyMs"]["P99"],
            format(round(statistics.median(r["Ingest"]["ServerAllocatedBytesPerMessage"] for r in runs)), ","),
            statistics.median(r["Ingest"]["ServerCpuMsPer1000Messages"] for r in runs),
            format(round(statistics.median(end_to_end)), ",") if end_to_end else "not measured",
            round(statistics.median(r["Gen2Collections"] for r in runs))))


if __name__ == "__main__":
    main()
