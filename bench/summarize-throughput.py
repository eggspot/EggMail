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
