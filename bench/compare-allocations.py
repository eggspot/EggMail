#!/usr/bin/env python3
"""Allocation regression gate: compares allocation per message against the checked-in baseline and fails on a regression.

  python3 bench/compare-allocations.py --baseline bench/baseline/allocations.json --micro micro.json --pipeline pipeline.json \
      [--summary summary.md] [--write-candidate candidate.json]

Why allocations and not throughput: bytes allocated per operation do not depend on how loaded or fast the machine is (a shared CI
runner makes throughput numbers meaningless, but not allocation counts), so a regression here is a real code change.

  micro.json     from `Mta.Bench.Pipeline --micro true --json`: bytes per call of each ingest step, measured on the calling thread. Exact and
                 repeatable, so its threshold is tight (thresholds.microPercent in the baseline file).
  pipeline.json  from `Mta.Bench.Pipeline --deliver false --json`: total process allocation per accepted message through the real runtime
                 (SMTP ingest, storage). Varies by about 2 percent between runs of the same code (timing of batched writes), so its threshold is
                 looser (thresholds.pipelinePercent).

Exit code 1: a value is more than the threshold above the baseline, or a baseline entry is missing from the measurement. A value more than
the threshold BELOW the baseline is reported as an improvement and does not fail; update the baseline in the pull request that earned it
(--write-candidate writes the file to copy over bench/baseline/allocations.json). Python 3 standard library only.
"""
import argparse
import json
import sys


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def compare(name, baseline, measured, percent, rows):
    if measured is None:
        rows.append((name, baseline, None, None, "MISSING"))
        return False
    # A step that allocates nothing has no percentage: it regresses as soon as it allocates more than a few bytes (rounding of the per-call average).
    change = (measured - baseline) * 100.0 / baseline if baseline else (0.0 if measured <= 16 else 100.0)
    if change > percent:
        verdict = "REGRESSION"
    elif change < -percent:
        verdict = "improved (update the baseline)"
    else:
        verdict = "ok"
    rows.append((name, baseline, measured, change, verdict))
    return verdict not in ("REGRESSION", "MISSING")


def table(title, rows, percent):
    lines = ["### %s (fail above +%g %%)" % (title, percent), "", "| Measurement | Baseline B | Now B | Change | Result |", "|---|---:|---:|---:|---|"]
    for name, baseline, measured, change, verdict in rows:
        lines.append("| %s | %s | %s | %s | %s |" % (
            name, format(baseline, ","), "n/a" if measured is None else format(measured, ","),
            "n/a" if change is None else "%+.1f %%" % change, verdict))
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--micro", required=True)
    parser.add_argument("--pipeline", required=True)
    parser.add_argument("--summary", help="write the markdown report here (also printed)")
    parser.add_argument("--write-candidate", help="write a new baseline file built from this measurement")
    args = parser.parse_args()

    baseline = load(args.baseline)
    micro = load(args.micro)["BytesPerOperation"]
    pipeline = load(args.pipeline)
    thresholds = baseline["thresholds"]
    ok = True

    micro_rows = []
    for name, expected in baseline["micro"].items():
        ok &= compare(name, expected, micro.get(name), thresholds["microPercent"], micro_rows)

    pipeline_rows = []
    for key, expected in baseline["pipeline"].items():
        shape = (pipeline["Messages"], pipeline["Connections"], pipeline["SizeBytes"], pipeline["History"], pipeline.get("SqliteSync"))
        want = (expected["messages"], expected["connections"], expected["sizeBytes"], expected["history"], expected["sqliteSync"])
        if shape != want:
            print("pipeline measurement shape %s differs from the baseline %s" % (shape, want), file=sys.stderr)
            ok = False
        ok &= compare(key, expected["bytesPerMessage"], pipeline["Ingest"]["ServerAllocatedBytesPerMessage"], thresholds["pipelinePercent"], pipeline_rows)

    report = "\n\n".join([
        "## Allocation gate",
        "Baseline: " + baseline["recordedOn"],
        table("Per step, exact (micro)", micro_rows, thresholds["microPercent"]),
        table("Per accepted message through the real runtime (pipeline)", pipeline_rows, thresholds["pipelinePercent"]),
        "**Result: %s**" % ("passed" if ok else "FAILED: allocation per message grew beyond the threshold"),
    ])
    print(report)
    if args.summary:
        with open(args.summary, "w", encoding="utf-8") as handle:
            handle.write(report + "\n")

    if args.write_candidate:
        candidate = dict(baseline)
        candidate["micro"] = {name: micro[name] for name in baseline["micro"] if name in micro}
        candidate["pipeline"] = {
            key: dict(expected, bytesPerMessage=pipeline["Ingest"]["ServerAllocatedBytesPerMessage"])
            for key, expected in baseline["pipeline"].items()
        }
        candidate["recordedOn"] = "UPDATE ME: where and when this was measured"
        with open(args.write_candidate, "w", encoding="utf-8") as handle:
            json.dump(candidate, handle, indent=2)
            handle.write("\n")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
