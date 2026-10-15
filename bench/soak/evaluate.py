#!/usr/bin/env python3
"""Soak verdict: reads the files a soak run wrote and decides PASS or FAIL against fixed, documented criteria (docs/soak.md).

  python3 bench/soak/evaluate.py <run directory> [--rss-growth-pct 20 ...]     writes verdict.json and summary.md, exits 1 on FAIL
  python3 bench/soak/evaluate.py --self-test                                   checks the criteria against synthetic runs

Inputs in the run directory (all written by soak.py):
  config.json         the parameters of the run
  samples.csv         one row per sample (default every minute)
  events.jsonl        phases and drills with epoch timestamps
  load-stats.jsonl    the load generator's counters and latency percentiles every 10 s
  verification.json   the end-of-run reconciliation of acknowledged messages against the sink

The criteria are in CRITERIA below; every threshold can be overridden on the command line. A criterion that cannot be evaluated (a run too short
for a trend, a history mode that records no events) is reported as SKIP with the reason and never counts as a pass of that criterion; the verdict
says "PASS (n skipped)" so a short smoke run is not mistaken for a full soak.

Python 3 standard library only (3.9 or newer).
"""
import argparse
import csv
import datetime
import json
import os
import statistics
import sys
import tempfile

# name -> (default, meaning). The numbers are deliberately plain: they are what docs/soak.md promises.
THRESHOLDS = {
    "rss_growth_pct": (20.0, "RSS of the uninterrupted tail: median of the last quarter may exceed the median of the first quarter by at most this many percent"),
    "fd_growth_abs": (10.0, "open file descriptors: the last quarter may exceed the first by at most max(this, 10 percent)"),
    "thread_growth_abs": (6.0, "OS threads: the last quarter may exceed the first by at most max(this, 10 percent)"),
    "error_rate_pct": (0.5, "share of submissions refused by a live server, or failed on a healthy connection, outside crash windows"),
    "crash_window_s": (30.0, "seconds after a restart that still count as the crash window (errors in it are expected)"),
    "min_trend_samples": (8.0, "samples needed in the tail to judge a trend; fewer -> SKIP"),
    "p99_growth_ratio": (3.0, "advisory: p99 submission latency of the last quarter over the first quarter (WARN above)"),
    "ack_log_tolerance_pct": (0.1, "the ack log may hold this many percent fewer messages than the generator counted as accepted (at least 5 messages)"),
    "sampler_min_fraction": (0.8, "samples.csv must hold at least this fraction of the rows the run's length and sample interval promise"),
    "drills_min_fraction": (0.5, "at least this fraction of the drills the run's length and drill interval promise must have completed"),
    "flagged_single_pct": (1.0, "share of the messages the sink received once (in a sample) that may carry a possible_duplicate flag: the flag must not be sprayed"),
    "max_flagged_per_kill": (400.0, "possible_duplicate flags on once-received messages allowed per kill -9 (a killed server held at most a claim batch plus its in-flight sends)"),
}

# Trend criteria: the ones a short run cannot judge. With --strict (automatic from one hour of load) a SKIP among them is a FAIL.
TREND_CRITERIA = ("RSS flat after warm-up", "file descriptors flat", "OS threads flat")

STATUS_ORDER = {"FAIL": 0, "WARN": 1, "SKIP": 2, "PASS": 3}


def parse_iso(text):
    """ISO time with a Z and up to seven fractional digits (what .NET writes) -> epoch seconds."""
    text = text.rstrip("Z")
    if "." in text:
        head, frac = text.split(".", 1)
        text = head + "." + frac[:6]
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
    else:
        fmt = "%Y-%m-%dT%H:%M:%S"
    return datetime.datetime.strptime(text, fmt).replace(tzinfo=datetime.timezone.utc).timestamp()


def load_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def load_jsonl(path):
    rows = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass     # a line cut off by a kill while it was written
    except OSError:
        pass
    return rows


def load_samples(path):
    rows = []
    try:
        with open(path, newline="", encoding="utf-8") as handle:
            for raw in csv.DictReader(handle):
                row = {}
                for key, value in raw.items():
                    if key in ("iso", "phase"):
                        row[key] = value
                    else:
                        try:
                            row[key] = float(value) if value not in ("", None) else None
                        except ValueError:
                            row[key] = None
                rows.append(row)
    except OSError:
        pass
    return rows


# --------------------------------------------------------------------------- statistics

def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def quarters(values):
    """(first quarter, last quarter) of a list, at least one element each."""
    n = max(1, len(values) // 4)
    return values[:n], values[-n:]


def theil_sen_per_hour(points):
    """Median of pairwise slopes of (seconds, value) points, per hour. Robust against the spikes a plain regression would follow."""
    points = [(t, v) for t, v in points if v is not None]
    if len(points) < 3:
        return None
    step = max(1, len(points) // 200)          # at most about 200 points: 20,000 pairs
    points = points[::step]
    slopes = []
    for i in range(len(points)):
        for j in range(i + 1, len(points)):
            dt = points[j][0] - points[i][0]
            if dt > 0:
                slopes.append((points[j][1] - points[i][1]) / dt)
    return statistics.median(slopes) * 3600 if slopes else None


def sparkline(values, width=48):
    values = [v for v in values if v is not None]
    if not values:
        return ""
    bars = "▁▂▃▄▅▆▇█"
    if len(values) > width:
        size = len(values) / width
        values = [statistics.mean(values[int(i * size):max(int(i * size) + 1, int((i + 1) * size))]) for i in range(width)]
    low, high = min(values), max(values)
    if high == low:
        return bars[0] * len(values)
    return "".join(bars[min(len(bars) - 1, int((v - low) / (high - low) * (len(bars) - 1) + 0.5))] for v in values)


# --------------------------------------------------------------------------- criteria

def tail_window(samples, config, thresholds):
    """The samples a trend is judged on: the last process generation, while load runs, after that process has warmed up."""
    load = [s for s in samples if s.get("phase") == "load" and s.get("up") == 1.0]
    if not load:
        return []
    generation = load[-1]["generation"]
    warmup_s = config.get("warmup_s", 300)
    return [s for s in load if s["generation"] == generation and (s.get("uptime_s") or 0) >= warmup_s]


def growth_criterion(name, window, key, limit_abs, limit_pct, unit, thresholds):
    """Two views of the same tail, both must hold: the median of the last quarter against the median of the first (a shift, robust against spikes), and the
    Theil-Sen drift (the median pairwise slope times the length of the tail: how far the line the data follows climbs over the whole tail, so it scales with
    the length of the run). A leak shows in both, a spike in neither."""
    need = int(thresholds["min_trend_samples"])
    points = [(s["elapsed_s"], s.get(key)) for s in window if s.get(key) is not None]
    values = [v for _, v in points]
    if len(values) < need:
        return {"name": name, "status": "SKIP", "detail": "only %d samples in the uninterrupted tail, %d needed (run longer, or sample more often)" % (len(values), need)}
    first, last = quarters(values)
    a, b = median(first), median(last)
    allowed = max(limit_abs, a * limit_pct / 100.0) if limit_pct is not None else limit_abs
    shift = b - a
    slope = theil_sen_per_hour(points)
    span_h = (points[-1][0] - points[0][0]) / 3600.0
    drift = slope * span_h if slope is not None else 0.0
    detail = "first quarter median %.1f %s, last quarter median %.1f %s (shift %+.1f); Theil-Sen slope %s per hour = %+.1f %s of drift over the %.0f minute tail; allowed %.1f for each; %d samples" % (
        a, unit, b, unit, shift, ("%+.2f %s" % (slope, unit)) if slope is not None else "n/a", drift, unit, span_h * 60, allowed, len(values))
    return {"name": name, "status": "PASS" if shift <= allowed and drift <= allowed else "FAIL", "detail": detail, "first": a, "last": b, "slope_per_hour": slope, "drift": drift}


def crash_windows(events, thresholds):
    """(start, end) epoch pairs: from each kill until the restarted server was ready plus the grace."""
    windows = []
    kill = None
    for e in events:
        if e.get("type") == "crash_kill":
            kill = e["ts"]
        elif e.get("type") in ("crash_ready", "crash_failed") and kill is not None:
            windows.append((kill, e["ts"] + thresholds["crash_window_s"]))
            kill = None
    if kill is not None:
        windows.append((kill, kill + 600))
    return windows


def error_accounting(stats, events, thresholds):
    """Failures by the generator, split into those inside crash windows (expected) and the rest. Each stats line covers the time since the previous one."""
    windows = crash_windows(events, thresholds)
    accepted = rejected_out = errors_out = rejected_in = errors_in = 0
    previous = None
    for line in stats:
        try:
            now = parse_iso(line["t"])
        except (KeyError, ValueError):
            continue
        if previous is not None:
            start = previous[0]
            inside = any(start < w_end and now > w_start for w_start, w_end in windows)
            d_rej = line["rejected"] - previous[1]
            d_err = line["connect_errors"] - previous[2]
            d_acc = line["accepted"] - previous[3]
            if d_rej < 0 or d_err < 0 or d_acc < 0:
                d_rej, d_err, d_acc = line["rejected"], line["connect_errors"], line["accepted"]
            accepted += d_acc
            if inside:
                rejected_in += d_rej
                errors_in += d_err
            else:
                rejected_out += d_rej
                errors_out += d_err
        previous = (now, line["rejected"], line["connect_errors"], line["accepted"])
    return {"accepted": accepted, "failed_outside": rejected_out + errors_out, "rejected_outside": rejected_out, "connect_errors_outside": errors_out,
            "failed_inside_crash_windows": rejected_in + errors_in}


def evaluate(run_dir, thresholds, strict=None):
    config = load_json(os.path.join(run_dir, "config.json"), {})
    samples = load_samples(os.path.join(run_dir, "samples.csv"))
    events = load_jsonl(os.path.join(run_dir, "events.jsonl"))
    stats = load_jsonl(os.path.join(run_dir, "load-stats.jsonl"))
    verification = load_json(os.path.join(run_dir, "verification.json"), None)
    criteria = []

    def add(name, status, detail, **extra):
        item = {"name": name, "status": status, "detail": detail}
        item.update(extra)
        criteria.append(item)

    # 1 and 2: the delivery contract
    if verification is None:
        add("no acknowledged message lost", "FAIL", "verification.json is missing: the run did not reach its end-of-run reconciliation")
        add("no unflagged duplicate", "FAIL", "verification.json is missing")
    else:
        lost = verification.get("lost_count", -1)
        add("no acknowledged message lost", "PASS" if lost == 0 else "FAIL",
            "%d acknowledged, %d delivered at least once, %d lost%s" % (
                verification.get("acknowledged", 0), verification.get("delivered_unique_of_acknowledged", 0), lost,
                ((" (first: %s)" % verification.get("lost_sample", [])[:10]) +
                 ("; the queue had not drained, so these may only be waiting for a retry (a destination that answers 4xx twice in a row delays a message 7 minutes, three times 22)"
                  if (verification.get("drain") or {}).get("drained") is False else "")) if lost else ""))
        unflagged = verification.get("duplicates_unflagged")
        duplicates = verification.get("duplicates", 0)
        if verification.get("duplicates_verifiable") is False:
            add("no unflagged duplicate", "SKIP", "%d duplicate(s) at the sink; History:Mode=StatsOnly records no events, so the possible_duplicate flag cannot be read" % duplicates)
        elif unflagged is None:
            add("no unflagged duplicate", "FAIL", "the duplicates could not be checked: %s" % verification.get("duplicates_error", "unknown"))
        else:
            checked = verification.get("duplicates_checked", duplicates)
            add("no unflagged duplicate", "PASS" if unflagged == 0 else "FAIL",
                "%d message(s) arrived more than once; %d checked through the API, %d flagged possible_duplicate, %d NOT flagged%s" % (
                    duplicates, checked, verification.get("duplicates_flagged", 0), unflagged,
                    (" (first: %s)" % verification.get("duplicates_unflagged_sample", [])[:10]) if unflagged else ""))

    if verification is not None:
        # The sink dropped final replies on purpose: the server must have retried those and produced duplicates, or the flag path was never exercised
        # (and "no unflagged duplicate" proved nothing).
        dropped = verification.get("sink_dropped_acks", 0)
        duplicates = verification.get("duplicates", 0)
        if config.get("sink_drop_ack_rate", 0) > 0:
            if dropped > 0 and duplicates == 0:
                add("duplicate path exercised", "FAIL", "the sink kept %d message(s) without answering, yet none arrived twice: the server did not retry a delivery whose outcome it could not know" % dropped)
            elif dropped == 0 and verification.get("acknowledged", 0) * config["sink_drop_ack_rate"] >= 20:
                add("duplicate path exercised", "WARN", "the sink was set to drop %.1f%% of final replies but dropped none in %d messages: the possible_duplicate check ran on nothing" % (
                    100 * config["sink_drop_ack_rate"], verification.get("acknowledged", 0)))
            else:
                add("duplicate path exercised", "PASS", "the sink dropped %d final replies; %d message(s) arrived twice or more" % (dropped, duplicates))
        # The flag must mean something: on messages the sink received exactly once it is allowed after a kill (the server held them), not as a habit.
        checked = verification.get("singles_checked")
        if checked is not None:
            flagged = verification.get("singles_flagged", 0)
            kills = len([e for e in events if e.get("type") == "crash_kill"])
            share = 100.0 * flagged / checked if checked else 0.0
            # What kills can explain: at most max_flagged_per_kill messages each, as a share of everything acknowledged; never less than the flat limit.
            limit = max(thresholds["flagged_single_pct"], 100.0 * kills * thresholds["max_flagged_per_kill"] / max(1, verification.get("acknowledged", 1)))
            sprayed = share > limit or (kills == 0 and flagged > 0)      # without a kill nothing held a once-received message in doubt
            add("possible_duplicate is not sprayed", "FAIL" if sprayed else "PASS",
                "%d of %d sampled once-received messages carry the flag (%.2f%%; limit %.2f%% for %d kill(s); none allowed without a kill)" % (flagged, checked, share, limit, kills))
        # the generator is judged too
        code = verification.get("load_exit_code")
        if code is not None:
            add("load generator exit code", "PASS" if code == 0 else "FAIL", "mta-tools load exited with %s" % code)
        # the ack log is the evidence of the whole run: it must be there and complete
        acknowledged = verification.get("acknowledged", 0)
        counted = max([line.get("accepted", 0) for line in stats] or [0])
        tolerance = max(5, counted * thresholds["ack_log_tolerance_pct"] / 100.0)
        if acknowledged == 0:
            add("ack log complete", "FAIL", "the ack log holds no acknowledged message: nothing was proven")
        elif acknowledged < counted - tolerance:
            add("ack log complete", "FAIL", "the ack log holds %d messages but the generator counted %d accepted (tolerance %d)" % (acknowledged, counted, tolerance))
        else:
            add("ack log complete", "PASS", "%d acknowledged messages in the ack log, the generator counted %d accepted" % (acknowledged, counted))

    # the harness itself: samples, drills and their errors
    expected_rows = config.get("duration_s", 0) / config["sample_interval_s"] if config.get("sample_interval_s") else 0
    if expected_rows:
        rows = len([s for s in samples if s.get("phase") == "load"])
        add("sampler kept up", "PASS" if rows >= thresholds["sampler_min_fraction"] * expected_rows else "FAIL",
            "%d samples during the load, %.0f expected at one every %.0f s (at least %.0f%% required)" % (rows, expected_rows, config["sample_interval_s"], 100 * thresholds["sampler_min_fraction"]))
    errors = [e for e in events if e.get("type") == "drill_error"]
    add("harness errors", "FAIL" if errors else "PASS",
        ("%d error(s) in the drill loop or the server watch, the first (%s): %s" % (len(errors), errors[0].get("where"), errors[0].get("error"))) if errors else "no error in the drill loop or the server watch")
    tail = 1.0 - config.get("quiet_tail", 0.25)
    for label, key, event in (("crash", "crash_interval_min", "crash_ready"), ("backup", "backup_interval_min", "backup_drill")):
        interval = config.get(key, 0)
        if interval > 0 and config.get("duration_s"):
            expected = int(config["duration_s"] * tail / (interval * 60.0))
            done = len([e for e in events if e.get("type") == event])      # a drill that ran and failed is judged by its own criterion
            if expected >= 1:
                add("%s drills ran as often as promised" % label, "PASS" if done >= thresholds["drills_min_fraction"] * expected else "FAIL",
                    "%d %s drill(s) completed, %d expected in the drill part of the run at one every %g minutes (at least %.0f%% required)" % (
                        done, label, expected, interval, 100 * thresholds["drills_min_fraction"]))

    # the run must have been what it claims to be
    if stats and config.get("duration_s"):
        ran = max(line.get("elapsed_s", 0) for line in stats)
        add("load ran for the whole duration", "PASS" if ran >= 0.95 * config["duration_s"] else "FAIL",
            "the load generator reported %s of the requested %s" % (fmt_duration(ran), fmt_duration(config["duration_s"])))
    elif config.get("duration_s"):
        add("load ran for the whole duration", "FAIL", "the load generator wrote no statistics")
    if verification is not None and verification.get("unexpected_exits") is not None:
        exits = verification["unexpected_exits"]
        add("server stayed up between drills", "PASS" if exits == 0 else "FAIL", "%d exit(s) of the server that no drill caused" % exits)

    # 3: errors
    acct = error_accounting(stats, events, thresholds)
    total = acct["accepted"] + acct["failed_outside"]
    if total <= 0:
        add("error rate", "FAIL", "the load generator accepted no message")
    else:
        rate = 100.0 * acct["failed_outside"] / total
        add("error rate", "PASS" if rate <= thresholds["error_rate_pct"] else "FAIL",
            "%.3f%% of %d submissions failed outside crash windows (%d refused by a live server, %d connection errors); limit %.2f%%; %d more failures inside crash windows are expected" % (
                rate, total, acct["rejected_outside"], acct["connect_errors_outside"], thresholds["error_rate_pct"], acct["failed_inside_crash_windows"]))

    # 4: queue drains
    drain = (verification or {}).get("drain")
    if drain is None:
        add("queue drains to zero after load stops", "FAIL", "no drain result")
    else:
        add("queue drains to zero after load stops", "PASS" if drain.get("drained") else "FAIL",
            "after the load stopped: queue depth %s, deferred %s, drained in %s s (limit %s s)" % (
                drain.get("depth"), drain.get("deferred"), drain.get("seconds"), drain.get("limit_seconds")))

    # 5: trends on the uninterrupted tail
    window = tail_window(samples, config, thresholds)
    criteria.append(growth_criterion("RSS flat after warm-up", window, "rss_mb", 0.0, thresholds["rss_growth_pct"], "MB", thresholds))
    criteria.append(growth_criterion("file descriptors flat", window, "fds", thresholds["fd_growth_abs"], 10.0, "fds", thresholds))
    criteria.append(growth_criterion("OS threads flat", window, "threads", thresholds["thread_growth_abs"], 10.0, "threads", thresholds))
    # the same RSS test on every earlier process generation: advisory (a restart every 20 minutes cannot show a slow leak, the tail can)
    worst = None
    for generation in sorted({s["generation"] for s in samples if s.get("generation") is not None}):
        segment = [s for s in samples if s["generation"] == generation and s.get("phase") == "load" and (s.get("uptime_s") or 0) >= config.get("warmup_s", 300)]
        values = [s["rss_mb"] for s in segment if s.get("rss_mb") is not None]
        if len(values) >= int(thresholds["min_trend_samples"]):
            first, last = quarters(values)
            growth = 100.0 * (median(last) - median(first)) / median(first) if median(first) else 0.0
            if worst is None or growth > worst[0]:
                worst = (growth, int(generation), len(values))
    if worst is not None and worst[0] > thresholds["rss_growth_pct"]:
        add("RSS growth in every process generation", "WARN", "generation %d grew %.1f%% (limit %.0f%%) over %d samples" % (worst[1], worst[0], thresholds["rss_growth_pct"], worst[2]))
    elif worst is not None:
        add("RSS growth in every process generation", "PASS", "worst generation %d: %+.1f%% over %d samples" % (worst[1], worst[0], worst[2]))

    # advisory: latency
    p99 = [s.get("lat_p99_ms") for s in window if s.get("lat_p99_ms") is not None]
    if len(p99) >= int(thresholds["min_trend_samples"]):
        first, last = quarters(p99)
        a, b = median(first), median(last)
        ratio = b / a if a else 1.0
        add("submission p99 latency stable", "PASS" if ratio <= thresholds["p99_growth_ratio"] else "WARN",
            "median p99 %.1f ms in the first quarter, %.1f ms in the last (x%.2f; advisory limit x%.1f)" % (a, b, ratio, thresholds["p99_growth_ratio"]))

    # drills
    drills = [e for e in events if e.get("type") in ("crash_ready", "crash_failed", "backup_drill", "restore_failed")]
    crash_ok = [e for e in events if e.get("type") == "crash_ready"]
    crash_bad = [e for e in events if e.get("type") == "crash_failed"]
    if config.get("crash_interval_min", 0) > 0 or crash_ok or crash_bad:
        if not crash_ok and not crash_bad:
            add("crash drills recover", "FAIL", "crash drills were configured but none ran")
        else:
            slow = [e for e in crash_ok if e.get("ready_after_s", 0) > e.get("limit_s", 120)]
            stalled = [e for e in events if e.get("type") == "crash_check" and e.get("missing", 0) > 0]
            add("crash drills recover", "PASS" if not crash_bad and not slow and not stalled else "FAIL",
                "%d kill -9 drill(s): %d restarted and ready (slowest %.1f s), %d failed to come back, %d left acknowledged messages undelivered past the recovery grace" % (
                    len(crash_ok) + len(crash_bad), len(crash_ok), max([e.get("ready_after_s", 0) for e in crash_ok] or [0]), len(crash_bad), len(stalled)))
    if config.get("backup_interval_min", 0) > 0 or any(e.get("type") in ("backup_drill", "restore_failed") for e in events):
        done = [e for e in events if e.get("type") == "backup_drill"]
        ok = [e for e in done if e.get("ok")]
        if not done:
            add("backup and restore drills", "FAIL", "backup drills were configured but none completed")
        else:
            add("backup and restore drills", "PASS" if len(ok) == len(done) else "FAIL",
                "%d backup+restore drill(s), %d restored and served correctly%s" % (
                    len(done), len(ok), "".join("; FAILED: %s" % e.get("error") for e in done if not e.get("ok"))[:400]))

    shutdown = (verification or {}).get("shutdown")
    if shutdown is not None:
        add("graceful shutdown", "PASS" if shutdown.get("exit_code") == 0 else "FAIL",
            "SIGTERM: exit code %s after %s s" % (shutdown.get("exit_code"), shutdown.get("seconds")))

    log_scan = (verification or {}).get("host_log")
    if log_scan is not None:
        status = "FAIL" if log_scan.get("critical", 0) else ("WARN" if log_scan.get("errors", 0) else "PASS")
        add("host log", status, "%d critical and %d error-level lines in host.log (%d lines in all)%s" % (
            log_scan.get("critical", 0), log_scan.get("errors", 0), log_scan.get("lines", 0),
            (": " + "; ".join(log_scan.get("sample", [])[:3])[:500]) if log_scan.get("errors") or log_scan.get("critical") else ""))

    strict = config.get("strict", False) if strict is None else strict
    if strict:
        for c in criteria:
            if c["status"] == "SKIP" and c["name"] in TREND_CRITERIA:
                c["status"] = "FAIL"
                c["detail"] = "strict run (one hour of load or more, or --strict): a trend that cannot be judged is a failure. " + c["detail"]
    failed = [c for c in criteria if c["status"] == "FAIL"]
    skipped = [c for c in criteria if c["status"] == "SKIP"]
    verdict = "FAIL" if failed else "PASS"
    return {"verdict": verdict, "skipped": len(skipped), "criteria": criteria, "thresholds": thresholds, "error_accounting": acct,
            "tail_window_samples": len(window), "drill_events": len(drills)}


# --------------------------------------------------------------------------- summary

def fmt_duration(seconds):
    seconds = int(seconds)
    return "%dh %02dm" % (seconds // 3600, seconds % 3600 // 60)


def summary_markdown(run_dir, result):
    config = load_json(os.path.join(run_dir, "config.json"), {})
    samples = load_samples(os.path.join(run_dir, "samples.csv"))
    events = load_jsonl(os.path.join(run_dir, "events.jsonl"))
    verification = load_json(os.path.join(run_dir, "verification.json"), {}) or {}
    stats = load_jsonl(os.path.join(run_dir, "load-stats.jsonl"))
    out = []
    verdict = result["verdict"] + (" (%d criteria skipped, see below)" % result["skipped"] if result["verdict"] == "PASS" and result["skipped"] else "")
    out.append("## Soak %s: %s, %s" % (verdict, config.get("backend", "?"), fmt_duration(config.get("duration_s", 0))))
    out.append("")
    out.append("**%s**" % config.get("environment_label", ""))
    out.append("")
    out.append("| Criterion | Result | Detail |")
    out.append("|---|---|---|")
    for c in sorted(result["criteria"], key=lambda c: (STATUS_ORDER[c["status"]], c["name"])):
        out.append("| %s | **%s** | %s |" % (c["name"], c["status"], c["detail"].replace("|", "/")))
    out.append("")
    out.append("### Run")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    for key in ("backend", "history", "sync", "rate_msgs_per_s", "size_mix", "connections", "crash_interval_min", "backup_interval_min", "duration_s", "warmup_s", "version", "machine"):
        if key in config:
            out.append("| %s | %s |" % (key, config[key]))
    acked = verification.get("acknowledged")
    if acked is not None:
        out.append("| messages acknowledged | %d |" % acked)
        out.append("| distinct messages the sink received | %s |" % verification.get("sink_unique", "?"))
        out.append("| sink receipts (duplicates included) | %s |" % verification.get("sink_total", "?"))
        out.append("| duplicates | %s (sink dropped %s final replies on purpose, answered %s with 451) |" % (verification.get("duplicates"), verification.get("sink_dropped_acks"), verification.get("sink_tempfails")))
    kills = len([e for e in events if e.get("type") == "crash_kill"])
    out.append("| crash drills (kill -9) | %d |" % kills)
    out.append("| backup and restore drills | %d |" % len([e for e in events if e.get("type") == "backup_drill"]))
    out.append("")
    if samples:
        out.append("### Trends")
        out.append("")
        out.append("Each line is the whole run, oldest on the left; restarts show as steps.")
        out.append("")
        out.append("```")
        for key, label in (("rss_mb", "RSS MB"), ("fds", "open FDs"), ("threads", "threads"), ("queue_depth", "queue depth"), ("gc_gen2", "gen2 GCs (cumulative per process)"), ("lat_p99_ms", "p99 submit ms"), ("disk_mb", "disk MB")):
            values = [s.get(key) for s in samples]
            clean = [v for v in values if v is not None]
            if clean:
                out.append("%-32s %s  min %.0f  max %.0f  last %.0f" % (label, sparkline(values), min(clean), max(clean), clean[-1]))
        out.append("```")
        out.append("")
    if stats:
        out.append("The load generator's own counters: %d accepted, %d refused by the server, %d connection errors in total; the server ended %d sessions at its per-session message limit (421, `Smtp:MaxMessagesPerSession`) and the generator reconnected." % (
            stats[-1]["accepted"], stats[-1]["rejected"], stats[-1]["connect_errors"], stats[-1].get("session_limit_closes", 0)))
        out.append("")
    drills = [e for e in events if e.get("type") in ("crash_ready", "crash_failed", "crash_check", "backup_drill")]
    if drills:
        out.append("### Drills")
        out.append("")
        out.append("| When (elapsed) | Drill | Result |")
        out.append("|---|---|---|")
        for e in drills[:60]:
            when = fmt_duration(e.get("elapsed_s", 0))
            if e["type"] == "crash_ready":
                out.append("| %s | kill -9, restart | ready after %.1f s; %s messages had been acknowledged before the kill |" % (when, e.get("ready_after_s", 0), e.get("acked_before_kill", "?")))
            elif e["type"] == "crash_check":
                out.append("| %s | recovery check%s | %s of the %s messages acknowledged before that kill are still undelivered |" % (when, " (at the end of the run)" if e.get("at_end") else "", e.get("missing"), e.get("checked")))
            elif e["type"] == "crash_failed":
                out.append("| %s | kill -9, restart | DID NOT COME BACK: %s |" % (when, e.get("error")))
            else:
                out.append("| %s | backup + restore | %s |" % (when, "ok: " + e.get("detail", "") if e.get("ok") else "FAILED: " + str(e.get("error"))))
        if len(drills) > 60:
            out.append("| | | ... %d more in events.jsonl |" % (len(drills) - 60))
        out.append("")
    out.append("Files: `samples.csv`, `events.jsonl`, `load-stats.jsonl`, `ack.log`, `verification.json`, `verdict.json`, `host.log`, `load.log` (the workflow artifact). Criteria and thresholds: docs/soak.md.")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- self-test

def synthetic_run(directory, rss_slope=0.0, fd_slope=0.0, lost=0, unflagged=0, depth=0, errors=0, history="full", minutes=120, strict=False,
                  crash_stalled=0, crash_failed=False, no_crash_drill=False, backup_ok=True, unexpected_exits=0, shutdown_code=0, no_verification=False,
                  dup_error=None, acknowledged=1000, singles_flagged=0, dropped=3, duplicates=3, drill_error=False, load_exit_code=0, row_every=1):
    """A fake run directory: one sample a minute, a process restart at minute 40, load stats every 10 s, drills at 40 minutes."""
    os.makedirs(directory, exist_ok=True)
    start = 1_800_000_000.0
    config = {"backend": "sqlite", "duration_s": minutes * 60, "warmup_s": 300, "crash_interval_min": 40, "backup_interval_min": 40, "history": history,
              "environment_label": "synthetic", "strict": strict, "sample_interval_s": 60, "quiet_tail": 0.25, "sink_drop_ack_rate": 0.005}
    with open(os.path.join(directory, "config.json"), "w") as handle:
        json.dump(config, handle)
    with open(os.path.join(directory, "samples.csv"), "w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["iso", "ts", "elapsed_s", "generation", "uptime_s", "phase", "up", "rss_mb", "fds", "threads", "lat_p99_ms", "queue_depth"])
        for minute in range(0, minutes, row_every):
            generation = 1 if minute < 40 else 2
            uptime = (minute if minute < 40 else minute - 40) * 60
            noise = ((minute * 7919) % 13) / 13.0
            writer.writerow(["", start + minute * 60, minute * 60, generation, uptime, "load", 1, 200 + noise * 4 + rss_slope * minute, 80 + fd_slope * minute, 30 + (minute % 3), 5 + noise, 3])
    with open(os.path.join(directory, "events.jsonl"), "w") as handle:
        if not no_crash_drill:
            handle.write(json.dumps({"type": "crash_kill", "ts": start + 40 * 60, "elapsed_s": 40 * 60}) + "\n")
            if crash_failed:
                handle.write(json.dumps({"type": "crash_failed", "ts": start + 40 * 60 + 130, "elapsed_s": 40 * 60 + 130, "error": "not ready"}) + "\n")
            else:
                handle.write(json.dumps({"type": "crash_ready", "ts": start + 40 * 60 + 8, "elapsed_s": 40 * 60 + 8, "ready_after_s": 8.0, "limit_s": 120}) + "\n")
            handle.write(json.dumps({"type": "crash_check", "ts": start + 70 * 60, "elapsed_s": 70 * 60, "checked": 500, "missing": crash_stalled}) + "\n")
        handle.write(json.dumps({"type": "backup_drill", "ts": start + 41 * 60, "elapsed_s": 41 * 60, "ok": backup_ok, "error": None if backup_ok else "integrity_check says malformed", "detail": "ok"}) + "\n")
        if drill_error:
            handle.write(json.dumps({"type": "drill_error", "ts": start + 50 * 60, "elapsed_s": 50 * 60, "error": "OSError('boom')"}) + "\n")
    with open(os.path.join(directory, "load-stats.jsonl"), "w") as handle:
        accepted = rejected = connect_errors = 0
        for tick in range(minutes * 6):
            now = start + tick * 10
            accepted += 300
            in_crash = 40 * 60 <= tick * 10 <= 40 * 60 + 40
            if in_crash:
                connect_errors += 50
            elif errors and tick % 20 == 0:
                rejected += errors
            stamp = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"
            handle.write(json.dumps({"t": stamp, "elapsed_s": tick * 10, "accepted": accepted, "rejected": rejected, "connect_errors": connect_errors}) + "\n")
    if no_verification:
        return
    # the generator counted 300 per tick; the ack log holds `acknowledged` (1000 by default is far fewer: the tolerance check needs them to agree)
    counted = minutes * 6 * 300
    verification = {
        "acknowledged": counted if acknowledged == 1000 else acknowledged, "delivered_unique_of_acknowledged": (counted if acknowledged == 1000 else acknowledged) - lost,
        "lost_count": lost, "lost_sample": list(range(lost)),
        "duplicates": duplicates, "duplicates_checked": duplicates, "duplicates_flagged": duplicates - unflagged, "duplicates_unflagged": unflagged,
        "duplicates_unflagged_sample": list(range(unflagged)), "duplicates_verifiable": history != "statsonly",
        "sink_dropped_acks": dropped, "singles_checked": 1000, "singles_flagged": singles_flagged, "load_exit_code": load_exit_code,
        "drain": {"drained": depth == 0, "depth": depth, "deferred": 0, "seconds": 12, "limit_seconds": 900},
        "shutdown": {"exit_code": shutdown_code, "seconds": 3.0}, "host_log": {"critical": 0, "errors": 0, "lines": 100}, "unexpected_exits": unexpected_exits,
    }
    if dup_error:
        verification["duplicates_unflagged"] = None
        verification["duplicates_error"] = dup_error
    with open(os.path.join(directory, "verification.json"), "w") as handle:
        json.dump(verification, handle)


def self_test():
    thresholds = {k: v[0] for k, v in THRESHOLDS.items()}
    # (title, synthetic run arguments, expected verdict, a criterion that must be among the FAILs or None, a criterion that must have this status)
    cases = [
        ("a clean run passes", {}, "PASS", None, None),
        ("a lost message fails", {"lost": 2}, "FAIL", "no acknowledged message lost", None),
        ("an unflagged duplicate fails", {"unflagged": 1}, "FAIL", "no unflagged duplicate", None),
        ("a duplicate lookup that errored fails", {"dup_error": "HTTP 500"}, "FAIL", "no unflagged duplicate", None),
        ("a queue that does not drain fails", {"depth": 40}, "FAIL", "queue drains to zero after load stops", None),
        ("a leaking process (RSS +2 MB/min) fails", {"rss_slope": 2.0}, "FAIL", "RSS flat after warm-up", None),
        ("a file descriptor leak fails", {"fd_slope": 0.5}, "FAIL", "file descriptors flat", None),
        ("errors outside crash windows fail", {"errors": 40}, "FAIL", "error rate", None),
        ("StatsOnly skips the duplicate flag check", {"history": "statsonly"}, "PASS", None, ("no unflagged duplicate", "SKIP")),
        ("acknowledged crash checks that stayed undelivered fail", {"crash_stalled": 3}, "FAIL", "crash drills recover", None),
        ("a server that did not come back fails", {"crash_failed": True}, "FAIL", "crash drills recover", None),
        ("a failed backup drill fails", {"backup_ok": False}, "FAIL", "backup and restore drills", None),
        ("a server exit that no drill caused fails", {"unexpected_exits": 1}, "FAIL", "server stayed up between drills", None),
        ("a non-zero exit after SIGTERM fails", {"shutdown_code": 137}, "FAIL", "graceful shutdown", None),
        ("a missing verification.json fails", {"no_verification": True}, "FAIL", "no acknowledged message lost", None),
        ("an empty ack log fails", {"acknowledged": 0}, "FAIL", "ack log complete", None),
        ("an ack log far shorter than the generator's count fails", {"acknowledged": 5000}, "FAIL", "ack log complete", None),
        ("a harness error in a drill loop fails", {"drill_error": True}, "FAIL", "harness errors", None),
        ("a crash drill that never ran fails", {"no_crash_drill": True}, "FAIL", "crash drills ran as often as promised", None),
        ("a sampler that wrote a third of its rows fails", {"row_every": 3}, "FAIL", "sampler kept up", None),
        ("dropped replies without any duplicate fail", {"duplicates": 0, "dropped": 4}, "FAIL", "duplicate path exercised", None),
        ("once-received messages flagged on a large scale fail", {"singles_flagged": 200}, "FAIL", "possible_duplicate is not sprayed", None),
        ("a few flagged once-received messages after one kill pass", {"singles_flagged": 3}, "PASS", None, ("possible_duplicate is not sprayed", "PASS")),
        ("a non-zero generator exit fails", {"load_exit_code": 1}, "FAIL", "load generator exit code", None),
    ]
    failures = 0
    for title, kwargs, expected, culprit, wanted in cases:
        with tempfile.TemporaryDirectory() as directory:
            synthetic_run(directory, **kwargs)
            result = evaluate(directory, dict(thresholds))
            names = [c["name"] for c in result["criteria"] if c["status"] == "FAIL"]
            ok = result["verdict"] == expected and (culprit is None or culprit in names)
            if wanted:
                ok = ok and any(c["name"] == wanted[0] and c["status"] == wanted[1] for c in result["criteria"])
            if title.startswith("a clean"):
                ok = ok and not names and all(c["status"] == "PASS" for c in result["criteria"] if c["name"] != "RSS growth in every process generation" or True)
            summary_markdown(directory, result)      # must not raise
            print("%-4s %s (verdict %s%s)" % ("ok" if ok else "FAIL", title, result["verdict"], ", failed: " + ", ".join(names) if names else ""))
            failures += 0 if ok else 1
    # a run too short for a trend: SKIP normally, FAIL when strict
    for strict, expected in ((False, "PASS"), (True, "FAIL")):
        short = tempfile.mkdtemp()
        synthetic_run(short, minutes=12, strict=strict, no_crash_drill=True)
        os.remove(os.path.join(short, "events.jsonl"))       # no drills expected in 12 minutes at 40 minute intervals: drop the fixture's drill events
        with open(os.path.join(short, "config.json")) as handle:
            config = json.load(handle)
        config["crash_interval_min"] = config["backup_interval_min"] = 0
        with open(os.path.join(short, "config.json"), "w") as handle:
            json.dump(config, handle)
        result = evaluate(short, dict(thresholds))
        trend = {c["name"]: c["status"] for c in result["criteria"] if c["name"] in TREND_CRITERIA}
        ok = result["verdict"] == expected and set(trend.values()) == {"SKIP" if not strict else "FAIL"}
        print("%-4s a 12 minute run reports its trend criteria as %s when strict=%s (verdict %s)" % ("ok" if ok else "FAIL", "FAIL" if strict else "SKIP", strict, result["verdict"]))
        failures += 0 if ok else 1
        for name in os.listdir(short):
            os.remove(os.path.join(short, name))
        os.rmdir(short)
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_dir", nargs="?")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--strict", action="store_true", help="a trend that cannot be judged (a run too short) is a FAIL; automatic in soak.py from one hour of load")
    for name, (default, meaning) in THRESHOLDS.items():
        parser.add_argument("--" + name.replace("_", "-"), type=float, default=default, help="%s (default %s)" % (meaning, default))
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.run_dir:
        parser.error("a run directory is required")
    thresholds = {name: getattr(args, name) for name in THRESHOLDS}
    result = evaluate(args.run_dir, thresholds, strict=True if args.strict else None)
    with open(os.path.join(args.run_dir, "verdict.json"), "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    summary = summary_markdown(args.run_dir, result)
    with open(os.path.join(args.run_dir, "summary.md"), "w", encoding="utf-8") as handle:
        handle.write(summary)
    print(summary)
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
