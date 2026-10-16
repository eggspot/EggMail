#!/usr/bin/env python3
"""Turns the inputs of the `soak` workflow into the arguments of soak.py, validates them, and checks the workflow files for the traps that broke the
first dispatch from `main` (`soak.py: error: argument --sync: invalid choice: 'false'`).

The trap: GitHub parses a workflow file as YAML 1.1, where an unquoted `off` is the boolean false. `default: off` and `options: [off, normal, full]` therefore
reached the job as the string 'false', and a push-triggered proof run (which never reads the declared defaults) could not see it. Rules this script enforces:

  * the workflow does not map inputs with `${{ inputs.x || 'default' }}` (a falsy value, a boolean false or even the number 0, silently becomes the default);
    it passes the whole input set as JSON (`toJSON(inputs)`) and the defaults are applied here, once, where they can be tested;
  * every input is validated here with a message that names the input and the allowed values;
  * `--self-test` (run by `ci`, no network, no .NET) reads the workflow files, applies YAML 1.1 to every unquoted default and option, feeds the defaults and a
    minimal dispatch (`-f hours=0.33 -f backend=sqlite`) and the schedule (no inputs) through the same code, and has soak.py's own argument parser accept the result.

In the workflow:  python3 bench/soak/plan.py --github     (reads INPUTS_JSON, writes soak-args.txt and the step outputs)

Python 3 standard library only (3.9 or newer).
"""
import json
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

# One place for the defaults. soak.yml declares the same values (the self-test compares them), so a dispatch that gives no -f inputs and a scheduled run
# (which has no inputs at all) behave the same.
DEFAULTS = {
    "hours": "2", "backend": "sqlite", "history": "full", "sync": "off", "rate": "30", "size_mix": "1024:55,8192:30,65536:12,524288:3", "connections": "8",
    "crash_interval_min": "20", "backup_interval_min": "30", "quiet_tail": "0.25", "sample_interval_s": "60", "claim_lease_min": "0",
}
CHOICES = {"backend": ("sqlite", "postgres", "both"), "history": ("full", "statsonly"), "sync": ("off", "normal", "full")}
# (minimum, maximum) of the numeric inputs
RANGES = {
    "hours": (0.01, 5.5), "rate": (0.1, 2000), "connections": (1, 200), "crash_interval_min": (0, 1440), "backup_interval_min": (0, 1440),
    "quiet_tail": (0, 0.9), "sample_interval_s": (1, 3600), "claim_lease_min": (0, 1440),
}
# A hosted job is limited to 360 minutes. Per run: 8 minutes of checkout, publish, start-up and shutdown, and a drain of at least 5.
JOB_BUDGET_MINUTES = 340
OVERHEAD_PER_RUN_MINUTES = 8 + 5


class PlanError(ValueError):
    pass


def normalise(inputs):
    """Raw workflow inputs (a dict of what GitHub passes, or None for a scheduled run) -> a dict of validated strings with the defaults filled in."""
    inputs = inputs or {}
    unknown = sorted(set(inputs) - set(DEFAULTS))
    if unknown:
        raise PlanError("unknown input(s) %s; the soak workflow takes %s" % (", ".join(unknown), ", ".join(sorted(DEFAULTS))))
    values = {}
    for name, default in DEFAULTS.items():
        raw = inputs.get(name)
        if raw is None or (isinstance(raw, str) and raw.strip() == ""):
            values[name] = default      # not given: the declared default. An explicit 0 or false is a value, not "not given"
            continue
        if isinstance(raw, bool):
            raise PlanError("input '%s' arrived as the boolean %s; the workflow file must quote 'off' and 'on' (YAML 1.1 reads them as booleans)" % (name, str(raw).lower()))
        values[name] = str(raw).strip()
    for name, allowed in CHOICES.items():
        if values[name] not in allowed:
            hint = " (an unquoted `off` in a workflow file is the boolean false)" if values[name] in ("false", "true") else ""
            raise PlanError("input '%s' is '%s', allowed: %s%s" % (name, values[name], ", ".join(allowed), hint))
    for name, (low, high) in RANGES.items():
        try:
            number = float(values[name])
        except ValueError:
            raise PlanError("input '%s' is '%s', which is not a number" % (name, values[name]))
        if not math.isfinite(number) or not low <= number <= high:
            raise PlanError("input '%s' is '%s', allowed: a number from %g to %g" % (name, values[name], low, high))
    if not re.fullmatch(r"\d+:\d+(,\d+:\d+)*", values["size_mix"]) or any(int(part.split(":")[0]) < 200 for part in values["size_mix"].split(",")):
        raise PlanError("input 'size_mix' is '%s', expected bytes:weight pairs such as 1024:55,8192:30 with every size at least 200 bytes" % values["size_mix"])
    return values


def make_plan(values):
    """Validated inputs -> {'backends': [...], 'common': [soak.py arguments shared by the runs], 'minutes': planned job time}."""
    backends = ["sqlite", "postgres"] if values["backend"] == "both" else [values["backend"]]
    hours = float(values["hours"])
    minutes = len(backends) * (hours * 60 + OVERHEAD_PER_RUN_MINUTES)
    if minutes > JOB_BUDGET_MINUTES:
        raise PlanError("%d run(s) of %.2f h of load need about %.0f minutes with start-up and drain, more than the %d a 6 hour hosted job leaves. Lower hours, "
                        "dispatch the backends separately, or use a self-hosted runner (docs/soak.md)" % (len(backends), hours, minutes, JOB_BUDGET_MINUTES))
    # soak.py turns --strict on by itself from one hour of load; saying so here keeps the workflow explicit. Under an hour the trend criteria cannot be judged
    # with the default sample interval, and a short proof dispatch (-f hours=0.33) should report them as skipped, not fail on that.
    common = (["--strict"] if hours >= 1 else []) + ["--hours", values["hours"], "--history", values["history"], "--sync", values["sync"], "--rate", values["rate"],
              "--size-mix", values["size_mix"], "--connections", values["connections"], "--crash-interval-min", values["crash_interval_min"],
              "--backup-interval-min", values["backup_interval_min"], "--quiet-tail", values["quiet_tail"], "--sample-interval-s", values["sample_interval_s"],
              "--claim-lease-min", values["claim_lease_min"], "--pg-mode", "docker"]
    return {"backends": backends, "common": common, "minutes": minutes, "load_minutes": hours * 60}


# --------------------------------------------------------------------------- the workflow files

YAML11_WORDS = {"y", "n", "yes", "no", "true", "false", "on", "off", "null", "~"}


def input_blocks(text):
    """name -> {'type': ..., 'default': (raw token or None), 'options': [raw tokens]} for the workflow_dispatch inputs of a workflow file (a line scanner
    that understands exactly the layout these files use: it is not a YAML parser)."""
    blocks = {}
    in_inputs = False
    current = None
    for line in text.splitlines():
        if re.match(r"^    inputs:\s*$", line):
            in_inputs, current = True, None
            continue
        if in_inputs and re.match(r"^  \S", line) or in_inputs and re.match(r"^\S", line):
            in_inputs = False
        if not in_inputs:
            continue
        m = re.match(r"^      (\w+):\s*$", line)
        if m:
            current = blocks.setdefault(m.group(1), {"type": "string", "default": None, "options": []})
            continue
        if current is None:
            continue
        m = re.match(r"^        type:\s*(\S+)", line)
        if m:
            current["type"] = m.group(1)
        m = re.match(r"^        default:\s*(.*?)\s*(#.*)?$", line)
        if m:
            current["default"] = m.group(1)
        m = re.match(r"^        options:\s*\[(.*)\]\s*$", line)
        if m:
            current["options"] = [t.strip() for t in m.group(1).split(",")]
    return blocks


def yaml11_scalar(token):
    """What GitHub's YAML 1.1 reader makes of a scalar written in a workflow file, as the string the job sees."""
    if token is None:
        return None
    if token[:1] in "'\"":
        return token[1:-1]
    low = token.lower()
    if low in ("true", "on", "yes", "y"):
        return "true"
    if low in ("false", "off", "no", "n"):
        return "false"
    if low in ("null", "~"):
        return ""
    return token


def check_workflow(path, expect_defaults=None):
    """Problems in one workflow file, as a list of messages."""
    problems = []
    text = open(path, encoding="utf-8").read()
    blocks = input_blocks(text)
    name = os.path.basename(path)
    if not blocks:
        problems.append("%s: no workflow_dispatch inputs found (the scanner understands the layout of these files)" % name)
    for input_name, block in blocks.items():
        boolean = block["type"] == "boolean"
        tokens = ([("default", block["default"])] if block["default"] is not None else []) + [("option", t) for t in block["options"]]
        for kind, token in tokens:
            if token[:1] in "'\"":
                continue
            if token.lower() in YAML11_WORDS and not (boolean and token in ("true", "false")):
                problems.append("%s: input '%s' has the unquoted %s %s, which YAML 1.1 reads as %s; quote it" % (
                    name, input_name, kind, token, "a boolean" if token.lower() != "null" and token != "~" else "null"))
            elif kind == "default" and not boolean and re.fullmatch(r"[-+]?\d[\d.]*", token):
                problems.append("%s: input '%s' has the unquoted numeric default %s; quote it so it stays the text it is" % (name, input_name, token))
        if block["type"] == "choice" and block["default"] is not None and block["options"]:
            default_text = yaml11_scalar(block["default"])
            options_text = [yaml11_scalar(t) for t in block["options"]]
            if default_text not in options_text:
                problems.append("%s: input '%s' default %s is not among its options %s after YAML 1.1" % (name, input_name, default_text, options_text))
        if not boolean and re.search(r"inputs\.%s\s*\|\|" % re.escape(input_name), text):
            problems.append("%s: `inputs.%s ||` maps a default with an expression; a falsy value (0, an empty string) silently becomes the default" % (name, input_name))
        if boolean and re.search(r"inputs\.%s\s*\|\|" % re.escape(input_name), text):
            problems.append("%s: `inputs.%s ||` on a boolean input turns false into the default" % (name, input_name))
    if expect_defaults is not None:
        for input_name, expected in expect_defaults.items():
            if input_name not in blocks:
                problems.append("%s: input '%s' is missing (plan.py expects it)" % (name, input_name))
            elif yaml11_scalar(blocks[input_name]["default"]) != expected:
                problems.append("%s: input '%s' declares the default %r, plan.py DEFAULTS says %r" % (name, input_name, yaml11_scalar(blocks[input_name]["default"]), expected))
        for input_name in blocks:
            if input_name not in expect_defaults:
                problems.append("%s: input '%s' is not known to plan.py" % (name, input_name))
    return problems, blocks


def self_test():
    failures = []

    def check(ok, title, detail=""):
        print("%-4s %s%s" % ("ok" if ok else "FAIL", title, (" (" + detail + ")") if detail and not ok else ""))
        if not ok:
            failures.append(title)

    import soak                      # soak.py's own parser: the arguments built here must be accepted by it
    parser = soak.build_parser()

    soak_yml = os.path.join(REPO, ".github", "workflows", "soak.yml")
    problems, blocks = check_workflow(soak_yml, DEFAULTS)
    check(not problems, "soak.yml: inputs are safe against YAML 1.1 and match plan.py", "; ".join(problems))
    bench_problems, _ = check_workflow(os.path.join(REPO, ".github", "workflows", "bench-throughput.yml"))
    check(not bench_problems, "bench-throughput.yml: inputs are safe against YAML 1.1", "; ".join(bench_problems))
    text = open(soak_yml, encoding="utf-8").read()
    check("toJSON(inputs)" in text and "plan.py --github" in text, "soak.yml hands all inputs to plan.py as JSON", "the workflow must call plan.py with INPUTS_JSON")

    # What the job really receives for each way of starting the workflow.
    declared = {name: yaml11_scalar(block["default"]) for name, block in blocks.items()}
    minimal = dict(declared, hours="0.33", backend="sqlite")           # gh workflow run soak -f hours=0.33 -f backend=sqlite
    for title, inputs in (("a dispatch with the declared defaults", declared), ("a minimal dispatch (-f hours=0.33 -f backend=sqlite)", minimal),
                          ("a dispatch of both backends", dict(declared, hours="0.33", backend="both")), ("a scheduled run (no inputs)", None),
                          ("an empty input set", {}), ("a drill switched off with an explicit 0", dict(declared, crash_interval_min="0", backup_interval_min="0"))):
        try:
            plan = make_plan(normalise(inputs))
            for backend in plan["backends"]:
                parser.parse_args(plan["common"] + ["--backend", "sqlite" if backend == "sqlite" else "postgres", "--drain-timeout-min", "5", "--out", "x"])
            ok, detail = True, ""
        except (PlanError, SystemExit) as error:
            ok, detail = False, repr(error)
        check(ok, title + " builds arguments soak.py accepts", detail)
    values = normalise(dict(declared, crash_interval_min="0"))
    check(values["crash_interval_min"] == "0", "an explicit 0 is kept, not replaced by the default")
    check(normalise(None) == DEFAULTS, "no inputs gives exactly the defaults")

    # What the job would have received before the fix, and other mistakes: refused, with a message that names the input.
    for title, inputs, expect in (
            ("the boolean the old `default: off` became", dict(declared, sync="false"), "sync"), ("a boolean arriving as a boolean", dict(declared, sync=False), "sync"),
            ("an unknown backend", dict(declared, backend="mysql"), "backend"), ("hours that are not a number", dict(declared, hours="nan"), "hours"),
            ("hours that do not fit one job", dict(declared, hours="5.5", backend="both"), "6 hour"), ("a negative rate", dict(declared, rate="-1"), "rate"),
            ("a size mix that is not a mix", dict(declared, size_mix="big"), "size_mix"), ("an input plan.py does not know", dict(declared, speed="9"), "speed")):
        try:
            make_plan(normalise(inputs))
            check(False, title + " is refused", "it was accepted")
        except PlanError as error:
            check(expect in str(error), title + " is refused with a clear message", str(error))

    # The scanner itself must see the trap, or the checks above prove nothing.
    bad = "on:\n  workflow_dispatch:\n    inputs:\n      sync:\n        type: choice\n        options: [off, normal]\n        default: off\n      rate:\n        default: 30\n"
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "bad.yml")
        with open(path, "w") as handle:
            handle.write(bad + "env:\n  X: ${{ inputs.rate || '30' }}\n")
        found, _ = check_workflow(path)
        check(len(found) >= 3, "the scanner flags an unquoted `off` default and option, an unquoted number and an `||` mapping", "; ".join(found))
    return 1 if failures else 0


def github():
    """Inside the workflow: validate, write soak-args.txt and the step outputs; on a bad input print a clear annotation and exit 2."""
    raw = os.environ.get("INPUTS_JSON", "null")
    try:
        values = normalise(json.loads(raw))
        plan = make_plan(values)
    except (PlanError, ValueError) as error:
        message = str(error)
        print("::error title=soak inputs::%s" % message)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as handle:
                handle.write("## Soak not started\n\nThe inputs were refused before anything ran: %s\n\nInputs received: `%s`\n" % (message, raw.replace("\n", " ")))
        return 2
    with open("soak-args.txt", "w", encoding="utf-8") as handle:
        handle.write("\n".join(plan["common"]) + "\n")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write("backends=%s\n" % " ".join(plan["backends"]))
            handle.write("load_minutes=%d\n" % round(plan["load_minutes"]))
    print("soak plan: backends %s, %.2f h of load each, about %.0f minutes of the %d a job allows" % (" ".join(plan["backends"]), plan["load_minutes"] / 60.0, plan["minutes"], JOB_BUDGET_MINUTES))
    print("arguments: " + " ".join(plan["common"]))
    return 0


def main():
    if "--self-test" in sys.argv:
        return self_test()
    if "--github" in sys.argv:
        return github()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
