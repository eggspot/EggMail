#!/usr/bin/env python3
"""Cold-start time of a published `mta` build: seconds from spawning `mta serve` until GET /healthz answers 200.

  python3 bench/measure-startup.py <publish directory> [--runs 7] [--label TEXT]

Two cases per build, median of --runs each:
  first start  a fresh, empty data directory (creates the SQLite schema, the key ring and the self-signed certificate)
  restart      the same data directory again (what a container restart costs)
It also prints the size of the publish directory. Used to decide ReadyToRun (docs/decisions.md): run it on the SAME machine for a JIT
and a ReadyToRun publish, one after the other, and compare the medians. Python 3 standard library only.
"""
import argparse
import json
import os
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def directory_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            total += os.path.getsize(os.path.join(root, name))
    return total


def start_and_wait(binary, data_dir):
    port = free_port()
    env = dict(os.environ)
    env.update({
        "Sqlite__DataDirectory": data_dir,
        "Dashboard__HttpPort": str(port),
        "Dashboard__HttpsPort": str(free_port()),
        "Dashboard__BindAddress": "127.0.0.1",
        "Backup__Enabled": "false",
        "Smtp__Listeners__submission__Port": str(free_port()),
        "Smtp__Listeners__submissions__Port": str(free_port()),
        "Smtp__Listeners__alternate__Port": str(free_port()),
        "Smtp__Listeners__bounce__Port": str(free_port()),
        "Smtp__Listeners__submission__BindAddress": "127.0.0.1",
        "Smtp__Listeners__submissions__BindAddress": "127.0.0.1",
        "Smtp__Listeners__alternate__BindAddress": "127.0.0.1",
        "Smtp__Listeners__bounce__BindAddress": "127.0.0.1",
    })
    started = time.perf_counter()
    process = subprocess.Popen([binary, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = started + 60
        while time.perf_counter() < deadline:
            if process.poll() is not None:
                raise RuntimeError("mta exited with code %s during start-up" % process.returncode)
            try:
                with urllib.request.urlopen("http://127.0.0.1:%d/healthz" % port, timeout=1) as response:
                    if response.status == 200:
                        return time.perf_counter() - started
            except OSError:
                time.sleep(0.01)
        raise RuntimeError("no healthy answer within 60 s")
    finally:
        process.terminate()
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("publish_dir")
    parser.add_argument("--runs", type=int, default=7)
    parser.add_argument("--label", default="")
    args = parser.parse_args()
    binary = os.path.join(args.publish_dir, "mta")
    if not os.path.exists(binary):
        sys.exit("no mta apphost in " + args.publish_dir)

    first, restart = [], []
    for _ in range(args.runs):
        data = tempfile.mkdtemp(prefix="eggmail-startup-")
        try:
            first.append(start_and_wait(binary, data))
            restart.append(start_and_wait(binary, data))
        finally:
            shutil.rmtree(data, ignore_errors=True)
    result = {
        "label": args.label,
        "publishSizeMiB": round(directory_size(args.publish_dir) / 1048576, 1),
        "runs": args.runs,
        "firstStartSecondsMedian": round(statistics.median(first), 3),
        "firstStartSecondsMin": round(min(first), 3),
        "restartSecondsMedian": round(statistics.median(restart), 3),
        "restartSecondsMin": round(min(restart), 3),
    }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
