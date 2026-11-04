#!/usr/bin/env python3
"""Read a PVE task through the existing, human-approved FULL SSH wrapper."""
import argparse
import json
import math
import os
import re
import shlex
import subprocess
import time


def positive_seconds(value):
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return result


UPID_PATTERN = re.compile(
    r"UPID:([A-Za-z0-9][A-Za-z0-9.-]*):[0-9A-Fa-f]+:[0-9A-Fa-f]+:"
    r"[0-9A-Fa-f]+:[A-Za-z0-9_-]+:[A-Za-z0-9_.-]*:[A-Za-z0-9_.@!-]+:"
)


def wait_task(upid, read_status, *, timeout=600, interval=3, clock=time.monotonic, sleep=time.sleep):
    match = UPID_PATTERN.fullmatch(upid)
    if not match or timeout <= 0 or interval <= 0:
        raise ValueError("invalid UPID or polling bounds")
    deadline = clock() + timeout
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            return 2, {"upid": upid, "status": "timeout"}
        state = read_status(match[1], upid, remaining)
        if state.get("status") == "stopped":
            exitstatus = state.get("exitstatus")
            if not isinstance(exitstatus, str) or not exitstatus:
                raise ValueError("missing task exitstatus")
            return (0 if exitstatus == "OK" else 1), {
                "upid": upid, "status": "stopped", "exitstatus": exitstatus,
            }
        if state.get("status") != "running":
            raise ValueError("unexpected task status")
        sleep(min(interval, max(0, deadline - clock())))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("upid", help="exact UPID returned by the original operation")
    parser.add_argument("--timeout", type=positive_seconds, default=600)
    parser.add_argument("--interval", type=positive_seconds, default=3)
    args = parser.parse_args(argv)

    def read_status(node, upid, remaining):
        command = shlex.join([
            "pvesh", "get", f"/nodes/{node}/tasks/{upid}/status", "--output-format", "json",
        ])
        result = subprocess.run(
            ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "--",
             f"{user}@{host}", f"host-exec -- {command}"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=min(15, remaining),
        )
        if result.returncode:
            raise ValueError("task inspection refused or unavailable")
        state = json.loads(result.stdout)
        if not isinstance(state, dict):
            raise ValueError("invalid task response")
        return state

    try:
        host = os.environ.get("PROXMOX_HOST", "")
        user = os.environ.get("PROXMOX_SSH_USER", "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", host):
            raise ValueError("invalid SSH destination")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", user):
            raise ValueError("invalid SSH user")
        code, result = wait_task(args.upid, read_status, timeout=args.timeout, interval=args.interval)
    except subprocess.TimeoutExpired:
        # A timed-out inspection says nothing about whether the PVE task stopped.
        code, result = 2, {"upid": args.upid, "status": "timeout"}
    except (ValueError, OSError):
        code, result = 3, {"upid": args.upid, "status": "inspection-error"}
    print(json.dumps(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
