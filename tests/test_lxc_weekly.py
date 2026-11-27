import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

RUNNER = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "pve-lxc-weekly.py"
FAKE = """#!/bin/sh
printf '%s\\n' "$*" >> "$TEST_TRACE"
case "$1 $2" in
 'list ') printf 'VMID Status Lock Name\\n210 running grafana\\n211 running fileserver\\n212 stopped offline-lxc\\n213 running retired-lxc\\n';;
 'status 210'|'status 211') printf 'status: running\\n';;
 'config 210') printf 'hostname: grafana\\n';;
 'config 211') printf 'hostname: fileserver\\n';;
 'exec 210') case "${TEST_RESPONSE:-ok}" in ok) printf 'Updated successfully!\\nPVE_APP_PACKAGE_CHANGED 0\\n';; missing) printf 'No update script found\\n';; failed) exit 2;; esac;;
 *) exit 77;;
esac
"""


class Weekly(unittest.TestCase):
    def run_case(self, args, response="ok"):
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            fake = d / "pct"
            fake.write_text(FAKE)
            fake.chmod(0o755)
            cfg = d / "config.json"
            cfg.write_text(
                json.dumps(
                    {
                        "exclude": [213],
                        "apps": {"210": {"name": "grafana", "slug": "grafana"}},
                        "state_dir": str(d / "state"),
                    }
                )
            )
            cfg.chmod(0o600)
            trace = d / "trace"
            env = {
                **os.environ,
                "PATH": str(d) + ":" + os.environ["PATH"],
                "TEST_TRACE": str(trace),
                "TEST_RESPONSE": response,
            }
            p = subprocess.run(
                [sys.executable, str(RUNNER), "--config", str(cfg), *args], capture_output=True, text=True, env=env
            )
            if not p.stdout.strip():
                self.fail(p.stderr)
            return p.returncode, json.loads(p.stdout), trace.read_text().splitlines()

    def test_read_only_inventory_never_execs_or_starts_guests(self):
        rc, r, t = self.run_case(["--audit"])
        self.assertEqual(rc, 0)
        self.assertEqual(t, ["list"])
        self.assertEqual(
            {x["id"]: x["disposition"] for x in r["guests"]},
            {210: "eligible", 211: "eligible", 212: "stopped", 213: "excluded"},
        )

    def test_pilot_runs_allowlisted_app_only_and_noop_is_reported(self):
        rc, r, t = self.run_case(["--only", "210", "--phase", "app", "--no-notify"])
        self.assertEqual(rc, 0)
        self.assertEqual(r["guests"][0]["application"]["status"], "current")
        self.assertEqual(r["guests"][0]["system"]["status"], "not_requested")
        self.assertEqual(len([x for x in t if x.startswith("exec ")]), 1)

    def test_missing_script_zero_exit_does_not_pass(self):
        rc, r, _ = self.run_case(["--only", "210", "--phase", "app", "--no-notify"], "missing")
        self.assertNotEqual(rc, 0)
        self.assertEqual(r["guests"][0]["application"]["status"], "needs_attention")

    def test_guest_outside_app_allowlist_not_executed(self):
        rc, r, t = self.run_case(["--only", "211", "--phase", "app", "--no-notify"])
        self.assertEqual(rc, 0)
        self.assertEqual(r["guests"][0]["application"]["status"], "not_allowlisted")
        self.assertFalse(any(x.startswith("exec ") for x in t))


if __name__ == "__main__":
    unittest.main()
