import fcntl
import json
import os
import pathlib
import runpy
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from typing import Any

RUNNER = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "pve-lxc-weekly.py"
FAKE = """#!/bin/sh
printf '%s\\n' "$*" >> "$TEST_TRACE"
case "$1 $2" in
 'list ') printf 'VMID Status Lock Name\\n210 running grafana\\n211 running fileserver\\n212 stopped offline-lxc\\n213 running retired-lxc\\n';;
 'status 210'|'status 211') printf 'status: %s\\n' "${TEST_POWER:-running}";;
 'config 210') printf 'hostname: %s\\n' "${TEST_NAME:-grafana}"; if [ "${TEST_LOCK:-0}" = 1 ]; then printf 'lock: backup\\n'; fi;;
 'config 211') printf 'hostname: fileserver\\n';;
 'exec 210')
  case "$*" in
   *PVE_SYSTEM_APT*) case "${TEST_SYSTEM:-apt}" in
    apt) printf 'PVE_SYSTEM_APT 3\\n';; apk) printf 'PVE_SYSTEM_APK 0\\n';;
    unsupported) printf 'PVE_SYSTEM_UNSUPPORTED\\n';; *) exit "$TEST_SYSTEM";; esac;;
   *) printf 'health_scheme=%s\\n' "$8" >> "$TEST_TRACE"
      case "${TEST_RESPONSE:-ok}" in ok) printf 'Updated successfully!\\nPVE_APP_PACKAGE_CHANGED 0\\n';; missing) printf 'No update script found\\n';; health) printf 'PVE_APP_HEALTH_PRECHECK_FAILED\\n'; exit 28;; failed) exit 2;; esac;;
  esac;;
 *) exit 77;;
esac
"""


class Weekly(unittest.TestCase):
    def run_case(
        self, args, response="ok", settings=None, *, hold_lock=False, extra_env=None
    ) -> tuple[int, Any, list[str]]:
        with ExitStack() as stack:
            d = pathlib.Path(stack.enter_context(tempfile.TemporaryDirectory()))
            if hold_lock:
                (d / "state").mkdir(mode=0o700)
                lock = stack.enter_context((d / "state" / "maintenance.lock").open("a"))
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
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
                        **(settings or {}),
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
                **(extra_env or {}),
            }
            p = subprocess.run(
                [sys.executable, str(RUNNER), "--config", str(cfg), *args], capture_output=True, text=True, env=env
            )
            return (
                p.returncode,
                json.loads(p.stdout) if p.stdout.strip() else p.stderr,
                trace.read_text().splitlines() if trace.exists() else [],
            )

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
        self.assertIn("health_scheme=http", t)

    def test_grafana_https_opt_in_and_health_failure_reason(self):
        config = {"apps": {"210": {"name": "grafana", "slug": "grafana", "health_scheme": "https"}}}
        rc, report, trace = self.run_case(["--only", "210", "--phase", "app"], "health", config)
        self.assertEqual(rc, 2)
        self.assertIn("health_scheme=https", trace)
        self.assertEqual(report["guests"][0]["application"]["reason"], "grafana pre-update health check failed")

    def test_missing_script_zero_exit_does_not_pass(self):
        rc, r, _ = self.run_case(["--only", "210", "--phase", "app", "--no-notify"], "missing")
        self.assertNotEqual(rc, 0)
        self.assertEqual(r["guests"][0]["application"]["status"], "needs_attention")

    def test_guest_outside_app_allowlist_not_executed(self):
        rc, r, t = self.run_case(["--only", "211", "--phase", "app", "--no-notify"])
        self.assertEqual(rc, 0)
        self.assertEqual(r["guests"][0]["application"]["status"], "not_allowlisted")
        self.assertFalse(any(x.startswith("exec ") for x in t))

    def test_system_outcomes_and_no_transaction_timeout(self):
        for mode, status, rc in [
            ("apt", "updated", 0),
            ("apk", "current", 0),
            ("unsupported", "unsupported", 2),
            ("22", "failed", 2),
            ("124", "timeout", 2),
            ("137", "failed", 2),
            ("143", "failed", 2),
        ]:
            with self.subTest(mode=mode):
                actual, report, trace = self.run_case(
                    ["--only", "210", "--phase", "system"], extra_env={"TEST_SYSTEM": mode}
                )
                self.assertEqual(actual, rc)
                result = report["guests"][0]["system"]
                self.assertEqual(result["status"], status)
                if mode in ("apt", "apk"):
                    self.assertEqual(result["method"], mode.upper())
                    self.assertEqual(result["packages"], 3 if mode == "apt" else 0)
                execution = [t.split()[:5] for t in trace if t.startswith("exec ")]
                self.assertEqual(execution, [["exec", "210", "--", "sh", "-c"]])

    def test_revalidation_stops_changed_guest(self):
        for env, status in [
            ({"TEST_LOCK": "1"}, "locked"),
            ({"TEST_NAME": "new-host"}, "identity_changed"),
            ({"TEST_POWER": "stopped"}, "not_running"),
        ]:
            rc, report, trace = self.run_case(["--only", "210"], extra_env=env)
            self.assertEqual(rc, 2)
            self.assertEqual(report["guests"][0]["disposition"], status)
            self.assertFalse(any(x.startswith("exec ") for x in trace))

    def test_app_never_runs_when_system_failed(self):
        rc, report, trace = self.run_case(["--only", "210"], extra_env={"TEST_SYSTEM": "22"})
        self.assertEqual(rc, 2)
        self.assertEqual(report["guests"][0]["application"]["status"], "needs_attention")
        self.assertEqual(sum(x.startswith("exec ") for x in trace), 1)

    def test_invalid_config_is_rejected_before_guest_access(self):
        for cfg in (
            {"exclude": True},
            {"apps": []},
            {"apps": {"210": {"slug": "grafana"}}},
            {"state_dir": "relative"},
            {"mail_to": ["invalid"]},
            {"gotify": {"url": "http://gotify.example/message", "token": "dummy"}},
            {"apps": {"210": {"name": "grafana", "slug": "grafana", "health_scheme": "ftp"}}},
        ):
            with self.subTest(cfg=cfg):
                rc, error, trace = self.run_case(["--audit"], settings=cfg)
                self.assertEqual(rc, 1)
                self.assertTrue(error.startswith("Maintenance stopped:"), error)
                self.assertEqual(trace, [])

    def test_lock_conflict_stops_before_inventory(self):
        rc, error, trace = self.run_case([], hold_lock=True)
        self.assertEqual(rc, 1)
        self.assertIn("another maintenance run is in progress", error)
        self.assertEqual(trace, [])

    def test_legacy_apt_warning_stops_before_upgrade(self):
        body = runpy.run_path(str(RUNNER))["SYSTEM"].replace(". /etc/os-release", "ID=debian")
        with tempfile.TemporaryDirectory() as temp:
            apt = pathlib.Path(temp) / "apt-get"
            apt.write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_TRACE"\n'
                'printf "W: Some index files failed to download.\\n"\nexit 0\n'
            )
            apt.chmod(0o755)
            df = pathlib.Path(temp) / "df"
            df.write_text("#!/bin/sh\nprintf 'fs 999999 0 999999 0%% /\\n'\n")
            df.chmod(0o755)
            trace = pathlib.Path(temp) / "trace"
            env = {**os.environ, "TEST_TRACE": str(trace), "PATH": temp + ":" + os.environ["PATH"]}
            result = subprocess.run(["sh", "-c", body], capture_output=True, text=True, env=env, timeout=5)
            self.assertEqual(result.returncode, 27, result.stdout + result.stderr)
            calls = trace.read_text().splitlines()
            self.assertEqual(len(calls), 1)
            self.assertTrue(calls[0].endswith(" update"))


if __name__ == "__main__":
    unittest.main()
