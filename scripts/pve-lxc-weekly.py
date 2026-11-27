#!/usr/bin/env python3
"""Local PVE LXC maintenance job. No guest is ever started by this program."""

import argparse
import collections
import datetime as dt
import email.message
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import urllib.parse
import urllib.request
import uuid

SYSTEM = r"""
set -eu
export LC_ALL=C DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
. /etc/os-release
free=$(df -Pk / | awk 'END{print $(NF-2)}')
[ "$free" -ge 262144 ] || { echo PVE_SYSTEM_LOW_DISK; exit 21; }
case "$ID" in
  debian|ubuntu|devuan)
    apt() { apt-get -o DPkg::Lock::Timeout=15 -o Acquire::Retries=2 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 "$@"; }
    apt -o APT::Update::Error-Mode=any update
    [ -z "$(dpkg --audit)" ] || { echo PVE_SYSTEM_DPKG_AUDIT; exit 22; }
    plan=$(apt -s --no-remove upgrade)
    printf '%s\n' "$plan"
    n=$(printf '%s\n' "$plan" | awk '/^[0-9]+ upgraded,/ { print $1 }')
    case "$n" in ''|*[!0-9]*) exit 23 ;; esac
    if [ "$n" -gt 0 ]; then apt -y --no-remove -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade; fi
    [ -z "$(dpkg --audit)" ] || exit 24
    packages=$(printf '%s\n' "$plan" | awk '$1=="Inst" { v=($3 ~ /^\[/ ? $4 : $3); sub(/^\(/,"",v); print $2,v }')
    if [ "$n" -gt 0 ]; then
      printf '%s\n' "$packages" | while read -r p version; do
        [ -n "$p" ] && [ "$(dpkg-query -W -f='${Version}' "$p")" = "$version" ] || exit 26
      done
    fi
    printf 'PVE_SYSTEM_APT %s\n' "$n"
    ;;
  alpine)
    plan=$(apk --no-cache upgrade --simulate 2>&1)
    printf '%s\n' "$plan"
    if printf '%s\n' "$plan" | grep -Eq '^(WARNING|ERROR)|\) Purging |\) Downgrading '; then exit 25; fi
    n=$(printf '%s\n' "$plan" | awk '/^\([0-9]+\/[0-9]+\)/{n++} END{print n+0}')
    if [ "$n" -gt 0 ]; then
      apk --no-cache upgrade
      post=$(apk --no-cache upgrade --simulate 2>&1)
      printf '%s\n' "$post"
      if printf '%s\n' "$post" | grep -Eq '^(WARNING|ERROR|\([0-9]+/[0-9]+\))'; then exit 26; fi
    fi
    printf 'PVE_SYSTEM_APK %s\n' "$n"
    ;;
  *) printf 'PVE_SYSTEM_UNSUPPORTED\n' ;;
esac
"""

GRAFANA = r"""
set -eu
export PHS_SILENT=1 LC_ALL=C TERM=xterm
. /etc/os-release
[ "$ID" = alpine ]
p=$(command -v update)
[ "$p" = /usr/bin/update ] && [ -f "$p" ] && [ ! -L "$p" ]
[ "$(stat -c %u "$p")" = 0 ]
grep -Fxq 'export SCRIPT_SLUG="grafana"' "$p"
grep -Fxq 'export UPDATE_SCRIPT_NAME="grafana"' "$p"
health() {
 h=$(curl -kfsS --max-time 8 https://127.0.0.1:3000/api/health)
 printf '%s\n' "$h" | grep -Eq '"database"[[:space:]]*:[[:space:]]*"ok"'
}
health
before=$(apk info -v | sort)
conf=$(sha256sum /etc/conf.d/grafana)
# Call the installed launcher; never supply menu input or enable bypass flags.
"$p" </dev/null
[ "$conf" = "$(sha256sum /etc/conf.d/grafana)" ]
rc-service grafana status
health
if [ "$before" = "$(apk info -v | sort)" ]; then echo PVE_APP_PACKAGE_CHANGED 0; else echo PVE_APP_PACKAGE_CHANGED 1; fi
"""

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
BLOCK = re.compile(
    r"no update script found|curl: \(22\)|no such device or address|not continuing|requires an interactive|temporarily disabled|has been removed|failed|\bERROR\b",
    re.I,
)
PROBLEM = {"failed", "needs_attention", "timeout"}


def command(args, seconds):
    try:
        r = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=seconds
        )
        return r.returncode, ANSI.sub("", r.stdout.decode(errors="replace"))
    except subprocess.TimeoutExpired as e:
        return 124, ANSI.sub("", (e.stdout or b"").decode(errors="replace"))


def read_config(path):
    s = path.stat()
    if path.is_symlink() or not stat.S_ISREG(s.st_mode) or s.st_mode & 0o077 or s.st_uid != os.geteuid():
        raise ValueError("configuration must be owner-only and not a symlink")
    c = json.loads(path.read_text())
    if any(not isinstance(x, int) or x < 100 for x in c.get("exclude", [])):
        raise ValueError("invalid exclusions")
    apps = c.get("apps", {})
    for i, p in apps.items():
        if not i.isdecimal() or not re.fullmatch(r"[a-zA-Z0-9_.-]+", p["name"]) or p["slug"] != "grafana":
            raise ValueError("unknown application profile")
    return c


def inventory(c, ids):
    rc, out = command(["pct", "list"], 20)
    if rc or not re.match(r"^VMID\s+Status\s+Lock\s+Name\b", out):
        raise RuntimeError("pct list did not return a valid inventory")
    found = {}
    for l in out.splitlines()[1:]:
        if not l.strip():
            continue
        p = l.split()
        if len(p) not in (3, 4) or not p[0].isdecimal() or int(p[0]) in found:
            raise RuntimeError("unexpected pct list row")
        i, status, name = int(p[0]), p[1], p[-1]
        why = (
            "excluded"
            if i in c.get("exclude", [])
            else "stopped"
            if status == "stopped"
            else "not_running"
            if status != "running"
            else "locked"
            if len(p) == 4
            else "eligible"
        )
        found[i] = {"id": i, "name": name, "power": status, "disposition": why}
    if ids and not ids <= found.keys():
        raise ValueError("requested LXC absent from inventory")
    return [x for i, x in sorted(found.items()) if not ids or i in ids]


def phase(guest, name, run, body):
    i = str(guest["id"])
    rc, out = command(["pct", "exec", i, "--", "timeout", "420", "sh", "-c", body], 450)
    (run / (i + "-" + name + ".log")).write_text(out)
    timeout = rc in (124, 137, 143)
    if timeout:
        return {"status": "timeout", "exit": rc}
    if name == "system":
        m = re.findall(r"(?m)^PVE_SYSTEM_(APT|APK) (\d+)\s*$", out)
        if not rc and len(m) == 1:
            return {"status": "updated" if int(m[0][1]) else "current", "method": m[0][0], "packages": int(m[0][1])}
        if not rc and "PVE_SYSTEM_UNSUPPORTED" in out:
            return {"status": "unsupported"}
        return {"status": "failed", "exit": rc}
    if rc:
        return {"status": "needs_attention" if BLOCK.search(out) else "failed", "exit": rc}
    m = re.findall(r"(?m)^PVE_APP_PACKAGE_CHANGED ([01])\s*$", out)
    if BLOCK.search(out) or "Updated successfully" not in out or len(m) != 1:
        return {"status": "needs_attention", "exit": rc}
    return {"status": "updated" if m[0] == "1" else "current"}


def recheck(guest):
    i = str(guest["id"])
    rc, status = command(["pct", "status", i], 12)
    if rc or status.strip() != "status: running":
        return "not_running"
    rc, cfg = command(["pct", "config", i], 12)
    if rc:
        return "config_unavailable"
    if re.search(r"(?m)^lock:", cfg):
        return "locked"
    if re.search(r"(?m)^template:\s*1$", cfg):
        return "template"
    if not re.search(r"(?m)^hostname:\s*" + re.escape(guest["name"]) + r"\s*$", cfg):
        return "identity_changed"
    return "eligible"


def run_guest(g, c, phase_arg, run):
    g.update(system={"status": "not_requested"}, application={"status": "not_requested"})
    if g["disposition"] != "eligible":
        return
    profile = c.get("apps", {}).get(str(g["id"]))
    system = phase_arg in ("all", "system")
    app = phase_arg in ("all", "app")
    if app and not profile:
        g["application"] = {"status": "not_allowlisted"}
    if not system and not profile:
        return
    g["disposition"] = recheck(g)
    if g["disposition"] != "eligible":
        return
    if system:
        g["system"] = phase(g, "system", run, SYSTEM)
    if app and profile:
        if profile["name"] != g["name"]:
            g["application"] = {"status": "needs_attention", "reason": "profile name mismatch"}
        elif system and g["system"]["status"] not in ("current", "updated"):
            g["application"] = {"status": "needs_attention", "reason": "system phase did not pass"}
        elif recheck(g) != "eligible":
            g["application"] = {"status": "needs_attention", "reason": "guest state changed"}
        else:
            g["application"] = phase(g, "application", run, GRAFANA)
    if (
        system
        and c.get("patchmon_report")
        and g["system"]["status"] in ("current", "updated")
        and recheck(g) == "eligible"
    ):
        i = str(g["id"])
        rc, out = command(
            [
                "pct",
                "exec",
                i,
                "--",
                "timeout",
                "45",
                "sh",
                "-c",
                "if [ -x /usr/local/bin/patchmon-agent ]; then /usr/local/bin/patchmon-agent report; fi",
            ],
            65,
        )
        if out:
            (run / (i + "-patchmon.log")).write_text(out)
        if rc:
            g["patchmon"] = {"status": "failed", "exit": rc}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def notify(c, title, body, warning):
    result = {}
    if c.get("gotify"):
        try:
            g = c["gotify"]
            url = g["url"]
            parts = urllib.parse.urlsplit(url)
            if (
                parts.scheme not in ("http", "https")
                or not parts.netloc
                or parts.username
                or parts.query
                or parts.fragment
            ):
                raise ValueError("invalid Gotify endpoint")
            data = json.dumps({"title": title, "message": body, "priority": 8 if warning else 4}).encode()
            rq = urllib.request.Request(
                url, data=data, headers={"Content-Type": "application/json", "X-Gotify-Key": g["token"]}
            )
            with urllib.request.build_opener(NoRedirect).open(rq, timeout=15) as r:
                m = json.load(r)
            result["gotify_id"] = int(m["id"])
        except Exception as e:
            result["gotify_error"] = type(e).__name__
    if warning and c.get("mail_to"):
        try:
            msg = email.message.EmailMessage()
            msg["To"] = c["mail_to"]
            msg["Subject"] = title
            msg.set_content(body)
            p = subprocess.run(["/usr/sbin/sendmail", "-t"], input=msg.as_bytes(), capture_output=True, timeout=20)
            result["mail_exit"] = p.returncode
        except Exception as e:
            result["mail_error"] = type(e).__name__
    return result


def summarize(r):
    states = ("system", "application")
    lines = [f"Run: {r['run_id']}", f"Scope: {r['scope']}", f"Host: {r['host']}", f"State: {r['status']}"]
    lines += [
        "Guests: "
        + ", ".join(f"{k}={v}" for k, v in sorted(collections.Counter(x["disposition"] for x in r["guests"]).items()))
    ]
    for k in states:
        counts = collections.Counter(x[k]["status"] for x in r["guests"] if x["disposition"] == "eligible")
        lines += [k.capitalize() + ": " + (", ".join(f"{a}={b}" for a, b in sorted(counts.items())) or "none")]
    for x in r["guests"]:
        if (
            x["disposition"] == "eligible"
            and x["application"]["status"] not in ("not_requested", "not_allowlisted")
            or any(x[k]["status"] in PROBLEM for k in states)
        ):
            lines += [f"{x['id']} {x['name']}: system={x['system']['status']}; app={x['application']['status']}"]
        if x.get("patchmon", {}).get("status") == "failed":
            lines += [f"{x['id']} {x['name']}: Patchmon report failed"]
    return "\n".join(lines)


def main():
    os.umask(0o077)
    a = argparse.ArgumentParser()
    a.add_argument("--config", type=Path, default=Path("/etc/pve-lxc-weekly.json"))
    a.add_argument("--audit", action="store_true")
    a.add_argument("--only", type=int, action="append")
    a.add_argument("--phase", choices=("all", "system", "app"), default="all")
    a.add_argument("--no-notify", action="store_true")
    args = a.parse_args()
    c = read_config(args.config)
    ids = set(args.only or [])
    if args.audit:
        print(json.dumps({"guests": inventory(c, ids)}, ensure_ascii=False))
        return 0
    state = Path(c.get("state_dir", "/var/log/pve-lxc-weekly"))
    state.mkdir(parents=True, exist_ok=True)
    if state.is_symlink() or state.stat().st_mode & 0o077 or state.stat().st_uid != os.geteuid():
        raise ValueError("unsafe log directory")
    with (state / "maintenance.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        r = {
            "schema": 1,
            "run_id": dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8],
            "host": socket.getfqdn(),
            "scope": "pilot" if ids else "weekly",
            "guests": inventory(c, ids),
        }
        run = state / r["run_id"]
        run.mkdir()
        for g in r["guests"]:
            run_guest(g, c, args.phase, run)
        warning = any(
            any(g[k]["status"] in PROBLEM | {"unsupported"} for k in ("system", "application"))
            or g["disposition"] in ("locked", "identity_changed", "config_unavailable", "not_running")
            or g.get("patchmon", {}).get("status") == "failed"
            for g in r["guests"]
        )
        r["status"] = "WARNING" if warning else "SUCCESS"
        summary = summarize(r)
        report = run / "report.json"
        report.write_text(json.dumps(r, indent=2) + "\n")
        if not args.no_notify:
            r["notification"] = notify(
                c, f"Proxmox LXC update {r['status']} - {r['host']}" + (" [pilote]" if ids else ""), summary, warning
            )
            temp = run / "report.tmp"
            temp.write_text(json.dumps(r, indent=2) + "\n")
            temp.replace(report)
        print(json.dumps(r, ensure_ascii=False))
        return 2 if warning or r.get("notification", {}).get("gotify_error") else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ValueError, OSError) as e:
        print("Maintenance stopped: " + str(e), file=sys.stderr)
        sys.exit(1)
