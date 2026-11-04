"""Local task polling; never contacts PVE in tests."""
import importlib.util
import json
import subprocess

import pytest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "task_wait", Path(__file__).resolve().parents[1] / "scripts/proxmox-task-wait.py"
)


def load():
    module = importlib.util.module_from_spec(SPEC)
    assert SPEC is not None and SPEC.loader is not None
    SPEC.loader.exec_module(module)
    return module


UPID = "UPID:pve:00000001:00000002:00000003:qmclone:900:agent@pve:"


def test_running_then_success():
    module = load()
    replies = iter([{"status": "running"}, {"status": "stopped", "exitstatus": "OK"}])
    now = [0.0]
    calls = []

    def read(node, upid, remaining):
        calls.append((node, upid))
        return next(replies)

    def sleep(seconds):
        now[0] += seconds

    code, result = module.wait_task(UPID, read, timeout=10, interval=1,
                                    clock=lambda: now[0], sleep=sleep)
    assert code == 0
    assert result == {"upid": UPID, "status": "stopped", "exitstatus": "OK"}
    assert calls == [("pve", UPID), ("pve", UPID)]


@pytest.mark.parametrize("reply,code", [
    ({"status": "stopped", "exitstatus": "disk full"}, 1),
    ({"status": "running"}, 2),
])
def test_failure_and_timeout_keep_upid(reply, code):
    module = load()
    now = [0]

    def sleep(seconds):
        now[0] += seconds

    rc, result = module.wait_task(UPID, lambda *args: reply, timeout=2, interval=1,
                                 clock=lambda: now[0], sleep=sleep)
    assert rc == code
    assert result["upid"] == UPID


@pytest.mark.parametrize("upid", ["null", UPID + ";id", UPID.replace("pve:", "../pve:", 1)])
def test_invalid_id_never_reads(upid):
    def forbidden(*args):
        pytest.fail("invalid UPID must not reach transport")
    with pytest.raises(ValueError):
        load().wait_task(upid, forbidden)


@pytest.mark.parametrize("reply", [{}, {"status": "stopped"}, {"status": "unknown"}])
def test_malformed_state_is_not_success(reply):
    with pytest.raises(ValueError):
        load().wait_task(UPID, lambda *args: reply)


def test_cli_uses_only_approved_wrapper(monkeypatch, capsys):
    module = load()
    monkeypatch.setenv("PROXMOX_HOST", "pve.example")
    monkeypatch.setenv("PROXMOX_SSH_USER", "agent")
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, '{"status":"stopped","exitstatus":"OK"}', "")

    monkeypatch.setattr(subprocess, "run", run)
    assert module.main([UPID, "--timeout", "10"]) == 0
    assert json.loads(capsys.readouterr().out)["upid"] == UPID
    argv, kwargs = calls[0]
    assert argv[:2] == ["ssh", "-T"]
    assert argv[-2] == "agent@pve.example"
    assert argv[-1].startswith("host-exec -- pvesh get /nodes/pve/tasks/")
    assert "--output-format json" in argv[-1]
    assert 0 < kwargs["timeout"] <= 10
    assert kwargs.get("shell", False) is False


@pytest.mark.parametrize("failure", [
    subprocess.CompletedProcess([], 1, "", "sensitive broker error"),
    subprocess.CompletedProcess([], 0, "not json", ""),
    subprocess.CompletedProcess([], 0, '[]', ""),
    OSError("sensitive details"),
    subprocess.TimeoutExpired("ssh", 1),
])
def test_cli_transport_errors_are_not_task_failure(monkeypatch, capsys, failure):
    module = load()
    monkeypatch.setenv("PROXMOX_HOST", "pve.example")
    monkeypatch.setenv("PROXMOX_SSH_USER", "agent")

    def run(*args, **kwargs):
        if isinstance(failure, Exception):
            raise failure
        return failure

    monkeypatch.setattr(subprocess, "run", run)
    rc = module.main([UPID, "--timeout", "10"])
    result = json.loads(capsys.readouterr().out)
    assert rc == (2 if isinstance(failure, subprocess.TimeoutExpired) else 3)
    assert result["upid"] == UPID
    assert "sensitive" not in json.dumps(result)


@pytest.mark.parametrize("host", ["-oProxyCommand=bad", "bad host", "host;id", ""])
def test_bad_destination_is_refused(monkeypatch, capsys, host):
    monkeypatch.setenv("PROXMOX_HOST", host)
    monkeypatch.setenv("PROXMOX_SSH_USER", "agent")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("must not connect"))
    assert load().main([UPID]) == 3
    assert json.loads(capsys.readouterr().out)["upid"] == UPID


def test_real_cli_roundtrip_with_local_ssh_fixture(tmp_path, monkeypatch):
    # This executable replaces SSH only in this test; no PVE or network involved.
    ssh = tmp_path / "ssh"
    ssh.write_text("#!/bin/sh\nprintf '%s\\n' '{\"status\":\"stopped\",\"exitstatus\":\"OK\"}'\n")
    ssh.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("PROXMOX_HOST", "pve.example")
    monkeypatch.setenv("PROXMOX_SSH_USER", "agent")
    import sys
    result = subprocess.run([sys.executable, str(SPEC.origin), UPID, "--timeout", "5"],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"upid": UPID, "status": "stopped", "exitstatus": "OK"}
