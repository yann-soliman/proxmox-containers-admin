import shutil
import subprocess
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_systemd_unit_syntax_without_installing_services(tmp_path):
    tool = shutil.which('systemd-analyze')
    if tool is None:
        pytest.skip('systemd-analyze unavailable')
    paths = []
    for name in ['proxmox-host-access-broker.service','proxmox-host-access-web.service']:
        text = (ROOT/'systemd'/name).read_text()
        text = text.replace('/opt/proxmox-host-access/venv/bin/python',sys.executable)
        p = tmp_path/name
        p.write_text(text)
        paths.append(str(p))
    result = subprocess.run([tool,'verify',*paths],capture_output=True,timeout=10)
    assert result.returncode == 0, result.stderr.decode()
    assert b'Unknown' not in result.stderr
