"""Existing guest transfer/stdin/exit behaviors with explicit native fixtures."""
import json
import os
import subprocess
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def wrapper(tmp_path):
    native = tmp_path/'native'
    native.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
if args[0]=='pull':
    Path(args[3]).write_bytes(b'guest-fixture-data')
elif args[0]=='push':
    Path(os.environ['NATIVE_CAPTURE']).write_text(json.dumps({'vmid':args[1],'path':args[3],'data':Path(args[2]).read_bytes().decode()}))
else:
    print(json.dumps({'argv':args,'stdin':sys.stdin.read(),'exitcode':7}))
''')
    native.chmod(0o700)
    source = (ROOT/'scripts/proxmox-guest-wrapper.sh').read_text()
    source = source.replace('/usr/sbin/pct',str(native)).replace('/usr/sbin/qm',str(native))
    # Model pct's silent successful transfers; inspect delivery out-of-band.
    staging = tmp_path/'transfer-state'
    staging.mkdir(mode=0o700)
    source = source.replace('/var/lib/proxmox-guest-wrapper',str(staging)).replace('0:700',str(os.getuid())+':700')
    p = tmp_path/'wrapper'
    p.write_text(source)
    capture = tmp_path/'native-transfer.json'
    def run(command,data=b''):
        return subprocess.run(['bash',str(p)],env={**os.environ,'SSH_ORIGINAL_COMMAND':command,'NATIVE_CAPTURE':str(capture)},
                              input=data,capture_output=True)
    return run, capture


def test_guest_pull_and_push_spaces_unchanged(wrapper):
    run, capture = wrapper
    result = run('lxc-pull 101 /guest/path with spaces')
    assert result.returncode == 0 and result.stdout == b'guest-fixture-data'
    result = run('lxc-push 101 /guest/path with spaces',b'input-data')
    assert result.returncode == 0
    assert json.loads(capture.read_text()) == {'vmid':'101','path':'/guest/path with spaces','data':'input-data'}


def test_vm_script_stdin_and_guest_nonzero_propagated(wrapper):
    run, _ = wrapper
    result = run('vm-shell-stdin 101',b'printf script')
    assert result.returncode == 7
    payload = json.loads(result.stdout)
    assert payload['stdin'] == 'printf script'
    assert payload['argv'] == ['guest','exec','101','--pass-stdin','1','--','sh','-s']
    result = run('vm-shell 101 -- exit 7')
    assert result.returncode == 7
