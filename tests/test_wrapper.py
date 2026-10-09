import json
import os
import subprocess
import pytest
from pathlib import Path
from host_access.client import parse_command, trusted_agent, exit_status
from host_access.config import Config
from host_access.leases import AccessError

ROOT = Path(__file__).resolve().parents[1]


def test_truncated_output_is_not_silent_cli_success():
    assert exit_status({'exitcode':0,'truncated':True}) == 125
    assert exit_status({'exitcode':7,'truncated':False}) == 7
    assert exit_status({'exitcode':-9,'truncated':False}) == 137


def test_host_protocol_and_identity_cannot_be_supplied():
    assert parse_command('host-access-request safe -- inspect') == dict(op='request',mode='safe',duration=900,reason='inspect')
    assert parse_command('host-access-request full 1800 -- fix') ['duration'] == 1800
    assert parse_command('host-exec --stdin -- cat') == dict(op='execute', command='cat', read_stdin=True)
    assert parse_command('host-exec -- printf "%s" hi') == dict(op='execute', command='printf "%s" hi')
    assert parse_command('host-safe service-status service=pveproxy.service')['params'] == {'service':'pveproxy.service'}
    for cmd in ['host-access-approve x', 'host-access-status a; reboot', 'host-access-request safe --', 'host-safe cpu-memory x=1 x=2', 'host-script-stdin extra']:
        with pytest.raises(AccessError):
            parse_command(cmd)
    c = Config(origin='https://example',agent_uid=123,web_uid=124)
    with pytest.raises(AccessError):
        trusted_agent(c, euid=0, sudo_uid='124')
    with pytest.raises(AccessError):
        trusted_agent(c, euid=123, sudo_uid='123')
    assert trusted_agent(c, euid=0, sudo_uid='123') == c.agent


@pytest.mark.parametrize('command,expected', [
    ('list-lxc',['pct','list']), ('list-vm',['qm','list']),
    ('lxc-status 100',['pct','status','100']), ('vm-status 100',['qm','status','100']),
    ('lxc-config 100',['pct','config','100']), ('vm-config 100',['qm','config','100']),
    ('lxc-shell 100 -- echo hi; true',['pct','exec','100','--','sh','-c','echo hi; true']),
    ('vm-shell 100 -- echo hi',['qm','guest','exec','100','--','sh','-c','echo hi']),
    ('lxc-shell-stdin 100',['pct','exec','100','--','sh','-s']),
    ('vm-shell-stdin 100',['qm','guest','exec','100','--pass-stdin','1','--','sh','-s']),
    ('vm-agent-ping 100',['qm','agent','100','ping']),
    ('lxc-power 100 reboot',['pct','reboot','100']), ('vm-power 100 reset',['qm','reset','100']),
])
def test_guest_wrapper_regression_real_bash(tmp_path, command, expected):
    stub = tmp_path/'stub'
    stub.write_text('#!/usr/bin/env python3\nimport json,sys,os\nprint(json.dumps({"argv":[os.path.basename(sys.argv[0]),*sys.argv[1:]],"exitcode":0}))\n')
    stub.chmod(0o700)
    for name in ['pct','qm']:
        (tmp_path/name).symlink_to(stub)
    wrapper = tmp_path/'wrapper'
    source = (ROOT/'scripts/proxmox-guest-wrapper.sh').read_text()
    source = source.replace('/usr/sbin/pct',str(tmp_path/'pct')).replace('/usr/sbin/qm',str(tmp_path/'qm'))
    wrapper.write_text(source)
    r = subprocess.run(['bash',str(wrapper)], env={**os.environ,'SSH_ORIGINAL_COMMAND':command}, capture_output=True)
    assert r.returncode == 0
    assert json.loads(r.stdout)['argv'] == expected


@pytest.mark.parametrize('command', ['host-access-status', 'host-exec -- true', 'lxc-status 1; true', 'vm-shell-stdin 1 extra', 'host-access-approve x'])
def test_disabled_host_and_invalid_guest_fail_closed(command):
    r = subprocess.run(['bash',str(ROOT/'scripts/proxmox-guest-wrapper.sh')], env={**os.environ,'SSH_ORIGINAL_COMMAND':command},capture_output=True)
    assert r.returncode != 0
