import os
import socket
import threading
import pytest
from host_access.leases import AccessError, Leases
from host_access.config import Config
from host_access.safe_actions import run_action
from test_broker import call, approve


def test_failed_persistence_does_not_leave_active_authority(tmp_path):
    s = Leases(tmp_path/'state.json',agent='a',target='n')
    r = s.request('full',900,'x')
    (tmp_path/'state.new').mkdir()
    with pytest.raises(AccessError):
        s.decide(r['id'],'approve')
    with pytest.raises(AccessError):
        s.active()


def test_failed_units_does_not_expose_descriptions(monkeypatch):
    from host_access import safe_actions
    monkeypatch.setattr(safe_actions,'command',lambda args: dict(available=True, output='evil.service loaded failed failed password-in-description\n'))
    result = run_action('failed-units',{},Config(origin='https://example',agent_uid=123,web_uid=124))
    assert 'password-in-description' not in str(result)
    assert result['rows'][0] == {'name':'evil.service','load':'loaded','active':'failed','sub':'failed'}


def test_boot_and_listening_process_metadata_are_selected(monkeypatch):
    from host_access import safe_actions
    c = Config(origin='https://example',agent_uid=123,web_uid=124)
    summary = run_action('host-summary',{},c)
    assert type(summary['boot_unix_time']) is int
    monkeypatch.setattr(safe_actions,'command',lambda args: dict(available=True,output='tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,fd=4))\n'))
    ports = run_action('listening-ports',{},c)
    assert ports['rows'][0]['processes'] == ['sshd']
    assert 'fd=' not in str(ports)


def test_lvm_missing_dependency_is_unavailable(monkeypatch):
    from host_access import safe_actions
    monkeypatch.setattr(safe_actions,'command',lambda args: dict(available=False,reason='missing'))
    result = run_action('lvm-summary',{},Config(origin='https://example',agent_uid=123,web_uid=124))
    assert result['available'] is False


def test_existing_fan_inputs_are_reported_without_probing(tmp_path, monkeypatch):
    from pathlib import Path
    directory = tmp_path/'hwmon0'
    directory.mkdir()
    temp,fan = directory/'temp1_input',directory/'fan1_input'
    temp.write_text('42000')
    fan.write_text('900')
    original = Path.glob
    def glob(path, pattern):
        if str(path) == '/sys/class/hwmon':
            return iter([temp] if 'temp' in pattern else [fan])
        return original(path, pattern)
    monkeypatch.setattr(Path,'glob',glob)
    result = run_action('hardware-temperatures',{},Config(origin='https://example',agent_uid=123,web_uid=124))
    assert any(row.get('rpm') == 900 for row in result['rows'])


def test_pve_task_query_and_fields_are_bounded(monkeypatch):
    import json
    from host_access import safe_actions
    seen = []
    def command(argv):
        seen.append(argv)
        return dict(available=True,output=json.dumps([{'type':'backup','id':'101','starttime':1,'status':'OK','password':'never expose','args':'never expose'}]))
    monkeypatch.setattr(safe_actions,'command',command)
    result = run_action('task-summary',{'limit':3},Config(origin='https://example',agent_uid=123,web_uid=124))
    assert 'password' not in str(result) and 'args' not in str(result)
    assert '--limit' in seen[0] and seen[0][seen[0].index('--limit')+1] == '3'


def test_broker_expiry_race_and_restart_readback(running):
    b,pw = running
    r = call(b,'agent','request',mode='full',duration=1,reason='expiry race')
    approve(b,pw,r['id'])
    result = call(b,'agent','execute',command='sleep 10; echo should-not-run')
    assert result['exitcode'] != 0 and 'should-not-run' not in result['stdout']
    assert call(b,'agent','status',id=r['id'])['state'] == 'expired'


def test_persisted_identity_and_mode_corruption_rejected(tmp_path):
    import json
    path = tmp_path/'state.json'
    s = Leases(path,agent='a',target='n')
    r = s.request('safe',900,'x')
    data = json.loads(path.read_text())
    for field,value in [('agent','forged'),('target','other-node'),('mode','root'),('duration',True)]:
        corrupted = json.loads(json.dumps(data))
        corrupted[r['id']][field] = value
        path.write_text(json.dumps(corrupted))
        with pytest.raises(AccessError):
            Leases(path,agent='a',target='n')


def test_auth_challenge_timeout(tmp_path):
    from host_access.auth import Auth
    import secrets
    p = tmp_path/'hash'
    pw = secrets.token_urlsafe(32)
    Auth.bootstrap(p,pw)
    now = [0.0]
    auth = Auth(p,clock=lambda: now[0])
    token,csrf = auth.login(pw)
    challenge = auth.challenge(token,'fixed-request')
    now[0] += 121
    with pytest.raises(AccessError):
        auth.confirm(token,csrf,challenge,'fixed-request',pw)


def test_request_history_stays_bounded(tmp_path):
    s = Leases(tmp_path/'state.json',agent='a',target='n')
    for _ in range(110):
        r = s.request('safe',900,'x')
        s.decide(r['id'],'deny')
    assert len(s.records) <= 100 and len(s.deadlines) <= 100
    s.expire()


def test_single_broker_instance_and_restart_invalidation(running):
    from host_access.broker import Broker
    from host_access.executor import LocalTestBackend
    b,pw = running
    r = call(b,'agent','request',mode='full',duration=900,reason='restart')
    approve(b,pw,r['id'])
    with pytest.raises(AccessError):
        Broker(b.config,backend=LocalTestBackend(),owner=os.getuid(),agent_peer_uid=os.getuid(),web_peer_uid=os.getuid())
    b.close()
    other = Broker(b.config,backend=LocalTestBackend(),owner=os.getuid(),agent_peer_uid=os.getuid(),web_peer_uid=os.getuid())
    other.start()
    try:
        assert call(other,'agent','status',id=r['id'])['state'] == 'revoked'
        with pytest.raises(AccessError):
            call(other,'agent','execute',command='true')
    finally:
        other.close()


def test_full_scripts_default_disabled_and_bounds(running):
    import base64
    from dataclasses import replace
    b,pw = running
    r = call(b,'agent','request',mode='full',duration=900,reason='script policy')
    approve(b,pw,r['id'])
    b.config = replace(b.config,enable_script=False)
    with pytest.raises(AccessError):
        call(b,'agent','script',stdin=base64.b64encode(b'printf forbidden').decode())
    b.config = replace(b.config,enable_script=True,max_input=64)
    result = call(b,'agent','script',stdin=base64.b64encode(b'printf script-result; exit 4').decode())
    assert result['stdout'] == 'script-result' and result['exitcode'] == 4
    with pytest.raises(AccessError):
        call(b,'agent','script',stdin=base64.b64encode(b'x'*65).decode())
    with pytest.raises(AccessError):
        call(b,'agent','execute',command='x'*65)
    with pytest.raises(AccessError):
        call(b,'agent','script',stdin='%%%')


def test_terminal_notifications_are_deduplicated_after_status_expiry(running):
    import time
    b,pw = running
    events = []
    b.notifier = lambda r: events.append(r['state']) or True
    r = call(b,'agent','request',mode='safe',duration=900,reason='events')
    approve(b,pw,r['id'])
    with b.lock:
        b.leases.deadlines[r['id']] = time.monotonic()-1
        assert b.dispatch('agent',{'op':'status','id':r['id']})['state'] == 'expired'
    call(b,'agent','revoke',id=r['id'])
    call(b,'agent','revoke',id=r['id'])
    until = time.monotonic()+1
    while len(events) < 3 and time.monotonic() < until:
        time.sleep(.01)
    assert events == ['pending','active','expired']


def test_approve_revoke_race_is_terminal(running):
    b,pw = running
    r = call(b,'agent','request',mode='full',duration=900,reason='race')
    login = call(b,'web','login',password=pw)
    page = call(b,'web','view',token=login['token'],id=r['id'])
    barrier = threading.Barrier(3)
    def decide():
        barrier.wait()
        try:
            call(b,'web','approve',id=r['id'],token=login['token'],csrf=login['csrf'],challenge=page['challenge'],password=pw)
        except AccessError:
            pass
    def revoke():
        barrier.wait()
        call(b,'agent','revoke',id=r['id'])
    threads = [threading.Thread(target=decide),threading.Thread(target=revoke)]
    for t in threads:
        t.start()
    barrier.wait()
    for t in threads:
        t.join(3)
    assert call(b,'agent','status',id=r['id'])['state'] == 'revoked'
    with pytest.raises(AccessError):
        call(b,'agent','execute',command='true')


def test_protocol_oversize_and_wrong_type_fail_closed(running):
    b,pw = running
    for raw in (b'[]\n',b'x'*131073+b'\n', b'{"op":"status","id":[]}\n'):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect(str(b.socket('agent')))
            s.sendall(raw)
            assert b'"ok": false' in s.recv(4096)
    assert call(b,'agent','status')['state'] == 'none'
