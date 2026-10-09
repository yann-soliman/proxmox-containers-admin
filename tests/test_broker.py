import os
import secrets
import threading
import time
import pytest
from host_access.auth import Auth
from host_access.config import Config
from host_access.executor import LocalTestBackend
from host_access.broker import Broker, rpc
from host_access.leases import AccessError


class EphemeralSecret(str):
    def __repr__(self):
        return '<ephemeral secret redacted>'


class LocalPolicyTestBackend(LocalTestBackend):
    """Explicit test-only config injection; runs the actual SAFE worker/native tools."""
    def __init__(self, config):
        self.config = config

    def start(self, argv, **kwargs):
        if argv[1:4] == ['-I','-m','host_access.safe_actions']:
            import json
            from dataclasses import asdict
            bootstrap = ('from host_access import safe_actions; from host_access.config import Config; '
                         'import json,sys; c=json.loads(sys.argv.pop(1)); '
                         'safe_actions.load=lambda:Config(**c); sys.exit(safe_actions.main())')
            argv = [argv[0],'-I','-c',bootstrap,json.dumps(asdict(self.config)),*argv[4:]]
        return super().start(argv, **kwargs)


@pytest.fixture
def running(tmp_path):
    password = EphemeralSecret(secrets.token_urlsafe(32))
    authfile = tmp_path / 'password.hash'
    Auth.bootstrap(authfile, password)
    c = Config(origin='https://approve.example', agent_uid=123, web_uid=124,
               state_dir=str(tmp_path), socket_dir=str(tmp_path.parent / ('u-' + secrets.token_hex(4))), password_file=str(authfile), enable_script=True)
    b = Broker(c, backend=LocalPolicyTestBackend(c), owner=os.getuid(), agent_peer_uid=os.getuid(), web_peer_uid=os.getuid())
    b.start()
    try:
        yield b, password
    finally:
        b.close()


def call(b, role, op, **kw):
    return rpc(b.socket(role), dict(op=op, **kw))


def approve(b, pw, rid):
    login = call(b, 'web', 'login', password=pw)
    page = call(b, 'web', 'view', token=login['token'], id=rid)
    return call(b, 'web', 'approve', token=login['token'], csrf=login['csrf'],
                challenge=page['challenge'], id=rid, password=pw)


def test_real_unix_separation_and_immutable_identity(running):
    b, pw = running
    with pytest.raises(AccessError):
        call(b, 'agent', 'request', mode='safe', duration=900, reason='x', agent='root')
    r = call(b, 'agent', 'request', mode='safe', duration=900, reason='inspect')
    assert r['agent'] == b.config.agent
    with pytest.raises(AccessError):
        call(b, 'agent', 'approve', id=r['id'], password=pw)
    with pytest.raises(AccessError):
        call(b, 'web', 'request', mode='full', duration=900, reason='x')
    with pytest.raises(AccessError):
        call(b, 'agent', 'execute', command='id', stdin='')
    approve(b, pw, r['id'])
    assert call(b, 'agent', 'status', id=r['id'])['state'] == 'active'
    import json
    diagnostic = call(b, 'agent', 'safe', action='cpu-memory', params={})
    assert diagnostic['exitcode'] == 0
    assert json.loads(diagnostic['stdout'])['available'] is True
    with pytest.raises(AccessError):
        call(b, 'agent', 'execute', command='id', stdin='')
    call(b, 'agent', 'revoke', id=r['id'])
    assert call(b, 'agent', 'status', id=r['id'])['state'] == 'revoked'


def test_real_full_stdio_revocation_during_execution(running):
    b, pw = running
    r = call(b, 'agent', 'request', mode='full', duration=900, reason='benign integration')
    approve(b, pw, r['id'])
    import base64
    out = call(b, 'agent', 'execute', command='cat; printf err >&2; exit 7', stdin=base64.b64encode(b'hello\x00binary').decode())
    assert base64.b64decode(out['stdout_b64']) == b'hello\x00binary'
    assert out['stderr'] == 'err' and out['exitcode'] == 7
    out = call(b, 'agent', 'execute', command='printf hello; printf err >&2; exit 7')
    assert out['stdout'] == 'hello' and out['stderr'] == 'err' and out['exitcode'] == 7
    result = []
    t = threading.Thread(target=lambda: result.append(call(b, 'agent', 'execute', command='sleep 20; echo escaped')))
    t.start()
    until = time.monotonic()+2
    while not b.jobs and time.monotonic() < until:
        time.sleep(.01)
    assert b.jobs
    call(b, 'agent', 'revoke', id=r['id'])
    t.join(5)
    assert not t.is_alive() and result[0]['exitcode'] != 0
    with pytest.raises(AccessError):
        call(b, 'agent', 'execute', command='echo escaped')


def test_peer_credentials_denied(tmp_path):
    p = tmp_path / 'hash'
    Auth.bootstrap(p, secrets.token_urlsafe(32))
    c = Config(origin='https://example', agent_uid=123, web_uid=124, password_file=str(p),
               state_dir=str(tmp_path), socket_dir=str(tmp_path.parent / ('u-' + secrets.token_hex(4))))
    b = Broker(c, backend=LocalTestBackend(), owner=os.getuid(), agent_peer_uid=99999, web_peer_uid=99998)
    b.start()
    try:
        with pytest.raises(AccessError):
            call(b, 'agent', 'status')
        with pytest.raises(AccessError):
            call(b, 'web', 'login', password='not-a-password')
    finally:
        b.close()
