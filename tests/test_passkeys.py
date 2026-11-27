import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import bytes_to_base64url as b64

from host_access.auth import Auth
from host_access.broker import Broker
from host_access.config import Config
from host_access.leases import AccessError

ORIGIN = 'https://approve.example'
RP_HASH = hashlib.sha256(b'approve.example').digest()
BINDING = 'a' * 43 + ':'


class SoftwareKey:
    def __init__(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.id = os.urandom(32)
        self.user_handle = None

    def credential(self, options, *, registration=False, origin=ORIGIN, uv=True, count=0):
        data = json.dumps(dict(type='webauthn.create' if registration else 'webauthn.get',
                               challenge=options['challenge'], origin=origin, crossOrigin=False)).encode()
        mask = 1 | (4 if uv else 0) | (64 if registration else 0)
        auth_data = RP_HASH + bytes([mask]) + count.to_bytes(4, 'big')
        response = {'clientDataJSON': b64(data)}
        if registration:
            pub = self.private.public_key().public_numbers()
            cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: pub.x.to_bytes(32, 'big'), -3: pub.y.to_bytes(32, 'big')})
            auth_data += bytes(16) + len(self.id).to_bytes(2, 'big') + self.id + cose
            response['attestationObject'] = b64(cbor2.dumps(dict(fmt='none', authData=auth_data, attStmt={})))
        else:
            signature = self.private.sign(auth_data+hashlib.sha256(data).digest(), ec.ECDSA(hashes.SHA256()))
            response.update(authenticatorData=b64(auth_data), signature=b64(signature), userHandle=self.user_handle)
        return dict(id=b64(self.id), rawId=b64(self.id), type='public-key', response=response)


def setup(tmp_path, mode='migration'):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700, exist_ok=True)
    pw_file = tmp_path / 'password.hash'
    if not pw_file.exists():
        Auth.bootstrap(pw_file, 'test-only long password string')
    config = Config(origin=ORIGIN, state_dir=str(state), password_file=str(pw_file),
                    socket_dir=str(tmp_path), agent_uid=123, web_uid=124, auth_mode=mode)
    return Broker(config, owner=os.getuid(), backend=SimpleNamespace(cleanup=lambda: None))


def rpc(broker, op, role='web', **args):
    return broker.dispatch(role, dict(op=op, **args))


def test_migration_advertises_feature_without_credentials(tmp_path):
    b = setup(tmp_path)
    try:
        assert rpc(b, 'auth_info') == {'auth_mode': 'migration', 'passkey_available': False}
        with pytest.raises(AccessError):
            rpc(b, 'auth_info', role='agent')
    finally:
        b.close()


def test_passkey_only_refuses_startup_without_credential(tmp_path):
    with pytest.raises(AccessError, match='requires an enrolled credential'):
        setup(tmp_path, 'passkey')


def test_passkey_session_has_absolute_expiry(tmp_path):
    pw_file = tmp_path / 'password.hash'
    Auth.bootstrap(pw_file, 'test-only long password string')
    now = 100.0
    auth = Auth(pw_file, clock=lambda: now)
    token, _ = auth.new_session(passkey=True)
    now += 1799
    assert auth.session(token)['passkey']
    now += 1
    with pytest.raises(AccessError, match='authentication required'):
        auth.session(token)


def test_passkey_cryptographic_lifecycle(tmp_path):
    from host_access.passkeys import issue_enrollment_code

    key = SoftwareKey()
    b = setup(tmp_path)
    try:
        login = rpc(b, 'login', password='test-only long password string')
        session = {k: login[k] for k in ('token', 'csrf')}
        with pytest.raises(AccessError):
            rpc(b, 'passkey_enroll_start', **session, code='absent')
        code = issue_enrollment_code(Path(b.config.state_dir), owner=os.getuid())
        options = rpc(b, 'passkey_enroll_start', **session, code=code)
        key.user_handle = options['user']['id']
        assert options['authenticatorSelection']['residentKey'] == 'required'
        with pytest.raises(AccessError):
            rpc(b, 'passkey_enroll_start', **session, code=code)
        rpc(b, 'passkey_enroll_finish', **session, credential=key.credential(options, registration=True))
        with pytest.raises(AccessError):
            rpc(b, 'passkey_enroll_finish', **session, credential=key.credential(options, registration=True))
    finally:
        b.close()

    b = setup(tmp_path, 'passkey')
    try:
        assert rpc(b, 'auth_info')['passkey_available']
        with pytest.raises(AccessError):
            rpc(b, 'login', password='test-only long password string')
        options = rpc(b, 'passkey_login_start', binding=BINDING)
        for i in range(40):
            rpc(b, 'passkey_login_start', binding=f'{i:043d}:')
        for i in range(40):
            other = f'{i:043d}:'
            rpc(b, 'passkey_login_start', binding=other)
            with pytest.raises(AccessError):
                rpc(b, 'passkey_login_finish', binding=other, credential={})
        valid = key.credential(options)
        with pytest.raises(AccessError):
            rpc(b, 'passkey_login_finish', binding='z'*43+':', credential=valid)
        assert rpc(b, 'passkey_login_finish', binding=BINDING, credential=valid)['max_age'] == 1800
        with pytest.raises(AccessError):
            rpc(b, 'passkey_login_finish', binding=BINDING, credential=valid)
        passkeys = b.passkeys
        assert passkeys is not None
        clock = passkeys.clock
        passkeys.clock = lambda: 100.0
        expired = rpc(b, 'passkey_login_start', binding=BINDING)
        passkeys.clock = lambda: 160.0
        with pytest.raises(AccessError):
            rpc(b, 'passkey_login_finish', binding=BINDING, credential=key.credential(expired))
        passkeys.clock = clock
        for invalid in ({'origin':'https://other.example'}, {'uv':False}):
            options = rpc(b, 'passkey_login_start', binding=BINDING)
            with pytest.raises(AccessError):
                rpc(b, 'passkey_login_finish', binding=BINDING, credential=key.credential(options, **invalid))
        options = rpc(b, 'passkey_login_start', binding=BINDING)
        login = rpc(b, 'passkey_login_finish', binding=BINDING, credential=key.credential(options))
        assert login['max_age'] == 1800
        session = {k: login[k] for k in ('token', 'csrf')}
        record = rpc(b, 'request', role='agent', mode='full', reason='Test only')
        rid = record['id']
        page = rpc(b, 'view', token=session['token'], id=rid)
        assert page['step_up']
        m = dict(**session, id=rid, challenge=page['challenge'])
        with pytest.raises(AccessError):
            rpc(b, 'approve', **m)
        assert rpc(b, 'status', role='agent', id=rid)['state'] == 'pending'
        m['challenge'] = rpc(b, 'view', token=session['token'], id=rid)['challenge']
        options = rpc(b, 'passkey_approve_start', **m)
        assert rpc(b, 'approve', **m, credential=key.credential(options))['state'] == 'active'
        with pytest.raises(AccessError):
            rpc(b, 'approve', **m, credential=key.credential(options))
    finally:
        b.close()
