"""Broker-owned WebAuthn credentials; callers serialize all methods under the broker lock."""
import hashlib
import json
import os
import re
import secrets
import tempfile
import time
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit

from webauthn import (generate_authentication_options, generate_registration_options, options_to_json,
                      verify_authentication_response, verify_registration_response)
from webauthn.helpers import (base64url_to_bytes as unb64, bytes_to_base64url as b64,
                              parse_authentication_credential_json, parse_client_data_json,
                              parse_registration_credential_json)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from .config import protected
from .leases import AccessError

STORE = 'passkeys.json'
TICKET = 'passkey-enrollment.json'
UV = UserVerificationRequirement.REQUIRED
BINDING = re.compile(r'[A-Za-z0-9_-]{43}:(?:[0-9a-f]{32})?')
MAX_KEYS = 8


def sync_directory(path):
    fd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_private(path, owner, limit):
    path = protected(path, owner=owner)
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('oversize authority data')
    return json.loads(data)


def write_private(path, value):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.'+path.name+'-', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(json.dumps(value, separators=(',', ':')).encode())
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, path)
            sync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)


def issue_enrollment_code(directory, *, owner=0):
    directory = protected(directory, owner=owner, directory=True)
    path = directory / TICKET
    if path.exists() or path.is_symlink():
        protected(path, owner=owner)
    code = secrets.token_urlsafe(24)
    write_private(path, dict(digest=hashlib.sha256(code.encode()).hexdigest(), expires=time.time()+300))
    return code


class Passkeys:
    def __init__(self, config, *, owner=0, clock=time.monotonic):
        self.store = Path(config.state_dir) / STORE
        self.ticket = Path(config.state_dir) / TICKET
        self.origin, self.rp_id = config.origin, urlsplit(config.origin).hostname
        self.clock, self.owner = clock, owner
        self.challenges, self.attempts = {}, deque()
        self.failed_storage = False
        self.user_id, self.keys = secrets.token_bytes(32), {}
        if self.store.exists() or self.store.is_symlink():
            try:
                data = read_private(self.store, owner, 65536)
                user_id, keys = unb64(data['user']), data['keys']
                if data['origin'] != self.origin or len(user_id) != 32 or type(keys) is not dict or len(keys) > MAX_KEYS:
                    raise ValueError('invalid passkey store')
                for ident, key in keys.items():
                    if (b64(unb64(ident)) != ident or not 1 <= len(unb64(ident)) <= 1023
                            or not 1 <= len(unb64(key['public'])) <= 4096
                            or type(key['count']) is not int or not 0 <= key['count'] <= 0xffffffff):
                        raise ValueError('invalid stored credential')
                self.user_id, self.keys = user_id, keys
            except (OSError, ValueError, TypeError, KeyError) as exc:
                raise AccessError('passkey store invalid; operator recovery required') from exc
        if config.auth_mode == 'passkey' and not self.keys:
            raise AccessError('passkey-only mode requires an enrolled credential')

    def save(self, keys):
        try:
            write_private(self.store, dict(origin=self.origin, user=b64(self.user_id), keys=keys))
        except OSError as exc:
            self.failed_storage = True
            self.challenges.clear()
            raise AccessError('passkey storage failed; operator recovery required') from exc
        self.keys = keys

    def check_available(self):
        if self.failed_storage:
            raise AccessError('passkey storage unavailable')

    def start(self, purpose, binding):
        self.check_available()
        now = self.clock()
        self.challenges = {k: v for k, v in self.challenges.items() if v[1] > now}
        key = (purpose, binding)
        # Anonymous logins must not deplete the enrollment or FULL approval slots.
        if key not in self.challenges and sum(k[0] == purpose for k in self.challenges) >= 32:
            raise AccessError('challenge quota reached')
        challenge = secrets.token_bytes(32)
        self.challenges[key] = (challenge, now+60)
        return challenge

    def take(self, purpose, binding):
        self.check_available()
        item = self.challenges.pop((purpose, binding), None)
        if not item or item[1] <= self.clock():
            raise AccessError('passkey challenge expired or mismatched')
        return item[0]

    def rate_limit(self):
        now = self.clock()
        while self.attempts and self.attempts[0] <= now - 60:
            self.attempts.popleft()
        if len(self.attempts) >= 12:
            raise AccessError('passkey attempts temporarily rate limited')
        self.attempts.append(now)

    def auth_options(self, purpose, binding):
        if not self.keys:
            raise AccessError('no passkey enrolled')
        challenge = self.start(purpose, binding)
        return json.loads(options_to_json(generate_authentication_options(
            rp_id=self.rp_id, challenge=challenge, user_verification=UV)))

    def verify(self, purpose, binding, credential):
        challenge = self.take(purpose, binding)
        if purpose == 'login':
            self.rate_limit()
        try:
            parsed = parse_authentication_credential_json(credential)
            item = self.keys[b64(parsed.raw_id)]
            if (parsed.response.user_handle != self.user_id or
                    parse_client_data_json(parsed.response.client_data_json).cross_origin):
                raise ValueError('foreign credential')
            verified = verify_authentication_response(
                credential=parsed, expected_challenge=challenge, expected_rp_id=self.rp_id,
                expected_origin=self.origin, credential_public_key=unb64(item['public']),
                credential_current_sign_count=item['count'], require_user_verification=True)
        except (WebAuthnException, KeyError, ValueError, TypeError, RecursionError) as exc:
            raise AccessError('passkey verification failed') from exc
        if verified.new_sign_count != item['count']:
            self.save({**self.keys, b64(parsed.raw_id): {**item, 'count': verified.new_sign_count}})

    def enroll_start(self, token, code):
        self.check_available()
        if len(self.keys) >= MAX_KEYS or not isinstance(code, str) or not re.fullmatch(r'[A-Za-z0-9_-]{32}', code):
            raise AccessError('passkey enrollment denied')
        try:
            ticket = read_private(self.ticket, self.owner, 1024)
            now = time.time()
            if not now < ticket['expires'] <= now + 300 or not secrets.compare_digest(
                    ticket['digest'], hashlib.sha256(code.encode()).hexdigest()):
                raise ValueError('invalid code')
            self.ticket.unlink()
            sync_directory(self.ticket.parent)
        except (OSError, TypeError, KeyError, ValueError) as exc:
            raise AccessError('passkey enrollment denied') from exc
        challenge = self.start('enroll', token)
        options = generate_registration_options(
            rp_id=self.rp_id, rp_name='Accès hôte PVE', user_name='operator', user_display_name='Opérateur PVE',
            user_id=self.user_id, challenge=challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.REQUIRED,
                                                                    require_resident_key=True,
                                                                    user_verification=UV),
            exclude_credentials=[PublicKeyCredentialDescriptor(id=unb64(k)) for k in self.keys])
        return json.loads(options_to_json(options))

    def enroll_finish(self, token, credential):
        challenge = self.take('enroll', token)
        try:
            parsed = parse_registration_credential_json(credential)
            if parse_client_data_json(parsed.response.client_data_json).cross_origin:
                raise ValueError('foreign enrollment')
            verified = verify_registration_response(
                credential=parsed, expected_challenge=challenge, expected_rp_id=self.rp_id,
                expected_origin=self.origin, require_user_verification=True)
            ident, pub = verified.credential_id, verified.credential_public_key
            if (b64(ident) in self.keys or len(self.keys) >= MAX_KEYS or
                    not 1 <= len(ident) <= 1023 or not 1 <= len(pub) <= 4096):
                raise ValueError('credential denied')
        except (WebAuthnException, ValueError, TypeError, RecursionError) as exc:
            raise AccessError('passkey enrollment failed') from exc
        self.save({**self.keys, b64(ident): {'public': b64(pub), 'count': verified.sign_count}})
