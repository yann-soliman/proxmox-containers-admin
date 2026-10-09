"""Password authority lives in broker memory; no password logging."""
import os
import secrets
import time
from collections import deque
from pathlib import Path
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError, InvalidHashError
from .leases import AccessError

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, type=Type.ID)


class Auth:
    @staticmethod
    def bootstrap(path, password):
        if not 16 <= len(password) <= 1024:
            raise ValueError('password must have 16..1024 characters')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(HASHER.hash(password))
            stream.flush()
            os.fsync(stream.fileno())

    def __init__(self, path, clock=time.monotonic):
        self.hash = Path(path).read_text().strip()
        if not self.hash.startswith('$argon2id$'):
            raise ValueError('Argon2id hash required')
        self.clock, self.attempts, self.sessions = clock, deque(), {}

    def verify(self, password):
        now = self.clock()
        while self.attempts and self.attempts[0] <= now - 60:
            self.attempts.popleft()
        if len(self.attempts) >= 6:
            raise AccessError('authentication temporarily rate limited')
        self.attempts.append(now)
        if not isinstance(password, str) or not 1 <= len(password) <= 1024:
            raise AccessError('authentication failed')
        try:
            HASHER.verify(self.hash, password)
        except (VerificationError, InvalidHashError) as exc:
            raise AccessError('authentication failed') from exc

    def login(self, password):
        self.verify(password)
        self.sessions = {k: v for k, v in self.sessions.items() if v['until'] > self.clock()}
        if len(self.sessions) >= 32:
            raise AccessError('session quota reached')
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.sessions[token] = dict(csrf=csrf, until=self.clock() + 900, challenge=None)
        return token, csrf

    def session(self, token):
        s = self.sessions.get(token)
        if not s or self.clock() >= s['until']:
            raise AccessError('authentication required')
        return s

    def check_csrf(self, token, csrf):
        s = self.session(token)
        if not isinstance(csrf, str) or not secrets.compare_digest(s['csrf'], csrf):
            raise AccessError('CSRF rejected')

    def challenge(self, token, rid):
        s = self.session(token)
        nonce = secrets.token_urlsafe(32)
        s['challenge'] = (nonce, rid, self.clock() + 120)
        return nonce

    def confirm(self, token, csrf, nonce, rid, password=None):
        # Approval uses the bounded authenticated session, not a second login.
        # Ignore the optional legacy argument; new web clients never send it.
        self.check_csrf(token, csrf)
        s = self.session(token)
        challenge, s['challenge'] = s['challenge'], None
        if not challenge or challenge[1] != rid or self.clock() >= challenge[2] or not isinstance(nonce, str) or not secrets.compare_digest(challenge[0], nonce):
            raise AccessError('confirmation expired or mismatched')
