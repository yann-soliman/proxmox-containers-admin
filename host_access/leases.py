"""Single-node fail-closed state machine. Caller holds the broker lock."""
import json
import os
import secrets
import time
from pathlib import Path


class AccessError(ValueError):
    pass


class Leases:
    def __init__(self, path, *, agent, target, clock=time.monotonic, maximum=1800, pending_ttl=300):
        self.path = Path(path)
        self.agent, self.target = agent, target
        self.clock, self.maximum, self.pending_ttl = clock, maximum, pending_ttl
        self.records = {}
        self.deadlines = {}
        if self.path.exists():
            try:
                if self.path.stat().st_size > 1048576:
                    raise ValueError()
                self.records = json.loads(self.path.read_text())
                if not isinstance(self.records, dict) or len(self.records) > 100:
                    raise ValueError()
                import re
                for key, r in self.records.items():
                    if not re.fullmatch('[0-9a-f]{32}', key) or r['id'] != key or r['state'] not in {'pending', 'active', 'denied', 'expired', 'revoked'}:
                        raise ValueError()
                    if r['agent'] != agent or r['target'] != target or r['mode'] not in {'safe', 'full'}:
                        raise ValueError()
                    if type(r['duration']) is not int or not 1 <= r['duration'] <= maximum or not isinstance(r['reason'], str) or not 1 <= len(r['reason']) <= 512:
                        raise ValueError()
                    if r['state'] in {'pending', 'active'}:
                        r['state'] = 'revoked'
            except (ValueError, KeyError, TypeError, OSError) as exc:
                raise AccessError('invalid state; operator recovery required') from exc
        self.save()

    def save(self):
        try:
            self._persist()
        except OSError as exc:
            for record in self.records.values():
                if record['state'] in {'active', 'pending'}:
                    record['state'] = 'revoked'
            self.deadlines.clear()
            raise AccessError('state storage failed; authority closed') from exc

    def _persist(self):
        temporary = self.path.with_suffix('.new')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(self.records, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)
        fd = os.open(self.path.parent, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def expire(self):
        changed = False
        for rid, deadline in list(self.deadlines.items()):
            if self.clock() >= deadline and self.records[rid]['state'] in {'pending', 'active'}:
                self.records[rid]['state'] = 'expired'
                changed = True
        if changed:
            self.save()

    def request(self, mode, duration, reason):
        self.expire()
        if mode not in {'safe', 'full'} or type(duration) is not int or not 1 <= duration <= self.maximum:
            raise AccessError('invalid mode or duration')
        if not isinstance(reason, str) or not 1 <= len(reason) <= 512 or any(ord(c) < 32 for c in reason):
            raise AccessError('invalid reason')
        if any(r['state'] in {'pending', 'active'} for r in self.records.values()):
            raise AccessError('one pending request or active lease allowed')
        # Bounded history; terminal records only can be evicted.
        if len(self.records) >= 100:
            oldest = next(iter(self.records))
            del self.records[oldest]
            self.deadlines.pop(oldest, None)
        rid = secrets.token_hex(16)
        r = dict(id=rid, agent=self.agent, target=self.target, mode=mode, duration=duration,
                 reason=reason, state='pending', requested_at=time.time(), notified=False)
        self.records[rid] = r
        self.deadlines[rid] = self.clock() + self.pending_ttl
        self.save()
        return dict(r)

    def get(self, rid):
        self.expire()
        if rid not in self.records:
            raise AccessError('unknown request')
        return dict(self.records[rid])

    def decide(self, rid, decision):
        r = self.get(rid)
        if r['state'] != 'pending' or decision not in {'approve', 'deny'}:
            raise AccessError('request is not pending or decision invalid')
        r['state'] = 'active' if decision == 'approve' else 'denied'
        if decision == 'approve':
            self.deadlines[rid] = self.clock() + r['duration']
            r['expires_at'] = time.time() + r['duration']
        self.records[rid] = r
        self.save()
        return dict(r)

    def active(self, full=False):
        self.expire()
        for r in self.records.values():
            if r['state'] == 'active' and (not full or r['mode'] == 'full'):
                return dict(r)
        raise AccessError('no suitable active lease')

    def revoke(self, rid):
        r = self.get(rid)
        if r['state'] in {'pending', 'active'}:
            self.records[rid]['state'] = 'revoked'
            self.save()
        return self.get(rid)
