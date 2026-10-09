"""Unix peer-authenticated authority; all admission/transitions share one lock."""
import base64
import io
import json
import os
import queue
import signal
import socket
import socketserver
import struct
import threading
import time
from pathlib import Path
from .auth import Auth
from .config import load, protected
from .executor import SystemdBackend, ExecutionError
from .leases import Leases, AccessError
from .safe_actions import plan

MAX_WIRE = 131072


def receive(stream, limit):
    raw = stream.readline(limit + 1)
    if not raw.endswith(b'\n') or len(raw) > limit:
        raise AccessError('message size or framing rejected')
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise AccessError('invalid JSON') from exc
    if not isinstance(result, dict):
        raise AccessError('object required')
    return result


def rpc(path, message, timeout=1810, *, deadline=None):
    raw = json.dumps(message).encode() + b'\n'
    if len(raw) > MAX_WIRE:
        raise AccessError('message too large')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        def bounded_timeout():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AccessError('RPC deadline exceeded')
            s.settimeout(min(timeout, remaining))

        s.settimeout(timeout)
        if deadline is not None:
            bounded_timeout()
        s.connect(str(path))
        if deadline is not None:
            bounded_timeout()
        s.sendall(raw)
        if deadline is None:
            with s.makefile('rb') as stream:
                result = receive(stream, 41943040)
        else:
            # Reception authorization must obey a TOTAL deadline even if a
            # response arrives in multiple chunks; normal execution RPC is unchanged.
            reply = bytearray()
            while b'\n' not in reply:
                bounded_timeout()
                chunk = s.recv(min(4096, 41943041 - len(reply)))
                if not chunk:
                    break
                reply.extend(chunk)
                if len(reply) > 41943040:
                    raise AccessError('message too large')
            bounded_timeout()
            result = receive(io.BytesIO(reply), 41943040)
    if not result.get('ok'):
        raise AccessError(result.get('error', 'broker refused'))
    return result['result']


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 16

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Never emit payloads/tracebacks containing passwords or command bodies.
        pass


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            pid, uid, gid = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if uid != self.server.peer_uid:
                raise AccessError('peer authority rejected')
            message = receive(self.rfile, MAX_WIRE)
            result = self.server.broker.dispatch(self.server.role, message)
            reply = dict(ok=True, result=result)
        except (AccessError, ExecutionError) as exc:
            reply = dict(ok=False, error=str(exc))
        except Exception:
            reply = dict(ok=False, error='broker operation failed closed')
        try:
            self.wfile.write(json.dumps(reply).encode() + b'\n')
        except OSError:
            pass


class Broker:
    def __init__(self, config, *, backend=None, owner=0, agent_peer_uid=0, web_peer_uid=None, notifier=None):
        self.config, self.owner = config, owner
        self.backend = backend if backend is not None else SystemdBackend()
        self.agent_peer_uid = agent_peer_uid
        self.web_peer_uid = config.web_uid if web_peer_uid is None else web_peer_uid
        self.lock = threading.RLock()
        self.jobs, self.servers, self.threads = {}, [], []
        self.stopped = threading.Event()
        self.last_request = -float('inf')
        self.notifications = queue.Queue(maxsize=100)
        self.notifier = notifier
        protected(config.state_dir, owner=owner, directory=True)
        protected(config.password_file, owner=owner)
        state = Path(config.state_dir) / 'state.json'
        if state.exists() or state.is_symlink():
            protected(state, owner=owner)
        lockfile = Path(config.state_dir)/'broker.lock'
        if lockfile.exists() or lockfile.is_symlink():
            protected(lockfile, owner=owner)
        import fcntl
        self.lock_fd = os.open(lockfile, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self.lock_fd)
            self.lock_fd = None
            raise AccessError('another broker owns state') from exc
        try:
            self.leases = Leases(state, agent=config.agent, target=config.target,
                                 maximum=config.maximum_duration, pending_ttl=config.pending_ttl)
            self.auth = Auth(config.password_file)
        except Exception:
            os.close(self.lock_fd)
            self.lock_fd = None
            raise
        self.event_states = {rid: r['state'] for rid, r in self.leases.records.items()}
        self.closed = False

    def socket(self, role):
        return Path(self.config.socket_dir) / (role + '.sock')

    def start(self):
        self.backend.cleanup()
        Path(self.config.socket_dir).mkdir(mode=0o750, exist_ok=True)
        protected(self.config.socket_dir, owner=self.owner, directory=True)
        if self.owner == 0:
            import pwd
            os.chown(self.config.socket_dir, 0, pwd.getpwuid(self.config.web_uid).pw_gid)
        for role, uid in [('agent', self.agent_peer_uid), ('web', self.web_peer_uid)]:
            path = self.socket(role)
            if path.exists() or path.is_symlink():
                s = path.lstat()
                import stat
                if s.st_uid != self.owner or not stat.S_ISSOCK(s.st_mode):
                    raise ValueError('unsafe socket path')
                path.unlink()
            server = Server(str(path), Handler)
            server.broker, server.role, server.peer_uid = self, role, uid
            server.slots = threading.BoundedSemaphore(16)
            os.chmod(path, 0o600 if role == 'agent' else 0o660)
            if self.owner == 0 and role == 'web':
                import pwd
                os.chown(path, 0, pwd.getpwuid(self.config.web_uid).pw_gid)
            self.servers.append(server)
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            self.threads.append(t)
        for fn in (self.watch, self.notify_worker):
            t = threading.Thread(target=fn, daemon=True)
            t.start()
            self.threads.append(t)

    def audit(self, event, record, **metadata):
        if not self.config.audit_enabled:
            return
        data = {key: record[key] for key in ('id', 'agent', 'target', 'mode', 'duration', 'state') if key in record}
        data.update(event=event, timestamp=time.time(), **metadata)
        path = Path(self.config.state_dir)/'audit.jsonl'
        try:
            if path.exists() or path.is_symlink():
                protected(path, owner=self.owner)
                if path.stat().st_size > 1048576:
                    os.replace(path, path.with_suffix('.jsonl.1'))
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(json.dumps(data)+'\n')
        except (OSError, ValueError):
            # Optional best-effort metadata log cannot grant access or log payloads.
            pass

    def emit(self, record):
        if self.event_states.get(record['id']) == record['state']:
            return
        self.event_states = {rid: state for rid, state in self.event_states.items() if rid in self.leases.records}
        self.event_states[record['id']] = record['state']
        self.audit('state-transition', record)
        if self.notifier:
            try:
                self.notifications.put_nowait(dict(record))
            except queue.Full:
                pass

    def notify_worker(self):
        while not self.stopped.is_set():
            try:
                r = self.notifications.get(timeout=.1)
            except queue.Empty:
                continue
            try:
                success = bool(self.notifier(r))
            except Exception:
                success = False
            if r['state'] == 'pending':
                with self.lock:
                    if r['id'] in self.leases.records:
                        self.leases.records[r['id']]['notified'] = success
                        self.leases.save()

    def watch(self):
        while not self.stopped.wait(.05):
            with self.lock:
                try:
                    self.leases.expire()
                    for r in self.leases.records.values():
                        self.emit(r)
                    for rid, job in list(self.jobs.values()):
                        if self.leases.get(rid)['state'] != 'active':
                            job.stop()
                except Exception:
                    # Storage failure must close execution authority, never continue.
                    self.stopped.set()
                    for rid, job in list(self.jobs.values()):
                        job.stop()

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.stopped.set()
        with self.lock:
            for rid, job in list(self.jobs.values()):
                job.stop()
            try:
                for rid in list(self.leases.records):
                    self.leases.revoke(rid)
            except AccessError:
                pass
        for s in self.servers:
            s.shutdown()
            s.server_close()
        for t in self.threads:
            t.join(timeout=6)
        for role in ('agent', 'web'):
            self.socket(role).unlink(missing_ok=True)
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def dispatch(self, role, m):
        schemas = {
            'agent': {'request': {'mode', 'duration', 'reason'}, 'status': {'id'}, 'revoke': {'id'},
                      'safe': {'action', 'params'}, 'execute': {'command', 'stdin'}, 'script': {'stdin'}},
            'web': {'login': {'password'}, 'session': {'token'}, 'overview': {'token'}, 'view': {'token', 'id'},
                    'approve': {'token', 'csrf', 'id', 'challenge', 'password'},
                    'deny': {'token', 'csrf', 'id'}, 'revoke': {'token', 'csrf', 'id'}, 'logout': {'token', 'csrf'}}}
        op = m.get('op')
        if role not in schemas or not isinstance(op, str) or op not in schemas[role] or set(m) - schemas[role][op] - {'op'}:
            raise AccessError('operation or fields rejected')
        with self.lock:
            if self.stopped.is_set():
                raise AccessError('broker unavailable')
            if role == 'web':
                if op == 'login':
                    token, csrf = self.auth.login(m.get('password'))
                    return dict(token=token, csrf=csrf)
                token = m.get('token')
                session = self.auth.session(token)
                if op == 'session':
                    return dict(csrf=session['csrf'])
                if op == 'overview':
                    self.leases.expire()
                    records = sorted(self.leases.records.values(),
                                     key=lambda r: (r['requested_at'], r['id']), reverse=True)
                    return dict(csrf=session['csrf'], records=[dict(r) for r in records[:20]])
                if op == 'logout':
                    self.auth.check_csrf(token, m.get('csrf'))
                    del self.auth.sessions[token]
                    return {}
                rid = m.get('id')
                record = self.leases.get(rid)
                if op == 'view':
                    return dict(request=record, csrf=session['csrf'], challenge=self.auth.challenge(token, rid))
                self.auth.check_csrf(token, m.get('csrf'))
                if op == 'approve':
                    self.auth.confirm(token, m.get('csrf'), m.get('challenge'), rid, m.get('password'))
                    result = self.leases.decide(rid, 'approve')
                elif op == 'deny':
                    result = self.leases.decide(rid, 'deny')
                else:
                    result = self.revoke(rid)
                self.emit(result)
                return result
            if op == 'request':
                if time.monotonic() - self.last_request < 60:
                    raise AccessError('request temporarily rate limited')
                r = self.leases.request(m.get('mode', 'safe'), m.get('duration', self.config.default_duration), m.get('reason', ''))
                self.last_request = time.monotonic()
                self.emit(r)
                return r
            if op == 'status':
                rid = m.get('id')
                if rid is None:
                    if not self.leases.records:
                        return dict(state='none')
                    rid = next(reversed(self.leases.records))
                return self.leases.get(rid)
            if op == 'revoke':
                result = self.revoke(m.get('id'))
                self.emit(result)
                return result
            lease = self.leases.active(full=op != 'safe')
            if self.jobs:
                raise AccessError('execution concurrency limit reached')
            data = b''
            if op == 'safe':
                argv = plan(m.get('action'), m.get('params', {}), self.config)
            else:
                try:
                    supplied = base64.b64decode(m.get('stdin', ''), validate=True)
                except (ValueError, TypeError):
                    raise AccessError('invalid stdin') from None
                if op == 'execute':
                    command = m.get('command')
                    if not isinstance(command, str) or not command or '\x00' in command:
                        raise AccessError('invalid command')
                    script, payload = command.encode(), supplied
                else:
                    if not self.config.enable_script:
                        raise AccessError('script action disabled')
                    script, payload = supplied, b''
                if len(script) + len(payload) > self.config.max_input:
                    raise AccessError('stdin or command too large')
                data = json.dumps(dict(script=base64.b64encode(script).decode(), stdin=base64.b64encode(payload).decode())).encode()
                import sys
                argv = [str(Path(sys.executable).absolute()), '-I', '-m', 'host_access.full_exec']
            deadline = min(self.leases.deadlines[lease['id']], time.monotonic() + self.config.execution_timeout)
            if op == 'safe':
                data = json.dumps(dict(admit=True, deadline=deadline)).encode()
            else:
                envelope = json.loads(data)
                envelope['deadline'] = deadline
                data = json.dumps(envelope).encode()
            job = self.backend.start(argv, deadline=deadline, max_output=self.config.max_output)
            if self.leases.get(lease['id'])['state'] != 'active' or time.monotonic() >= deadline:
                job.stop()
                raise AccessError('lease expired during admission')
            jid = id(job)
            self.jobs[jid] = (lease['id'], job)
            self.audit('execution-started', lease)
        try:
            result = job.wait(data)
            with self.lock:
                self.audit('execution-finished', self.leases.get(lease['id']), exitcode=result['exitcode'])
            return result
        finally:
            with self.lock:
                self.jobs.pop(jid, None)

    def revoke(self, rid):
        r = self.leases.revoke(rid)
        for job_rid, job in list(self.jobs.values()):
            if job_rid == rid:
                job.stop()
        return r


def main():
    if os.geteuid() != 0:
        raise SystemExit('broker requires root')
    c = load()
    from .notify import Gotify
    b = Broker(c, notifier=Gotify(c) if c.gotify_url else None)
    b.start()
    signal.signal(signal.SIGTERM, lambda *_: b.stopped.set())
    signal.signal(signal.SIGINT, lambda *_: b.stopped.set())
    try:
        while not b.stopped.wait(.2):
            pass
    finally:
        b.close()


if __name__ == '__main__':
    main()
