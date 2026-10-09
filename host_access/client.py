"""Root-installed single-agent wrapper client. Not a privileged arbitrary CLI."""
import base64
import fcntl
import json
import os
import re
import select
import shlex
import stat
import sys
import time
from pathlib import Path
from .broker import rpc
from .config import load, protected
from .leases import AccessError


def trusted_agent(config, *, euid=None, sudo_uid=None):
    euid = os.geteuid() if euid is None else euid
    sudo_uid = os.environ.get('SUDO_UID', '') if sudo_uid is None else sudo_uid
    if euid != 0 or sudo_uid != str(config.agent_uid):
        raise AccessError('installed agent privilege mapping rejected')
    return config.agent


def parse_command(command, default_duration=900):
    if not isinstance(command, str) or len(command.encode()) > 65536 or '\x00' in command:
        raise AccessError('invalid wrapper command')
    if command.startswith('host-exec --stdin -- '):
        tail = command[len('host-exec --stdin -- '):]
        if not tail:
            raise AccessError('empty command')
        return dict(op='execute', command=tail, read_stdin=True)
    if command.startswith('host-exec -- '):
        tail = command[len('host-exec -- '):]
        if not tail:
            raise AccessError('empty command')
        return dict(op='execute', command=tail)
    try:
        args = shlex.split(command)
    except ValueError:
        raise AccessError('invalid command syntax') from None
    if not args:
        raise AccessError('empty command')
    action = args.pop(0)
    if action == 'host-access-request':
        match = re.fullmatch(r'host-access-request (safe|full)(?: ([0-9]{1,4}))? -- (.+)', command)
        if not match:
            raise AccessError('usage: host-access-request safe|full [seconds] -- reason')
        mode, duration, reason = match.groups()
        return dict(op='request', mode=mode, duration=int(duration) if duration else default_duration, reason=reason)
    if action in {'host-access-status', 'host-access-revoke'}:
        if len(args) > 1 or (action == 'host-access-revoke' and not args) or (args and not re.fullmatch('[0-9a-f]{32}', args[0])):
            raise AccessError('usage: host-access-status [id] / host-access-revoke id')
        return dict(op='status' if action.endswith('status') else 'revoke', **({'id':args[0]} if args else {}))
    if action == 'host-script-stdin' and not args:
        return dict(op='script')
    if action == 'host-safe' and args:
        name = args.pop(0)
        params = {}
        for item in args:
            key, sep, value = item.partition('=')
            if not sep or not value or key in params or not re.fullmatch('[a-z]+', key):
                raise AccessError('usage: host-safe action [key=value]')
            params[key] = int(value) if key in {'depth','lines','minutes','limit'} and value.isascii() and value.isdigit() else value
        return dict(op='safe', action=name, params=params)
    raise AccessError('host action rejected')


def exit_status(result):
    code = result['exitcode']
    if result.get('truncated') and code == 0:
        return 125  # Policy/output failure, not a silent successful SSH result.
    return code if 0 <= code <= 255 else 128 + min(abs(code), 127)


def receive_stdin(config, fd, *, owner=0):
    """One bounded pre-admission receiver; execution is still broker-authorized."""
    deadline = time.monotonic() + config.stdin_timeout
    runtime = protected(config.socket_dir, owner=owner, directory=True)
    lockpath = runtime/'stdin.lock'  # Never derived from a command/environment.
    if lockpath.exists() or lockpath.is_symlink():
        protected(lockpath, owner=owner)
    lockfd = os.open(lockpath, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        metadata = os.fstat(lockfd)
        if (metadata.st_uid != owner or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1 or metadata.st_mode & 0o077):
            raise AccessError('untrusted stdin lock')
        os.fchmod(lockfd, 0o600)
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AccessError('stdin reception concurrency limit reached') from None

        def check_lease(rid=None):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AccessError('stdin reception timed out')
            message = dict(op='status', **({'id': rid} if rid is not None else {}))
            lease = rpc(runtime/'agent.sock', message, timeout=min(1.0, remaining),
                        deadline=min(deadline, time.monotonic() + 1.0))
            if time.monotonic() >= deadline:
                raise AccessError('stdin reception timed out')
            if lease.get('state') != 'active' or lease.get('mode') != 'full':
                raise AccessError('no active FULL lease for stdin')
            return lease['id']

        rid = check_lease()  # Server-side check BEFORE any stdin read.
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        try:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            data = bytearray()
            next_check = time.monotonic() + .2
            while True:
                now = time.monotonic()
                if now >= deadline:
                    raise AccessError('stdin reception timed out')
                if now >= next_check:
                    check_lease(rid)  # Pin the immutable lease, never select a replacement.
                    next_check = time.monotonic() + .2
                    continue
                ready, _, _ = select.select([fd], [], [], min(deadline, next_check)-now)
                if not ready:
                    continue
                try:
                    chunk = os.read(fd, min(4096, config.max_input + 1 - len(data)))
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    check_lease(rid)
                    return bytes(data)
                data.extend(chunk)
                if len(data) > config.max_input:
                    raise AccessError('stdin too large')
        finally:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags)
    finally:
        # Do not unlink: competing processes must always lock the same inode.
        os.close(lockfd)


def main():
    try:
        c = load()
        trusted_agent(c)
        # Python -I and a root-owned installation prevent environment module hijacks.
        protected(Path(__file__).resolve(), readable_group=True)
        m = parse_command(os.environ.get('SSH_ORIGINAL_COMMAND', ''), c.default_duration)
        read_stdin = m.pop('read_stdin', False)
        if m['op'] == 'script' or read_stdin:
            if m['op'] == 'script' and not c.enable_script:
                raise AccessError('script action disabled')
            data = receive_stdin(c, sys.stdin.fileno())
            m['stdin'] = base64.b64encode(data).decode()
        r = rpc(Path(c.socket_dir)/'agent.sock', m)
        if m['op'] in {'execute', 'script', 'safe'}:
            sys.stdout.buffer.write(base64.b64decode(r['stdout_b64'], validate=True))
            sys.stderr.buffer.write(base64.b64decode(r['stderr_b64'], validate=True))
            return exit_status(r)
        print(json.dumps(r))
        return 0
    except (AccessError, OSError, ValueError):
        print('Host action refused or extension unavailable.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
