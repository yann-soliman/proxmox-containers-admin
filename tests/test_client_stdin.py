"""Live pipe reception through the real client and peer-authenticated local broker."""
import base64
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path

import pytest
from test_broker import call, approve


BOOTSTRAP = '''
import json, os, sys
from host_access import client
from host_access.config import Config
c = Config(**json.loads(sys.argv[1]))
client.load = lambda: c
client.trusted_agent = lambda c: c.agent
protected = client.protected
client.protected = lambda p, **k: None if str(p) == client.__file__ else protected(p, **k)
if hasattr(client, 'receive_stdin'):
    receive = client.receive_stdin
    client.receive_stdin = lambda c, fd: receive(c, fd, owner=os.getuid())
sys.exit(client.main())
'''


def launch(b, command='host-exec --stdin -- cat', **config):
    c = replace(b.config, **config)
    return subprocess.Popen([sys.executable, '-I', '-c', BOOTSTRAP, json.dumps(asdict(c))],
                            env={**os.environ, 'SSH_ORIGINAL_COMMAND': command},
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def stop(p):
    if p.poll() is None:
        p.kill()
    p.communicate(timeout=2)


def full(b, pw, duration=900):
    r = call(b, 'agent', 'request', mode='full', duration=duration, reason='stdin test')
    approve(b, pw, r['id'])
    return r['id']


def test_no_lease_fails_before_reading_live_open_pipe(running):
    b, _ = running
    p = launch(b)
    try:
        assert p.wait(timeout=1.5) == 1
        assert not b.jobs
    finally:
        stop(p)


def test_binary_finite_stdin_and_direct_semantics(running):
    b, pw = running
    full(b, pw)
    data = b'\x00\xff\xfehello\n'
    p = launch(b)
    out, err = p.communicate(data, timeout=3)
    assert p.returncode == 0 and out == data and err == b''
    p = launch(b, 'host-exec -- printf direct')
    out, err = p.communicate(timeout=3)
    assert p.returncode == 0 and out == b'direct'
    p = launch(b, 'host-script-stdin')
    out, err = p.communicate(b'printf script', timeout=3)
    assert p.returncode == 0 and out == b'script'


def test_oversize_rejected_without_eof(running):
    b, pw = running
    full(b, pw)
    p = launch(b, max_input=8)
    try:
        p.stdin.write(b'x'*9)
        p.stdin.flush()
        assert p.wait(timeout=1.5) == 1
        assert not b.jobs
    finally:
        stop(p)


def test_open_pipe_has_absolute_timeout_even_with_chunks(running):
    b, pw = running
    full(b, pw)
    p = launch(b, stdin_timeout=1)
    start = time.monotonic()
    try:
        while p.poll() is None and time.monotonic()-start < 2:
            try:
                p.stdin.write(b'x')
                p.stdin.flush()
            except BrokenPipeError:
                break
            time.sleep(.08)
        assert p.wait(timeout=.3) == 1
        assert time.monotonic()-start < 2
        assert not b.jobs
    finally:
        stop(p)


@pytest.mark.parametrize('ending', ['revoke', 'expire'])
def test_lease_closure_interrupts_reception(running, ending):
    b, pw = running
    rid = full(b, pw)
    p = launch(b)
    try:
        time.sleep(.25)
        start = time.monotonic()
        if ending == 'revoke':
            call(b, 'agent', 'revoke', id=rid)
        else:
            with b.lock:
                b.leases.deadlines[rid] = time.monotonic()
        assert p.wait(timeout=1.5) == 1
        assert time.monotonic()-start < 1.5
        assert not b.jobs
    finally:
        stop(p)


def test_nonblocking_cross_process_reception_lock_and_cleanup(running):
    import fcntl
    b, pw = running
    full(b, pw)
    first = launch(b)
    lock = Path(b.config.socket_dir)/'stdin.lock'
    try:
        deadline = time.monotonic()+1
        while not lock.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert lock.exists()
        # Wait for the first client to hold the lock, not just create its inode.
        with lock.open('rb') as stream:
            while True:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(stream, fcntl.LOCK_UN)
                except BlockingIOError:
                    break
                assert time.monotonic() < deadline
                time.sleep(.01)
        second = launch(b)
        try:
            assert second.wait(timeout=1) == 1
        finally:
            stop(second)
        assert first.poll() is None
        assert lock.stat().st_mode & 0o777 == 0o600
        assert lock.stat().st_uid == os.getuid()
        first.stdin.close()
        first.stdin = None
        assert first.wait(timeout=3) == 0
        third = launch(b)
        out, _ = third.communicate(b'after', timeout=3)
        assert third.returncode == 0 and out == b'after'
    finally:
        stop(first)


@pytest.mark.parametrize('kind', ['symlink', 'permissions', 'directory', 'fifo', 'hardlink', 'runtime'])
def test_untrusted_lock_paths_fail_before_reading(running, kind, tmp_path):
    b, pw = running
    full(b, pw)
    lock = Path(b.config.socket_dir)/'stdin.lock'
    outside = tmp_path/'untouched'
    outside.write_bytes(b'private')
    outside.chmod(0o600)
    if kind == 'symlink':
        lock.symlink_to(outside)
    elif kind == 'hardlink':
        os.link(outside, lock)
    elif kind == 'directory':
        lock.mkdir()
    elif kind == 'fifo':
        os.mkfifo(lock, 0o600)
    elif kind == 'runtime':
        Path(b.config.socket_dir).chmod(0o777)
    else:
        lock.write_bytes(b'')
        lock.chmod(0o666)
    p = launch(b)
    try:
        assert p.wait(timeout=1.5) == 1
        assert outside.read_bytes() == b'private'
        assert not b.jobs
    finally:
        stop(p)
        Path(b.config.socket_dir).chmod(0o750)


def test_client_command_cannot_choose_lock_or_reception_limits():
    from host_access.client import parse_command
    from host_access.leases import AccessError
    for cmd in ['host-exec --stdin-timeout 0 -- true', 'host-script-stdin /tmp/lock',
                'host-exec --stdin /tmp/lock -- true']:
        with pytest.raises(AccessError):
            parse_command(cmd)


def test_config_reception_timeout_bounds():
    from host_access.config import Config
    for value in [0, 31, True, 1.5]:
        with pytest.raises(ValueError):
            Config(origin='https://example', agent_uid=123, web_uid=124, stdin_timeout=value)


@pytest.mark.parametrize('mode', ['safe', 'pending', 'disabled'])
def test_unsuitable_authority_refuses_live_pipe(running, mode):
    b, pw = running
    lease_mode = 'safe' if mode == 'safe' else 'full'
    rid = call(b, 'agent', 'request', mode=lease_mode, duration=900, reason='reject input')['id']
    if mode != 'pending':
        approve(b, pw, rid)
    p = launch(b, 'host-script-stdin' if mode == 'disabled' else 'host-exec --stdin -- true',
               enable_script=mode != 'disabled')
    try:
        assert p.wait(timeout=1.5) == 1
        assert not b.jobs
    finally:
        stop(p)


def test_authorization_before_read_and_fd_cleanup(running, monkeypatch):
    import fcntl
    from host_access import client
    from host_access.leases import AccessError
    b, pw = running
    readfd, writefd = os.pipe()
    flags = fcntl.fcntl(readfd, fcntl.F_GETFL)
    original_read = os.read
    reads = []

    def read(fd, size):
        reads.append(fd)
        return original_read(fd, size)

    monkeypatch.setattr(client.os, 'read', read)
    try:
        with pytest.raises(AccessError, match='no active FULL'):
            client.receive_stdin(b.config, readfd, owner=os.getuid())
        assert reads == []
        assert fcntl.fcntl(readfd, fcntl.F_GETFL) == flags
        full(b, pw)
        os.write(writefd, b'too large')
        with pytest.raises(AccessError, match='too large'):
            client.receive_stdin(replace(b.config, max_input=1), readfd, owner=os.getuid())
        assert reads == [readfd]
        assert fcntl.fcntl(readfd, fcntl.F_GETFL) == flags
        # Failure closes the lock descriptor, not just successful EOF.
        lock = Path(b.config.socket_dir)/'stdin.lock'
        with lock.open('rb') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(readfd)
        os.close(writefd)


def test_production_receiver_requires_root_owner(running):
    from host_access.client import receive_stdin
    b, _ = running
    readfd, writefd = os.pipe()
    try:
        with pytest.raises(ValueError, match='untrusted|ownership'):
            receive_stdin(b.config, readfd)  # No test-only owner override.
    finally:
        os.close(readfd)
        os.close(writefd)


@pytest.mark.parametrize('trickle', [False, True])
def test_status_rpc_total_deadline_with_open_socket(tmp_path, trickle):
    import socket
    import threading
    from host_access.broker import rpc
    from host_access.leases import AccessError
    path = tmp_path/'slow.sock'
    stopped = threading.Event()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        listener.listen(1)

        def serve():
            connection, _ = listener.accept()
            with connection:
                connection.recv(4096)
                while not stopped.wait(.03):
                    if trickle:
                        try:
                            connection.sendall(b' ')
                        except OSError:
                            break

        thread = threading.Thread(target=serve)
        thread.start()
        start = time.monotonic()
        try:
            with pytest.raises((OSError, AccessError)):
                rpc(path, {'op': 'status'}, timeout=.15, deadline=start+.3)
            assert time.monotonic()-start < .6
        finally:
            stopped.set()
            thread.join(1)
            assert not thread.is_alive()


def test_regular_file_stdin(running, tmp_path):
    b, pw = running
    full(b, pw)
    source = tmp_path/'input'
    source.write_bytes(base64.b64decode('AP9maWxl'))
    c = b.config
    with source.open('rb') as stream:
        p = subprocess.run([sys.executable, '-I', '-c', BOOTSTRAP, json.dumps(asdict(c))],
                           env={**os.environ, 'SSH_ORIGINAL_COMMAND': 'host-exec --stdin -- cat'},
                           stdin=stream, capture_output=True, timeout=3)
    assert p.returncode == 0 and p.stdout == source.read_bytes()
