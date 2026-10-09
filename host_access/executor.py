"""Bounded I/O and deadlines. Production has no non-systemd fallback."""
import os
import selectors
import signal
import subprocess
import time
import uuid
from .safe_actions import ENV


class ExecutionError(ValueError):
    pass


class Job:
    def __init__(self, process, deadline, max_output, stopper):
        self.process, self.deadline, self.max_output, self.stopper = process, deadline, max_output, stopper

    def stop(self):
        self.stopper()

    def wait(self, data):
        p = self.process
        out, err, written, truncated = bytearray(), bytearray(), 0, False
        selector = selectors.DefaultSelector()
        for stream in (p.stdout, p.stderr, p.stdin):
            os.set_blocking(stream.fileno(), False)
        selector.register(p.stdout, selectors.EVENT_READ, out)
        selector.register(p.stderr, selectors.EVENT_READ, err)
        if data:
            selector.register(p.stdin, selectors.EVENT_WRITE, None)
        else:
            p.stdin.close()
        killed_at = None
        try:
            while selector.get_map():
                if time.monotonic() >= self.deadline and killed_at is None:
                    self.stop()
                    killed_at = time.monotonic()
                if killed_at is not None and time.monotonic() - killed_at > 3:
                    break
                for key, _ in selector.select(0.05):
                    stream = key.fileobj
                    if key.data is None:
                        try:
                            written += os.write(stream.fileno(), data[written:written+8192])
                        except BrokenPipeError:
                            written = len(data)
                        if written == len(data):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        chunk = os.read(stream.fileno(), 8192)
                        if not chunk:
                            selector.unregister(stream)
                            stream.close()
                            continue
                        remaining = max(0, self.max_output - len(out) - len(err))
                        key.data.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            truncated = True
                            if killed_at is None:
                                self.stop()
                                killed_at = time.monotonic()
            while p.poll() is None and killed_at is None:
                if time.monotonic() >= self.deadline:
                    self.stop()
                    killed_at = time.monotonic()
                    break
                time.sleep(.02)
            try:
                code = p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.stop()
                p.kill()
                code = p.wait(timeout=3)
            import base64
            return dict(stdout=out.decode(errors='replace'), stderr=err.decode(errors='replace'),
                        stdout_b64=base64.b64encode(out).decode(), stderr_b64=base64.b64encode(err).decode(),
                        exitcode=code, truncated=truncated)
        finally:
            selector.close()
            # Kill descendants even if main command exits leaving inherited pipes closed.
            self.stop()
            for stream in (p.stdin, p.stdout, p.stderr):
                if not stream.closed:
                    stream.close()


class LocalTestBackend:
    """Explicit injection for unprivileged integration tests ONLY; not a CLI option."""
    def cleanup(self):
        pass

    def start(self, argv, *, deadline, max_output):
        if deadline <= time.monotonic():
            raise ExecutionError('deadline expired')
        p = subprocess.Popen(argv, env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
        def stop():
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        return Job(p, deadline, max_output, stop)


class SystemdBackend:
    prefix = 'pha-exec-'

    def arguments(self, unit, argv, seconds):
        return ['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect', '--service-type=exec',
                '--unit=' + unit, '--property=KillMode=control-group', '--property=TimeoutStopSec=2',
                '--property=SendSIGKILL=yes', '--property=Restart=no',
                '--property=RuntimeMaxSec=' + format(seconds, '.3f'),
                '--property=WorkingDirectory=/', '--setenv=PATH=' + ENV['PATH'],
                '--setenv=LANG=C.UTF-8', '--setenv=HOME=/', '--', *argv]

    def control(self, *args):
        return subprocess.run(['/usr/bin/systemctl', *args], env=ENV, stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=5)

    def cleanup(self):
        r = self.control('list-units', '--all', '--no-legend', '--plain', self.prefix + '*.service')
        if r.returncode:
            raise ExecutionError('systemd unavailable; no fallback')
        for line in r.stdout.decode().splitlines():
            unit = line.split()[0]
            if unit.startswith(self.prefix) and unit.endswith('.service'):
                result = self.control('stop', unit)
                if result.returncode:
                    raise ExecutionError('tracked unit cleanup failed; authority closed')

    def start(self, argv, *, deadline, max_output):
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise ExecutionError('deadline expired')
        unit = self.prefix + uuid.uuid4().hex + '.service'
        p = subprocess.Popen(self.arguments(unit, argv, seconds), env=ENV, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        def stop():
            try:
                self.control('kill', '--kill-whom=all', '--signal=KILL', unit)
                self.control('stop', unit)
            finally:
                if p.poll() is None:
                    p.kill()
        # Serialize admission until systemd has acknowledged the unit. This closes
        # the stop-before-unit-creation race; very short-lived units can already exit.
        until = min(deadline, time.monotonic() + 5)
        try:
            while time.monotonic() < until:
                if p.poll() is not None:
                    # A short valid command can already have failed/exited. Return
                    # its real I/O/status, never mistake that for startup failure.
                    break
                r = self.control('show', unit, '--property=ActiveState', '--value')
                if r.returncode == 0 and r.stdout.strip() in {b'active', b'activating', b'deactivating', b'failed'}:
                    break
                time.sleep(0.02)
            else:
                raise ExecutionError('systemd startup deadline exceeded')
        except Exception:
            try:
                stop()
                p.wait(timeout=3)
            finally:
                for stream in (p.stdin, p.stdout, p.stderr):
                    stream.close()
            raise
        return Job(p, deadline, max_output, stop)
