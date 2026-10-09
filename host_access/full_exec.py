"""Full-mode worker: script travels via stdin/memfd, never process argv/env."""
import base64
import json
import os
import subprocess
import sys
from .safe_actions import ENV


def main():
    raw = sys.stdin.buffer.read(196609)
    if len(raw) > 196608:
        return 1
    try:
        envelope = json.loads(raw)
        script = base64.b64decode(envelope['script'], validate=True)
        data = base64.b64decode(envelope['stdin'], validate=True)
        if len(script) + len(data) > 65536:
            return 1
        import time
        deadline = envelope['deadline']
        if type(deadline) not in {int, float} or not time.monotonic() < deadline:
            return 1
    except (ValueError, KeyError, TypeError):
        return 1
    fd = os.memfd_create('pha-script', flags=0)
    try:
        os.write(fd, script)
        os.lseek(fd, 0, os.SEEK_SET)
        # Script descriptor separate from payload stdin, same systemd cgroup.
        p = subprocess.Popen(['/bin/sh', '/proc/self/fd/'+str(fd)], pass_fds=(fd,), env=ENV,
                             stdin=subprocess.PIPE, stdout=sys.stdout.buffer, stderr=sys.stderr.buffer)
        p.communicate(data)
        return p.returncode if p.returncode >= 0 else 128 + min(-p.returncode, 127)
    finally:
        os.close(fd)


if __name__ == '__main__':
    sys.exit(main())
