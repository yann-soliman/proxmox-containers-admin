"""Operator-only password bootstrap/recovery; secrets exclusively via getpass."""
import getpass
import os
import sys
from pathlib import Path
from .auth import Auth
from .config import load, protected
from .executor import SystemdBackend


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise SystemExit('operator command requires root: bootstrap | change-password | cleanup')
    action = sys.argv[1]
    if action == 'cleanup':
        SystemdBackend().cleanup()
        return
    if action not in {'bootstrap', 'change-password'}:
        raise SystemExit('unknown operator action')
    c = load()
    try:
        tty = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY)
        os.close(tty)
    except OSError:
        raise SystemExit('interactive operator terminal required; no echoed stdin fallback') from None
    p = Path(c.password_file)
    protected(p.parent, directory=True)
    if action == 'bootstrap' and (p.exists() or p.is_symlink()):
        raise SystemExit('password already initialized; use change-password')
    if action == 'change-password':
        protected(p)
    # Stop sessions and leases BEFORE changing credentials. Restart remains manual.
    backend = SystemdBackend()
    for service in ('proxmox-host-access-web.service', 'proxmox-host-access-broker.service'):
        result = backend.control('stop', service)
        if result.returncode:
            raise SystemExit('could not stop authority services; no credentials changed')
    value = getpass.getpass('Operator password (16+ characters): ')
    confirmation = getpass.getpass('Confirm password: ')
    if value != confirmation:
        raise SystemExit('passwords differ')
    if action == 'bootstrap':
        Auth.bootstrap(p, value)
    else:
        temporary = p.with_name(p.name + '.replacement')
        Auth.bootstrap(temporary, value)
        os.replace(temporary, p)
    del value, confirmation
    print('Argon2id credential stored. Services remain stopped; start them explicitly.')


if __name__ == '__main__':
    main()
