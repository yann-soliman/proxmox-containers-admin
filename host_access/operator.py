"""Operator-only credential bootstrap/recovery; never take secrets in arguments."""
import getpass
import os
import sys
from pathlib import Path
from .auth import Auth
from .config import load, protected
from .executor import SystemdBackend


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise SystemExit('operator command requires root: bootstrap | change-password | enroll-passkey | cleanup')
    action = sys.argv[1]
    if action == 'cleanup':
        SystemdBackend().cleanup()
        return
    if action not in {'bootstrap', 'change-password', 'enroll-passkey'}:
        raise SystemExit('unknown operator action')
    c = load()
    try:
        tty = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY)
        os.close(tty)
    except OSError:
        raise SystemExit('interactive operator terminal required; no echoed stdin fallback') from None
    if action == 'enroll-passkey':
        if c.auth_mode == 'password':
            raise SystemExit('enable migration mode before enrolling a passkey')
        from .passkeys import issue_enrollment_code
        code = issue_enrollment_code(Path(c.state_dir))
        # Print to the human console, never to systemd/journald or a pipe.
        with open('/dev/tty', 'w') as tty:
            print(f'Open {c.origin}/passkeys/enroll and enter within 5 minutes: {code}', file=tty)
        return
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
