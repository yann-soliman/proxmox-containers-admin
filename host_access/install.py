"""Explicit installer; staging exercises filesystem layout without deployment."""
import argparse
import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ('proxmox-host-access-broker.service', 'proxmox-host-access-web.service')
ACCOUNT = 'proxmox-host-access'
BASE = '/opt/proxmox-host-access'
LAUNCHER = '/usr/local/libexec/proxmox-host-access-agent'


def checked(command):
    subprocess.run(command, check=True)


def target(stage, absolute):
    path = stage / absolute.lstrip('/')
    for parent in [*reversed(path.parents), path]:
        if parent.is_symlink():
            raise ValueError('symlink in installation path')
        if stage == Path('/') and parent.exists():
            metadata = parent.lstat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError('untrusted owner/permissions in installation path')
    return path


def public_directory(path):
    # mkdir(mode=...) is still filtered by the installer's restrictive umask.
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    path.mkdir(parents=True, exist_ok=True, mode=0o755)
    for directory in missing:
        directory.chmod(0o755)
    path.chmod(0o755)


def readable_runtime(directory, gid):
    # Only the code/venv tree: never touch config, credentials or state.
    # Do not follow venv interpreter/lib64 symlinks into system directories.
    for path in [directory, *directory.rglob('*')]:
        if path.is_symlink():
            continue
        if path.is_dir():
            path.chmod(0o755)
            os.chown(path, 0, 0)
        elif path.is_file():
            package_file = 'host_access' in path.relative_to(directory).parts
            executable = bool(path.stat().st_mode & 0o111)
            path.chmod(0o640 if package_file else (0o755 if executable else 0o644))
            os.chown(path, 0, gid if package_file else 0)
        else:
            raise ValueError('unexpected runtime file type')


def put(stage, absolute, data, mode, gid=None):
    p = target(stage, absolute)
    if not p.parent.exists():
        public_directory(p.parent)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
    p.chmod(mode)
    if gid is not None:
        os.chown(p, 0, gid)


def install(stage, live):
    gid = None
    if live:
        directory = target(stage, BASE)
        if directory.exists():
            raise ValueError('existing installation: uninstall first; credentials are retained')
        for service in SERVICES:
            if target(stage, '/etc/systemd/system/'+service).exists():
                raise ValueError('existing service files: review/remove partial installation first')
        if target(stage, LAUNCHER).exists():
            raise ValueError('existing launcher: review/remove partial installation first')
        try:
            account = pwd.getpwnam(ACCOUNT)
        except KeyError:
            checked(['/usr/sbin/useradd','--system','--no-create-home','--shell','/usr/sbin/nologin',ACCOUNT])
            account = pwd.getpwnam(ACCOUNT)
        if account.pw_uid == 0:
            raise ValueError('web account cannot be root')
        gid = account.pw_gid
        public_directory(directory)
        # Use only a dedicated venv; never pip/apt-install globally or start services.
        checked(['/usr/bin/python3','-m','venv',str(directory/'venv')])
        checked([str(directory/'venv/bin/python'),'-m','pip','install','setuptools==84.0.0','wheel==0.48.0'])
        checked([str(directory/'venv/bin/python'),'-m','pip','install','--no-build-isolation','-c',str(ROOT/'requirements.lock'),str(ROOT)])
        readable_runtime(directory, gid)
    else:
        public_directory(target(stage, BASE))
    for service in SERVICES:
        put(stage,'/etc/systemd/system/'+service,(ROOT/'systemd'/service).read_bytes(),0o644)
    put(stage,LAUNCHER,b'#!/bin/sh\nexec /opt/proxmox-host-access/venv/bin/python -I -m host_access.client\n',0o755)
    configdir = target(stage,'/etc/proxmox-host-access')
    configdir.mkdir(parents=True,exist_ok=True,mode=0o750)
    configdir.chmod(0o750)
    if live:
        os.chown(configdir,0,gid)
    example = (ROOT/'examples/host-access.toml').read_text()
    if live:
        example = example.replace('web_uid = 1002','web_uid = '+str(account.pw_uid))
    put(stage,'/etc/proxmox-host-access/config.toml.example',example.encode(),0o640,gid)
    state = target(stage,'/var/lib/proxmox-host-access')
    state.mkdir(parents=True,exist_ok=True,mode=0o700)
    state.chmod(0o700)
    if live:
        os.chown(state,0,0)
        checked(['/usr/bin/systemctl','daemon-reload'])
    print('Installed files only. No service enabled/started, no SSH/network changes. Configure and bootstrap manually.')


def uninstall(stage, live):
    # Validate trust paths BEFORE disabling services or executing installed code.
    directory = target(stage, BASE)
    target(stage, BASE+'/venv/bin')
    target(stage, LAUNCHER)
    for service in SERVICES:
        target(stage, '/etc/systemd/system/'+service)
    if live:
        for service in reversed(SERVICES):
            checked(['/usr/bin/systemctl','disable','--now',service])
        checked([BASE+'/venv/bin/python','-I','-m','host_access.operator','cleanup'])
    for absolute in [LAUNCHER, *('/etc/systemd/system/'+s for s in SERVICES)]:
        target(stage,absolute).unlink(missing_ok=True)
    directory = target(stage,BASE)
    if directory.exists():
        shutil.rmtree(directory)
    if live:
        checked(['/usr/bin/systemctl','daemon-reload'])
    print('Extension removed. Guest wrapper, SSH, account, credentials and state retained. Purge retained data manually after review.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation',choices=['install','uninstall'])
    parser.add_argument('--stage',type=Path,help='offline filesystem staging only; no root or systemd operations')
    args = parser.parse_args()
    live = args.stage is None
    if live and os.geteuid() != 0:
        parser.error('live installation requires root')
    stage = Path('/') if live else args.stage.absolute()
    if not live and stage == Path('/'):
        parser.error('stage must not be /')
    try:
        (install if args.operation == 'install' else uninstall)(stage,live)
    except (ValueError,OSError,subprocess.CalledProcessError) as exc:
        print('Installation operation failed: '+str(exc),file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
