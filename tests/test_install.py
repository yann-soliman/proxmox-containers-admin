import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_staged_installer_and_reversible_uninstaller(tmp_path):
    stage = tmp_path/'stage'
    r = subprocess.run(['bash',str(ROOT/'scripts/install-host-access.sh'),'--stage',str(stage)],capture_output=True)
    assert r.returncode == 0, r.stderr.decode()
    broker = stage/'etc/systemd/system/proxmox-host-access-broker.service'
    web = stage/'etc/systemd/system/proxmox-host-access-web.service'
    assert broker.is_file() and web.is_file()
    assert 'User=proxmox-host-access' in web.read_text()
    assert '-I -m host_access.broker' in broker.read_text()
    launcher = stage/'usr/local/libexec/proxmox-host-access-agent'
    assert launcher.stat().st_mode & 0o777 == 0o755
    assert 'host_access.client' in launcher.read_text() and '$@' not in launcher.read_text()
    config = stage/'etc/proxmox-host-access/config.toml.example'
    assert config.is_file()
    untouched = stage/'usr/local/sbin/proxmox-guest-wrapper'
    untouched.parent.mkdir(parents=True,exist_ok=True)
    untouched.write_text('guest wrapper unchanged')
    r = subprocess.run(['bash',str(ROOT/'scripts/uninstall-host-access.sh'),'--stage',str(stage)],capture_output=True)
    assert r.returncode == 0, r.stderr.decode()
    assert not launcher.exists() and not broker.exists()
    assert untouched.read_text() == 'guest wrapper unchanged'
    assert config.exists()


def test_live_install_paths_reject_untrusted_ancestors(tmp_path):
    from host_access.install import target
    import pytest
    # Read-only check only: no root installation or account/service changes.
    with pytest.raises(ValueError):
        target(Path('/'), str(tmp_path/'privileged-launcher'))


def test_existing_install_refusal_does_not_stop_services(tmp_path,monkeypatch):
    from host_access import install as installer
    from types import SimpleNamespace
    import pytest
    (tmp_path/'opt/proxmox-host-access').mkdir(parents=True)
    unit = tmp_path/'etc/systemd/system/proxmox-host-access-web.service'
    unit.parent.mkdir(parents=True)
    unit.write_text('existing')
    operations = []
    monkeypatch.setattr(installer,'checked',lambda command:operations.append(command))
    monkeypatch.setattr(installer.pwd,'getpwnam',lambda name:SimpleNamespace(pw_uid=123,pw_gid=123))
    with pytest.raises(ValueError):
        installer.install(tmp_path,True)
    assert operations == []


def test_uninstall_refuses_symlink_before_privileged_actions(tmp_path,monkeypatch):
    from host_access import install as installer
    import pytest
    (tmp_path/'opt').mkdir()
    outside = tmp_path/'outside'
    outside.mkdir()
    (tmp_path/'opt/proxmox-host-access').symlink_to(outside,target_is_directory=True)
    operations = []
    monkeypatch.setattr(installer,'checked',lambda command:operations.append(command))
    with pytest.raises(ValueError):
        installer.uninstall(tmp_path,True)
    assert operations == [] and outside.is_dir()


def test_restrictive_umask_real_runtime(tmp_path, monkeypatch):
    import importlib.metadata
    import os
    import shutil
    import sys
    from types import SimpleNamespace
    from host_access import install as installer

    ownership = []
    monkeypatch.setattr(installer.pwd, 'getpwnam', lambda _: SimpleNamespace(pw_uid=123, pw_gid=124))
    monkeypatch.setattr(installer.os, 'chown', lambda p, uid, gid: ownership.append((Path(p), uid, gid)))
    base = tmp_path/'opt/proxmox-host-access'
    hashfile = tmp_path/'etc/proxmox-host-access/password.hash'
    hashfile.parent.mkdir(parents=True)
    hashfile.write_bytes(b'protected hash fixture')
    hashfile.chmod(0o600)
    secret = tmp_path/'var/lib/proxmox-host-access/secret.token'
    secret.parent.mkdir(parents=True)
    secret.write_bytes(b'protected token fixture')
    secret.chmod(0o600)

    def checked(command):
        if command[1:3] == ['-m', 'venv']:
            subprocess.run([sys.executable, '-m', 'venv', '--without-pip', command[-1]], check=True)
        elif 'pip' in command and str(ROOT) == command[-1]:
            site = next((base/'venv/lib').glob('python*/site-packages'))
            # Copy locally installed real runtime distributions, with restrictive modes.
            for name in ['Flask', 'Werkzeug', 'Jinja2', 'MarkupSafe', 'itsdangerous', 'click',
                         'blinker', 'argon2-cffi', 'argon2-cffi-bindings', 'cffi', 'pycparser', 'waitress']:
                dist = importlib.metadata.distribution(name)
                for entry in dist.files:
                    if '..' in entry.parts:
                        continue
                    source = Path(dist.locate_file(entry))
                    if source.is_file():
                        dest = site/entry
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(source, dest)
            shutil.copytree(ROOT/'host_access', site/'host_access', copy_function=shutil.copyfile)
        # No account/systemd/network/pip operation is executed.

    monkeypatch.setattr(installer, 'checked', checked)
    previous = os.umask(0o077)
    try:
        installer.install(tmp_path, True)
    finally:
        os.umask(previous)
    assert (tmp_path/'opt').stat().st_mode & 0o777 == 0o755
    assert base.stat().st_mode & 0o777 == 0o755
    for p in (base/'venv').rglob('*'):
        if p.is_symlink():
            continue
        mode = p.stat().st_mode & 0o777
        assert not mode & 0o022, p
        if p.is_dir():
            assert mode == 0o755, p
        elif 'host_access' in p.parts:
            assert mode == 0o640, p
        else:
            assert mode & 0o044 == 0o044, p
    assert ownership and all(uid == 0 for _, uid, _ in ownership)
    owners = {p: (uid, gid) for p, uid, gid in ownership}
    for p in [base, *base.rglob('*')]:
        if not p.is_symlink():
            expected_gid = 124 if p.is_file() and 'host_access' in p.relative_to(base).parts else 0
            assert owners[p] == (0, expected_gid), p
    assert hashfile.read_bytes() == b'protected hash fixture'
    assert secret.read_bytes() == b'protected token fixture'
    assert hashfile.stat().st_mode & 0o777 == secret.stat().st_mode & 0o777 == 0o600
    assert (tmp_path/'var/lib/proxmox-host-access').stat().st_mode & 0o777 == 0o700
    assert (tmp_path/'etc/proxmox-host-access').stat().st_mode & 0o777 == 0o750
    assert (tmp_path/'etc/proxmox-host-access/config.toml.example').stat().st_mode & 0o777 == 0o640
    result = subprocess.run([str(base/'venv/bin/python'), '-I', '-c',
                             'import flask, argon2, waitress, host_access.web'], capture_output=True)
    assert result.returncode == 0, result.stderr.decode()


def test_operator_password_bootstrap_uses_no_cli_password():
    source = (ROOT/'host_access/operator.py').read_text()
    assert 'getpass.getpass' in source
    assert 'password=' not in source
    assert 'SUDO_UID' not in source
