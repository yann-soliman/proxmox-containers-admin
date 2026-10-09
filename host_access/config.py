"""Root-installed configuration, never derived from client environment."""
from dataclasses import dataclass, field
from pathlib import Path
import stat
import tomllib
from urllib.parse import urlsplit

CONFIG_PATH = '/etc/proxmox-host-access/config.toml'


def protected(path, *, owner=0, directory=False, readable_group=False):
    p = Path(path)
    # Check every ancestor: no symlinks, no group/world-writable trust path.
    for ancestor in [*reversed(p.absolute().parents), p.absolute()]:
        s = ancestor.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_mode & 0o022 or s.st_uid not in {0, owner}:
            raise ValueError('untrusted path')
    s = p.lstat()
    if s.st_uid != owner or (directory and not stat.S_ISDIR(s.st_mode)):
        raise ValueError('invalid ownership or type')
    if not directory and (not stat.S_ISREG(s.st_mode) or s.st_mode & (0o007 if readable_group else 0o077)):
        raise ValueError('unprotected file')
    return p


@dataclass(frozen=True)
class Config:
    origin: str
    agent_uid: int
    web_uid: int
    agent: str = 'proxmox-agent'
    target: str = 'pve-node'
    state_dir: str = '/var/lib/proxmox-host-access'
    socket_dir: str = '/run/proxmox-host-access'
    password_file: str = '/etc/proxmox-host-access/password.hash'
    default_duration: int = 900
    maximum_duration: int = 1800
    pending_ttl: int = 300
    execution_timeout: int = 300
    max_output: int = 1048576
    max_input: int = 65536
    stdin_timeout: int = 10
    enable_script: bool = False
    audit_enabled: bool = False
    services: tuple = ()
    log_services: tuple = ()
    directories: dict = field(default_factory=dict)
    devices: dict = field(default_factory=dict)
    filesystems: dict = field(default_factory=dict)
    storage_paths: dict = field(default_factory=dict)
    gotify_url: str = ''
    gotify_token_file: str = ''
    bind: str = '127.0.0.1'
    trusted_proxy: str = '127.0.0.1'
    port: int = 8787

    def __post_init__(self):
        import ipaddress
        ipaddress.ip_address(self.bind)
        ipaddress.ip_address(self.trusted_proxy)
        if type(self.enable_script) is not bool or type(self.audit_enabled) is not bool:
            raise ValueError('enable_script and audit_enabled must be booleans')
        for path in (self.state_dir, self.socket_dir, self.password_file):
            if not Path(path).is_absolute() or '..' in Path(path).parts:
                raise ValueError('authority paths must be absolute')
        u = urlsplit(self.origin)
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.path or u.query or u.fragment:
            raise ValueError('origin must be an exact HTTPS origin')
        if type(self.agent_uid) is not int or type(self.web_uid) is not int or self.agent_uid <= 0 or self.web_uid <= 0 or self.web_uid == self.agent_uid:
            raise ValueError('distinct nonroot agent and web UIDs required')
        if not 1 <= self.default_duration <= self.maximum_duration <= 1800:
            raise ValueError('invalid duration limits')
        if not 1 <= self.execution_timeout <= 1800 or not 1024 <= self.max_output <= 4194304 or not 1 <= self.max_input <= 65536:
            raise ValueError('invalid execution bounds')
        if type(self.stdin_timeout) is not int or not 1 <= self.stdin_timeout <= 30:
            raise ValueError('invalid stdin reception timeout')
        if not 1 <= self.pending_ttl <= 900 or not 1 <= self.port <= 65535:
            raise ValueError('invalid request lifetime or port')
        for name in (self.agent, self.target):
            if not name or len(name) > 128 or any(ord(c) < 32 for c in name):
                raise ValueError('invalid identity')
        import re
        for unit in (*self.services, *self.log_services):
            if not re.fullmatch(r'[A-Za-z0-9_.@-]+\.service', unit):
                raise ValueError('invalid unit')
        for resources in (self.directories, self.devices, self.filesystems, self.storage_paths):
            for key, value in resources.items():
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', key) or not Path(value).is_absolute() or '..' in Path(value).parts:
                    raise ValueError('invalid resource')


def load(path=CONFIG_PATH, *, owner=0):
    p = protected(path, owner=owner, readable_group=True)
    with p.open('rb') as stream:
        return Config(**tomllib.load(stream))
