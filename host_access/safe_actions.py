"""Closed diagnostic catalogue. No client paths, shell or extra argv."""
import json
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from .config import load
from .leases import AccessError

CATALOGUE = frozenset(('host-summary cpu-memory process-summary disk-usage disk-layout '
    'directory-usage journal-usage pve-storage-status zfs-health lvm-summary disk-health '
    'hardware-temperatures service-status failed-units service-logs network-summary '
    'listening-ports time-status pve-node-health guest-summary task-summary backup-schedule-summary').split())
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
       'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0', 'HOME': '/'}


def validate(action, params, c):
    if action not in CATALOGUE or not isinstance(params, dict):
        raise AccessError('unknown safe action')
    allowed = {'directory-usage': {'root', 'depth'}, 'disk-health': {'device'},
               'service-status': {'service'}, 'service-logs': {'service', 'lines', 'minutes'},
               'task-summary': {'limit'}}.get(action, set())
    if set(params) - allowed:
        raise AccessError('unknown argument')
    for key, upper in [('depth', 3), ('lines', 200), ('minutes', 60), ('limit', 50)]:
        if key in params and (type(params[key]) is not int or not 1 <= params[key] <= upper):
            raise AccessError('argument out of bounds')
    for key, resources in [('root', c.directories), ('device', c.devices), ('service', c.log_services if action == 'service-logs' else c.services)]:
        if key in params and (not isinstance(params[key], str) or params[key] not in resources):
            raise AccessError('resource not allowed')


def plan(action, params, c):
    validate(action, params, c)
    # Worker reloads the root-owned policy; clients cannot supply a config path.
    return [str(Path(sys.executable).absolute()), '-I', '-m', 'host_access.safe_actions', action, json.dumps(params, separators=(',', ':'))]


LOCAL_FILESYSTEMS = {'ext2', 'ext3', 'ext4', 'xfs', 'zfs', 'btrfs', 'tmpfs', 'vfat'}


def mount_table():
    import re
    escapes = {'040':' ', '011':'\t', '012':'\n', '134':'\\'}
    rows = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        parts = line.split()
        sep = parts.index('-')
        path = re.sub(r'\\(040|011|012|134)', lambda m: escapes[m[1]], parts[4])
        rows.append(dict(id=int(parts[0]), path=path, type=parts[sep+1]))
    return rows


def directory_usage(root, depth=2, max_entries=10000, timeout=5):
    root = Path(root)
    if not root.is_absolute() or '..' in root.parts or not 1 <= depth <= 3:
        raise AccessError('invalid directory root or depth')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        for component in root.parts[1:]:
            new = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = new
    except OSError as exc:
        os.close(fd)
        raise AccessError('directory is not a canonical local root') from exc
    start = time.monotonic()
    device = os.fstat(fd).st_dev
    def mount_id(descriptor):
        for line in Path('/proc/self/fdinfo/' + str(descriptor)).read_text().splitlines():
            if line.startswith('mnt_id:'):
                return int(line.split()[1])
        raise AccessError('mount boundary unavailable')
    root_mount = mount_id(fd)
    boundaries = {row['path'] for row in mount_table() if row['path'] != str(root)}
    total, entries, skipped = 0, 0, 0
    truncated = False
    levels, seen = [], set()
    def scan(descriptor, relative, level):
        nonlocal total, entries, skipped, truncated
        row = dict(level=level, path=relative, bytes=0)
        levels.append(row)
        try:
            with os.scandir(descriptor) as iterator:
                for entry in iterator:
                    if entries >= max_entries or time.monotonic() - start >= timeout:
                        truncated = True
                        break
                    entries += 1
                    s = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(s.st_mode) or s.st_dev != device:
                        skipped += 1
                    elif stat.S_ISREG(s.st_mode):
                        if (s.st_dev, s.st_ino) not in seen:
                            seen.add((s.st_dev, s.st_ino))
                            total += s.st_size
                            row['bytes'] += s.st_size
                    elif stat.S_ISDIR(s.st_mode):
                        child_relative = entry.name if relative == '.' else relative+'/'+entry.name
                        if str(root/child_relative) in boundaries:
                            # Opening an autofs mount could activate remote storage.
                            skipped += 1
                            continue
                        if level >= depth:
                            skipped += 1
                            continue
                        child = os.open(entry.name, flags, dir_fd=descriptor)
                        try:
                            # Different mount IDs also reject same-device bind mounts.
                            if os.fstat(child).st_dev != device or mount_id(child) != root_mount:
                                skipped += 1
                            else:
                                scan(child, entry.name if relative == '.' else relative+'/'+entry.name, level+1)
                        finally:
                            os.close(child)
                    if truncated:
                        break
        except OSError:
            skipped += 1
    try:
        scan(fd, '.', 0)
    finally:
        os.close(fd)
    return dict(bytes=total, entries=entries, skipped=skipped, truncated=truncated,
                directories=levels[:1000], depth=depth)


def command(argv):
    if not Path(argv[0]).is_file():
        return dict(available=False, reason='optional dependency unavailable')
    from .executor import Job
    try:
        process = subprocess.Popen(argv, env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = Job(process, time.monotonic()+10, 262144, lambda: process.kill() if process.poll() is None else None).wait(b'')
    except (OSError, subprocess.TimeoutExpired):
        return dict(available=False, reason='diagnostic unavailable or timed out')
    if result['exitcode'] and not result['truncated']:
        return dict(available=False, reason='diagnostic failed or timed out', exitcode=result['exitcode'])
    return dict(available=True, output=result['stdout'], truncated=result['truncated'])


def pve(endpoint, fields, limit=50, api_limit=False):
    argv = ['/usr/bin/pvesh', 'get', endpoint, '--output-format', 'json']
    if api_limit:
        argv += ['--limit', str(limit)]
    r = command(argv)
    if not r['available']:
        return r
    try:
        data = json.loads(r['output'])
        if isinstance(data, dict):
            data = [data]
        return dict(available=True, rows=[{k: row[k] for k in fields if k in row} for row in data[:limit]])
    except (ValueError, TypeError):
        return dict(available=False, reason='invalid diagnostic response')


def local_usage(resources):
    if not resources:
        return dict(available=False, reason='local resources not configured')
    mounts = mount_table()
    def check_local(path):
        candidates = [m for m in mounts if path == m['path'] or path.startswith(m['path'].rstrip('/')+'/')]
        if not candidates or max(candidates, key=lambda m:len(m['path']))['type'] not in LOCAL_FILESYSTEMS:
            raise AccessError('nonlocal or unsupported filesystem')
    rows = []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    for name, path in resources.items():
        p = Path(path)
        if not p.is_absolute() or '..' in p.parts:
            raise AccessError('invalid resource path')
        # Classify every ancestor BEFORE touching it. No resolve/stat on autofs,
        # remote paths, or symlink targets; final statvfs uses a pinned descriptor.
        check_local('/')
        fd = os.open('/', flags)
        try:
            cursor = Path('/')
            for component in p.parts[1:]:
                cursor /= component
                check_local(str(cursor))
                new = os.open(component, flags, dir_fd=fd)
                os.close(fd)
                fd = new
            info = Path('/proc/self/fdinfo/'+str(fd)).read_text()
            mount_id = int(next(line.split()[1] for line in info.splitlines() if line.startswith('mnt_id:')))
            if not any(m['id'] == mount_id and m['type'] in LOCAL_FILESYSTEMS for m in mounts):
                raise AccessError('resource mount changed or unsupported')
            s = os.fstatvfs(fd)
        except OSError as exc:
            raise AccessError('noncanonical or unavailable local resource') from exc
        finally:
            os.close(fd)
        rows.append(dict(resource=name, total=s.f_blocks*s.f_frsize, free=s.f_bavail*s.f_frsize,
                         used=(s.f_blocks-s.f_bfree)*s.f_frsize,
                         inodes=s.f_files, free_inodes=s.f_favail))
    return dict(available=True, rows=rows)


def run_action(action, params, c):
    validate(action, params, c)
    unavailable = dict(available=False, reason='resource not configured')
    if action == 'host-summary':
        return dict(available=True, hostname=socket.gethostname(), kernel=os.uname().release,
                    os=Path('/etc/os-release').read_text()[:4096], uptime=Path('/proc/uptime').read_text().split()[0],
                    boot_unix_time=int(next(line.split()[1] for line in Path('/proc/stat').read_text().splitlines() if line.startswith('btime '))),
                    pve=command(['/usr/bin/pveversion']))
    if action == 'cpu-memory':
        return dict(available=True, cpu=command(['/usr/bin/lscpu', '-J']),
                    memory=Path('/proc/meminfo').read_text(), load=Path('/proc/loadavg').read_text(),
                    pressure={p.name: p.read_text()[:2048] for p in Path('/proc/pressure').glob('*')})
    if action == 'process-summary':
        return command(['/usr/bin/ps', '-eo', 'pid,uid,comm:32,pcpu,pmem', '--sort=-pcpu'])
    if action in {'disk-usage', 'pve-storage-status'}:
        # Never invoke pvesm status: it can activate configured remote storages.
        return local_usage(c.filesystems if action == 'disk-usage' else c.storage_paths)
    if action == 'disk-layout':
        return command(['/usr/bin/lsblk', '--json', '--output', 'NAME,TYPE,SIZE,MOUNTPOINTS', '--bytes'])
    if action == 'directory-usage':
        if 'root' not in params:
            return unavailable
        root = c.directories[params['root']]
        local_usage({params['root']: root})
        return dict(available=True, **directory_usage(root, params.get('depth', 2)))
    if action == 'journal-usage':
        return command(['/usr/bin/journalctl', '--disk-usage'])
    if action == 'zfs-health':
        status = command(['/usr/sbin/zpool', 'status', '-p'])
        capacity = command(['/usr/sbin/zpool', 'list', '-Hp', '-o', 'name,size,alloc,free,cap,health'])
        return dict(available=status['available'] or capacity['available'], status=status, capacity=capacity,
                    reason='' if status['available'] or capacity['available'] else 'ZFS reports unavailable')
    if action == 'lvm-summary':
        reports = {name: command(['/usr/sbin/' + name, '--readonly', '--reportformat', 'json', '-o', fields]) for name, fields in
                   [('pvs', 'pv_name,pv_size,pv_free'), ('vgs', 'vg_name,vg_size,vg_free'), ('lvs', 'lv_name,vg_name,lv_size,data_percent,metadata_percent')]}
        return dict(available=any(r['available'] for r in reports.values()), reports=reports, reason='optional LVM reports')
    if action == 'disk-health':
        if 'device' not in params:
            return unavailable
        device = c.devices[params['device']]
        if Path(device).resolve() != Path(device) or not stat.S_ISBLK(os.stat(device).st_mode):
            raise AccessError('invalid device')
        return command(['/usr/sbin/smartctl', '-H', '-A', '--', device])
    if action == 'hardware-temperatures':
        rows = []
        for pattern, field in [('hwmon*/temp*_input', 'millidegrees'), ('hwmon*/fan*_input', 'rpm')]:
            for p in Path('/sys/class/hwmon').glob(pattern):
                try:
                    rows.append(dict(sensor=p.parent.name + '/' + p.name, **{field:int(p.read_text())}))
                except (ValueError, OSError):
                    pass
        return dict(available=bool(rows), rows=rows)
    if action == 'service-status':
        if 'service' not in params:
            return unavailable
        return command(['/usr/bin/systemctl', 'show', '--no-pager', '--property=Id,ActiveState,SubState,Result', '--', params['service']])
    if action == 'failed-units':
        result = command(['/usr/bin/systemctl', 'list-units', '--failed', '--no-legend', '--no-pager', '--plain'])
        if not result['available']:
            return result
        rows = []
        for line in result['output'].splitlines()[:200]:
            fields = line.split()
            if len(fields) >= 4:
                rows.append(dict(zip(('name', 'load', 'active', 'sub'), fields[:4])))
        return dict(available=True, rows=rows)
    if action == 'service-logs':
        if 'service' not in params:
            return unavailable
        return command(['/usr/bin/journalctl', '--no-pager', '--unit=' + params['service'],
                        '--lines=' + str(params.get('lines', 100)), '--since=-' + str(params.get('minutes', 15)) + 'min', '--output=short-iso'])
    if action == 'network-summary':
        return dict(available=True, interfaces=command(['/usr/sbin/ip', '-j', '-s', 'address', 'show']),
                    routes=command(['/usr/sbin/ip', '-j', 'route', 'show']))
    if action == 'listening-ports':
        import re
        result = command(['/usr/bin/ss', '-H', '-lntup'])
        if not result['available']:
            return result
        rows = []
        for line in result['output'].splitlines()[:1000]:
            fields = line.split()
            if len(fields) >= 6:
                rows.append(dict(protocol=fields[0], state=fields[1], address=fields[4],
                                 processes=re.findall(r'\("([^"\n]{1,64})",pid=\d+,fd=\d+\)', line)))
        return dict(available=True, rows=rows, truncated=result.get('truncated', False))
    if action == 'time-status':
        return command(['/usr/bin/timedatectl', 'show', '--property=Timezone,NTPSynchronized,NTP,TimeUSec'])
    if action == 'pve-node-health':
        return pve('/cluster/status', ['type', 'name', 'online', 'quorate', 'nodes', 'local', 'level'])
    if action == 'guest-summary':
        return pve('/cluster/resources', ['vmid', 'name', 'type', 'status', 'node'])
    if action == 'task-summary':
        return pve('/nodes/' + socket.gethostname() + '/tasks', ['type', 'id', 'starttime', 'endtime', 'status'], params.get('limit', 20), api_limit=True)
    if action == 'backup-schedule-summary':
        return pve('/cluster/backup', ['id', 'schedule', 'enabled', 'vmid', 'node', 'all', 'exclude'])
    raise AccessError('unimplemented action')


def main():
    try:
        # A supervised unit may not run diagnostics until the broker serialized
        # admission and supplied this gate on stdin. Failed startup has no gate.
        gate = json.loads(sys.stdin.buffer.read(4097))
        deadline = gate.get('deadline')
        if gate.get('admit') is not True or type(deadline) not in {int, float} or not time.monotonic() < deadline:
            raise AccessError('execution not admitted')
        print(json.dumps(run_action(sys.argv[1], json.loads(sys.argv[2]), load())))
    except (AccessError, OSError, ValueError):
        print(json.dumps(dict(available=False, reason='diagnostic refused or unavailable')))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
