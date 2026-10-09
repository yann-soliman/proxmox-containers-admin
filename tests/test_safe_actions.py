import pytest
from host_access.config import Config
from host_access.safe_actions import CATALOGUE, plan, directory_usage, run_action
from host_access.leases import AccessError


def cfg(**kw):
    return Config(origin='https://example', agent_uid=123, web_uid=124, **kw)


def test_closed_catalogue_dispatches_fixed_plans():
    c = cfg()
    assert len(CATALOGUE) == 22
    for name in CATALOGUE:
        result = plan(name, {}, c)
        assert isinstance(result, list) and result[0].startswith('/')
    with pytest.raises(AccessError):
        plan('shell', {}, c)
    for name in CATALOGUE:
        with pytest.raises(AccessError):
            plan(name, {'argv': ['rm', '-rf', '/']}, c)


@pytest.mark.parametrize('name,params', [
    ('service-status', {'service': '../../evil'}),
    ('service-logs', {'service': 'pveproxy.service'}),
    ('directory-usage', {'root': '/etc', 'depth': 99}),
    ('disk-health', {'device': '/dev/sda'}),
    ('task-summary', {'limit': 10000}),
])
def test_resources_and_arguments_closed(name, params):
    with pytest.raises(AccessError):
        plan(name, params, cfg())


def test_directory_usage_bounded_no_symlinks(tmp_path):
    (tmp_path / 'a').mkdir()
    (tmp_path / 'a' / 'data').write_bytes(b'abc')
    (tmp_path / 'escape').symlink_to('/etc', target_is_directory=True)
    result = directory_usage(str(tmp_path), depth=2, max_entries=50, timeout=1)
    assert result['bytes'] == 3
    assert result['entries'] < 10
    assert result['skipped'] >= 1
    limited = directory_usage(str(tmp_path), depth=2, max_entries=1, timeout=1)
    assert limited['truncated']
    with pytest.raises(AccessError):
        directory_usage(str(tmp_path / 'escape'), depth=1)


def test_real_process_metadata_and_storage_not_probed(tmp_path):
    result = run_action('process-summary', {}, cfg())
    assert result['available'] and result['output']
    assert 'args' not in result and 'environ' not in result
    unavailable = run_action('pve-storage-status', {}, cfg())
    assert not unavailable['available']
    unavailable = run_action('service-logs', {}, cfg())
    assert not unavailable['available']


def test_directory_reports_bounded_per_level_totals(tmp_path):
    (tmp_path/'child').mkdir()
    (tmp_path/'rootfile').write_bytes(b'ab')
    (tmp_path/'child'/'childfile').write_bytes(b'123')
    result = directory_usage(str(tmp_path), depth=2)
    assert {r['path']:r['bytes'] for r in result['directories']} == {'.':2, 'child':3}


def test_directory_rejects_same_device_mount_boundary(tmp_path, monkeypatch):
    from pathlib import Path
    import os
    (tmp_path/'child').mkdir()
    (tmp_path/'rootfile').write_bytes(b'ab')
    (tmp_path/'child'/'hidden').write_bytes(b'123')
    original = Path.read_text
    def read_text(path,*args,**kwargs):
        if str(path).startswith('/proc/self/fdinfo/'):
            fd = int(path.name)
            target = os.readlink('/proc/self/fd/'+str(fd))
            return 'mnt_id: 2\n' if target == str(tmp_path/'child') else 'mnt_id: 1\n'
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_text',read_text)
    result = directory_usage(str(tmp_path), depth=2)
    assert result['bytes'] == 2 and result['skipped'] >= 1


def test_remote_and_automount_resources_rejected_before_stat(tmp_path, monkeypatch):
    from pathlib import Path
    import os
    remote = tmp_path/'mount space'
    remote.mkdir()
    original = Path.read_text
    escaped = str(remote).replace(' ',r'\040')
    for filesystem in ['nfs','autofs']:
        def read_text(path,*args,**kwargs):
            if str(path) == '/proc/self/mountinfo':
                return '1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 0:1 / '+escaped+' rw - '+filesystem+' remote rw\n'
            return original(path,*args,**kwargs)
        monkeypatch.setattr(Path,'read_text',read_text)
        def forbidden_stat(path):
            raise AssertionError('statvfs must not probe remote/automount')
        monkeypatch.setattr(os,'statvfs',forbidden_stat)
        with pytest.raises(AccessError):
            run_action('disk-usage',{},cfg(filesystems={'remote':str(remote)}))


def test_configured_local_resources_use_real_filesystem_data(tmp_path):
    from host_access.safe_actions import mount_table, LOCAL_FILESYSTEMS
    roots = [m for m in mount_table() if m['path'] == '/']
    if not roots or roots[-1]['type'] not in LOCAL_FILESYSTEMS:
        pytest.skip('test host root filesystem intentionally unsupported by safe policy')
    (tmp_path/'data').write_bytes(b'12345')
    c = cfg(filesystems={'workspace':str(tmp_path)},storage_paths={'local':str(tmp_path)},directories={'workspace':str(tmp_path)})
    for action in ['disk-usage','pve-storage-status']:
        result = run_action(action,{},c)
        assert result['available'] and result['rows'][0]['total'] > 0
        assert 0 <= result['rows'][0]['used'] <= result['rows'][0]['total']
    result = run_action('directory-usage',{'root':'workspace','depth':1},c)
    assert result['available'] and result['bytes'] == 5


def test_directory_scan_skips_known_mount_before_open(tmp_path,monkeypatch):
    from host_access import safe_actions
    import os
    child = tmp_path/'remote'
    child.mkdir()
    (child/'never-read').write_bytes(b'12345')
    monkeypatch.setattr(safe_actions,'mount_table',lambda:[dict(id=999,path=str(child),type='autofs')])
    original = os.open
    touched = []
    def open_local_only(path,*args,**kwargs):
        if path == 'remote':
            touched.append(path)
            raise AssertionError('opening the known automount could activate it')
        return original(path,*args,**kwargs)
    monkeypatch.setattr(os,'open',open_local_only)
    result = safe_actions.directory_usage(tmp_path)
    assert touched == [] and result['skipped'] == 1 and result['bytes'] == 0


def test_zfs_health_queries_both_status_and_capacity(monkeypatch):
    from host_access import safe_actions
    calls = []
    def absent(argv):
        calls.append(argv)
        return dict(available=False,reason='test: tool unavailable')
    monkeypatch.setattr(safe_actions,'command',absent)
    result = run_action('zfs-health',{},cfg())
    assert calls == [ ['/usr/sbin/zpool','status','-p'],
                      ['/usr/sbin/zpool','list','-Hp','-o','name,size,alloc,free,cap,health'] ]
    assert result['available'] is False


def test_native_command_output_is_continuously_bounded():
    from host_access.safe_actions import command
    import sys
    result = command([sys.executable, '-c', 'import os,time;\nwhile True: os.write(1,b"x"*8192); time.sleep(.02)'])
    assert result['truncated']
    assert len(result['output']) <= 262144


@pytest.mark.parametrize('action', sorted(CATALOGUE))
def test_catalogue_real_local_dispatch_returns_truthful_result(action):
    result = run_action(action, {}, cfg())
    assert type(result['available']) is bool
    if not result['available']:
        assert result.get('reason') or result.get('rows') == []
