import sys
import time
from host_access.executor import LocalTestBackend, SystemdBackend


def test_actual_stdio_exit_and_output_limit():
    backend = LocalTestBackend()
    job = backend.start([sys.executable, '-c', 'import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data); sys.stderr.write("err"); sys.exit(7)'], deadline=time.monotonic()+3, max_output=1024)
    result = job.wait(b'hello')
    import base64
    assert result == dict(stdout='hello', stderr='err', stdout_b64=base64.b64encode(b'hello').decode(),
                          stderr_b64=base64.b64encode(b'err').decode(), exitcode=7, truncated=False)
    job = backend.start([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())'],
                        deadline=time.monotonic()+3, max_output=1024)
    binary = bytes(range(256))
    assert base64.b64decode(job.wait(binary)['stdout_b64']) == binary
    job = backend.start([sys.executable, '-c', 'print("x"*100000)'], deadline=time.monotonic()+3, max_output=1024)
    result = job.wait(b'')
    assert result['truncated'] and len(result['stdout']) <= 1024


def test_expiry_kills_real_background_descendant(tmp_path):
    marker = tmp_path / 'escape'
    script = 'import subprocess,time; subprocess.Popen(["/bin/sh","-c", "sleep 1; touch '+str(marker)+'"]); time.sleep(5)'
    backend = LocalTestBackend()
    job = backend.start([sys.executable, '-c', script], deadline=time.monotonic()+0.2, max_output=1024)
    result = job.wait(b'')
    assert result['exitcode'] != 0
    time.sleep(1.1)
    assert not marker.exists()


def test_process_with_closed_output_obeys_its_deadline_not_three_seconds():
    backend = LocalTestBackend()
    job = backend.start(['/bin/sh','-c','exec 1>&- 2>&-; sleep 4; exit 0'],
                        deadline=time.monotonic()+5,max_output=1024)
    assert job.wait(b'')['exitcode'] == 0


def test_safe_worker_cannot_execute_before_admission(monkeypatch):
    import io
    from host_access import safe_actions
    monkeypatch.setattr(sys,'stdin',io.TextIOWrapper(io.BytesIO(b'')))
    monkeypatch.setattr(sys,'argv',['worker','host-summary','{}'])
    def premature_load():
        raise AssertionError('policy accessed before admission')
    monkeypatch.setattr(safe_actions,'load',premature_load)
    assert safe_actions.main() == 1


def test_systemd_cleanup_failure_is_closed(monkeypatch):
    from types import SimpleNamespace
    from host_access.executor import ExecutionError
    import pytest
    backend = SystemdBackend()
    def control(*args):
        if args[0] == 'list-units':
            return SimpleNamespace(returncode=0,stdout=b'pha-exec-old.service loaded active running test\n')
        return SimpleNamespace(returncode=1,stdout=b'')
    monkeypatch.setattr(backend,'control',control)
    with pytest.raises(ExecutionError):
        backend.cleanup()


def test_systemd_fast_nonzero_command_preserves_output(monkeypatch):
    from types import SimpleNamespace
    backend = SystemdBackend()
    monkeypatch.setattr(backend,'arguments',lambda *args: [sys.executable,'-c','import sys; print("failed-command-output"); sys.exit(7)'])
    monkeypatch.setattr(backend,'control',lambda *args: SimpleNamespace(returncode=0,stdout=b'inactive\n'))
    job = backend.start(['/unused'],deadline=time.monotonic()+2,max_output=1024)
    result = job.wait(b'')
    assert result['exitcode'] == 7 and result['stdout'] == 'failed-command-output\n'


def test_systemd_startup_timeout_closes_process_streams(monkeypatch):
    from types import SimpleNamespace
    import subprocess
    import pytest
    from host_access.executor import ExecutionError
    backend = SystemdBackend()
    processes = []
    original = subprocess.Popen
    def spawn(*args,**kwargs):
        p = original(*args,**kwargs)
        processes.append(p)
        return p
    monkeypatch.setattr(subprocess,'Popen',spawn)
    monkeypatch.setattr(backend,'arguments',lambda *args: [sys.executable,'-c','import time; time.sleep(10)'])
    monkeypatch.setattr(backend,'control',lambda *args: SimpleNamespace(returncode=0,stdout=b'inactive\n'))
    with pytest.raises(ExecutionError):
        backend.start(['/unused'],deadline=time.monotonic()+.05,max_output=1024)
    assert all(stream.closed for stream in (processes[0].stdin,processes[0].stdout,processes[0].stderr))
    assert processes[0].poll() is not None


def test_systemd_plan_is_fixed_supervised_no_command_in_arguments():
    backend = SystemdBackend()
    argv = backend.arguments('pha-exec-test', ['/bin/sh', '-s'], 1.5)
    assert '--pipe' in argv and '--wait' in argv
    assert '--property=KillMode=control-group' in argv
    assert '--property=RuntimeMaxSec=1.500' in argv
    assert argv[-2:] == ['/bin/sh', '-s']
    assert not hasattr(backend, 'fallback')
