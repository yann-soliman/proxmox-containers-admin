"""Opt-in disposable-systemd acceptance; never enabled on production by CI."""
import os
import time
import pytest
from host_access.executor import SystemdBackend

pytestmark = pytest.mark.skipif(os.environ.get('PHA_SYSTEMD_ACCEPTANCE') != '1', reason='requires explicit disposable root/systemd acceptance')


def test_real_systemd_stdio_deadline_and_descendants(tmp_path):
    assert os.geteuid() == 0
    backend = SystemdBackend()
    backend.cleanup()
    job = backend.start(['/usr/bin/printf','systemd-benign'],deadline=time.monotonic()+5,max_output=1024)
    result = job.wait(b'')
    assert result['exitcode'] == 0 and result['stdout'] == 'systemd-benign'
    marker = tmp_path/'descendant'
    # Benign delayed write only, no adversarial root escape/persistence tests.
    script = ('(sleep 2; touch '+str(marker)+') & wait').encode()
    job = backend.start(['/bin/sh','-s'],deadline=time.monotonic()+.5,max_output=1024)
    result = job.wait(script)
    assert result['exitcode'] != 0
    time.sleep(2.1)
    assert not marker.exists()
