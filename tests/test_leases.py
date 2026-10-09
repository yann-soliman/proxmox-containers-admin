import pytest
from host_access.leases import Leases, AccessError


def test_request_approval_expiry_and_single_use(tmp_path):
    now = [100.0]
    leases = Leases(tmp_path / 'state.json', agent='agent-a', target='node-a', clock=lambda: now[0])
    r = leases.request('safe', 900, 'inspect')
    assert r['agent'] == 'agent-a' and r['target'] == 'node-a'
    assert r['state'] == 'pending'
    with pytest.raises(AccessError):
        leases.active()
    leases.decide(r['id'], 'approve')
    assert leases.active()['mode'] == 'safe'
    with pytest.raises(AccessError):
        leases.decide(r['id'], 'approve')
    now[0] += 901
    with pytest.raises(AccessError):
        leases.active()
    assert leases.get(r['id'])['state'] == 'expired'


@pytest.mark.parametrize('mode,duration', [('root', 900), ('safe', 1801), ('safe', 0), ('safe', True)])
def test_invalid_requests(tmp_path, mode, duration):
    s = Leases(tmp_path / 'state.json', agent='a', target='n')
    with pytest.raises(AccessError):
        s.request(mode, duration, 'x')


def test_restart_revoke_and_request_quota(tmp_path):
    path = tmp_path / 'state.json'
    s = Leases(path, agent='a', target='n')
    r = s.request('full', 900, 'x')
    with pytest.raises(AccessError):
        s.request('safe', 900, 'x')
    s.decide(r['id'], 'approve')
    restarted = Leases(path, agent='a', target='n')
    assert restarted.get(r['id'])['state'] == 'revoked'
    with pytest.raises(AccessError):
        restarted.active()


def test_deny_terminal_and_corruption(tmp_path):
    path = tmp_path / 'state.json'
    s = Leases(path, agent='a', target='n')
    r = s.request('safe', 900, 'x')
    s.decide(r['id'], 'deny')
    with pytest.raises(AccessError):
        s.decide(r['id'], 'approve')
    path.write_text('broken')
    with pytest.raises(AccessError):
        Leases(path, agent='a', target='n')
