import secrets
import pytest
from host_access.auth import Auth
from host_access.leases import AccessError


def test_session_confirmation_and_bounded_rate_limit(tmp_path):
    password = secrets.token_urlsafe(32)
    p = tmp_path / 'password.hash'
    Auth.bootstrap(p, password)
    assert password not in p.read_text() and p.read_text().startswith('$argon2id$')
    assert p.stat().st_mode & 0o777 == 0o600
    now = [0.0]
    auth = Auth(p, clock=lambda: now[0])
    with pytest.raises(AccessError):
        auth.login('incorrect')
    token, csrf = auth.login(password)
    challenge = auth.challenge(token, 'request-1')
    with pytest.raises(AccessError):
        auth.confirm(token, csrf, challenge, 'request-2', password)
    challenge = auth.challenge(token, 'request-1')
    auth.confirm(token, csrf, challenge, 'request-1')
    challenge = auth.challenge(token, 'request-1')
    auth.confirm(token, csrf, challenge, 'request-1', password)
    with pytest.raises(AccessError):
        auth.confirm(token, csrf, challenge, 'request-1', password)
    for _ in range(8):
        with pytest.raises(AccessError):
            auth.login('incorrect')
    with pytest.raises(AccessError):
        auth.login(password)
    now[0] += 61
    assert auth.login(password)
    now[0] += 901
    with pytest.raises(AccessError):
        auth.session(token)


def test_no_public_bootstrap_and_csrf(tmp_path):
    p = tmp_path / 'hash'
    pw = secrets.token_urlsafe(32)
    Auth.bootstrap(p, pw)
    with pytest.raises(FileExistsError):
        Auth.bootstrap(p, pw)
    a = Auth(p)
    token, csrf = a.login(pw)
    with pytest.raises(AccessError):
        a.check_csrf(token, 'wrong')
    a.check_csrf(token, csrf)
