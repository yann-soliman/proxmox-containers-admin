"""UI integration uses ephemeral test authority, never production credentials."""
import time
from pathlib import Path

import pytest

from host_access.leases import AccessError
from host_access.web import create_app
from test_broker import call
from test_web import hidden


@pytest.fixture
def ui(running):
    b, pw = running
    app = create_app(b.config, transport=lambda m: call(b, 'web', m.pop('op'), **m))
    return b, pw, app.test_client(), b.config.origin


def sign_in(client, base, pw, rid=''):
    path = '/login' + ('?request=' + rid if rid else '')
    page = client.get(path, base_url=base)
    return client.post(path, base_url=base, headers={'Origin': base},
                       data={'csrf': hidden(page.text, 'csrf'), 'password': pw})


def test_approval_uses_authenticated_session_without_second_password(ui):
    b, pw, client, base = ui
    r = call(b, 'agent', 'request', mode='full', duration=900, reason='single login')
    assert sign_in(client, base, pw, r['id']).status_code == 303
    page = client.get('/request/' + r['id'], base_url=base)
    assert 'type="password"' not in page.text
    data = {'csrf': hidden(page.text, 'csrf'), 'challenge': hidden(page.text, 'challenge')}
    path = '/request/' + r['id'] + '/approve'
    assert client.post(path, base_url=base, headers={'Origin': base}, data=data).status_code == 303
    assert call(b, 'agent', 'status', id=r['id'])['state'] == 'active'
    assert client.post(path, base_url=base, headers={'Origin': base}, data=data).status_code == 403


@pytest.mark.parametrize('expired', [False, True])
def test_approval_without_live_session_never_grants(ui, expired):
    b, pw, client, base = ui
    r = call(b, 'agent', 'request', mode='full', duration=900, reason='session guard')
    sign_in(client, base, pw, r['id'])
    page = client.get('/request/' + r['id'], base_url=base)
    data = {'csrf': hidden(page.text, 'csrf'), 'challenge': hidden(page.text, 'challenge')}
    if expired:
        for session in b.auth.sessions.values():
            session['until'] = 0
    else:
        client.delete_cookie('pha_session', domain='approve.example')
    response = client.post('/request/' + r['id'] + '/approve', base_url=base,
                           headers={'Origin': base}, data=data)
    assert response.status_code == 403
    assert call(b, 'agent', 'status', id=r['id'])['state'] == 'pending'


def test_dashboard_login_and_private_records(ui):
    b, pw, client, base = ui
    r = call(b, 'agent', 'request', mode='safe', duration=900, reason='<script>private reason</script>')
    response = client.get('/', base_url=base)
    assert response.status_code == 303 and response.location == '/login'
    assert 'private reason' not in response.text
    response = sign_in(client, base, pw)
    assert response.location == '/'
    page = client.get('/', base_url=base)
    assert page.status_code == 200
    assert 'Operate' in page.text and 'Monitor' in page.text
    assert '&lt;script&gt;private reason&lt;/script&gt;' in page.text
    assert '15 min' in page.text and 'En attente' in page.text
    assert '/request/' + r['id'] in page.text
    assert pw not in page.text and '$argon2' not in page.text
    assert client.get('/login', base_url=base).location == '/'
    assert client.post('/logout', base_url=base, headers={'Origin': base},
                       data={'csrf': hidden(page.text, 'csrf')}).status_code == 303
    assert client.get('/', base_url=base).status_code == 303


def test_exact_request_login_destination(ui):
    b, pw, client, base = ui
    r = call(b, 'agent', 'request', mode='safe', duration=61, reason='fixture')
    assert sign_in(client, base, pw, r['id']).location == '/request/' + r['id']
    assert '1 min 1 s' in client.get('/request/' + r['id'], base_url=base).text
    assert client.get('/login?request=' + r['id'], base_url=base).location == '/request/' + r['id']


@pytest.mark.parametrize('path', ['/', '/login', '/request/' + 'a' * 32])
def test_stale_cookie_recovery(ui, path):
    b, _, client, base = ui
    client.set_cookie('pha_session', 'stale', domain='approve.example')
    page = client.get(path, base_url=base)
    assert page.status_code == 200
    assert 'Se connecter' in page.text and 'session' in page.text.lower()
    assert any('pha_session=;' in c for c in page.headers.getlist('Set-Cookie'))
    assert client.get('/login', base_url=base).status_code == 200


def test_broker_failure_is_safe_not_redirect_loop(ui):
    b, _, _, base = ui
    def fail(m):
        raise OSError('sensitive-internal-path')
    client = create_app(b.config, transport=fail).test_client()
    client.set_cookie('pha_session', 'stale', domain='approve.example')
    for path in ['/', '/login', '/request/' + 'a' * 32]:
        page = client.get(path, base_url=base)
        assert page.status_code == 503 and not page.location
        assert 'indisponible' in page.text and 'sensitive-internal-path' not in page.text


def test_overview_role_token_bound_sort_and_no_grant(running):
    b, pw = running
    with pytest.raises(AccessError):
        call(b, 'web', 'overview')
    with pytest.raises(AccessError):
        call(b, 'web', 'overview', token='stale')
    login = call(b, 'web', 'login', password=pw)
    with pytest.raises(AccessError):
        call(b, 'agent', 'overview', token=login['token'])
    with pytest.raises(AccessError):
        call(b, 'web', 'overview', token=login['token'], limit=1000)
    with b.lock:
        for i in range(25):
            r = b.leases.request('safe', 900, 'fixture')
            b.leases.decide(r['id'], 'deny')
            b.leases.records[r['id']]['requested_at'] = i
        pending = b.leases.request('safe', 900, 'pending fixture')
        # Explicitly unsorted insertion order exercises server-side sorting.
        b.leases.records = dict(reversed(list(b.leases.records.items())))
    result = call(b, 'web', 'overview', token=login['token'])
    assert set(result) == {'csrf', 'records'}
    assert result['csrf'] == login['csrf'] and len(result['records']) == 20
    assert result['records'][0]['id'] == pending['id']
    assert [r['requested_at'] for r in result['records']] == sorted(
        (r['requested_at'] for r in result['records']), reverse=True)
    assert b.auth.session(login['token'])['challenge'] is None
    assert call(b, 'agent', 'status', id=pending['id'])['state'] == 'pending'
    with b.lock:
        b.leases.deadlines[pending['id']] = time.monotonic() - 1
    assert call(b, 'web', 'overview', token=login['token'])['records'][0]['state'] == 'expired'


@pytest.mark.parametrize('state', ['denied', 'revoked', 'expired'])
def test_terminal_no_mutation_forms(ui, state):
    b, pw, client, base = ui
    r = call(b, 'agent', 'request', mode='full', duration=900, reason='fixture')
    with b.lock:
        b.leases.records[r['id']]['state'] = state
    sign_in(client, base, pw)
    page = client.get('/request/' + r['id'], base_url=base)
    assert '/approve' not in page.text and '/deny' not in page.text and '/revoke' not in page.text
    assert 'shell root arbitraire' in page.text and 'ne défait pas' in page.text
    assert 'type="password"' not in page.text


def test_assets_csp_countdown_display_only(ui):
    b, pw, client, base = ui
    r = call(b, 'agent', 'request', mode='safe', duration=900, reason='fixture')
    sign_in(client, base, pw)
    page = client.get('/request/' + r['id'], base_url=base)
    data = {'csrf': hidden(page.text, 'csrf'), 'challenge': hidden(page.text, 'challenge'), 'password': pw}
    client.post('/request/' + r['id'] + '/approve', base_url=base, headers={'Origin': base}, data=data)
    page = client.get('/request/' + r['id'], base_url=base)
    assert 'data-expires-at=' in page.text and '<time' in page.text
    assert '/approve' not in page.text and 'Le serveur' in page.text
    csp = page.headers['Content-Security-Policy']
    assert "style-src 'self'" in csp and "script-src 'self'" in csp
    for directive in ["form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'"]:
        assert directive in csp
    assert 'unsafe-' not in csp and page.headers['Referrer-Policy'] == 'same-origin'
    assert '<style' not in page.text and ' style=' not in page.text
    for asset in ['ui.css', 'countdown.js']:
        response = client.get('/static/' + asset, base_url=base)
        assert response.status_code == 200
    script = client.get('/static/countdown.js', base_url=base).text
    assert 'fetch(' not in script and 'submit(' not in script and 'XMLHttpRequest' not in script
    assert call(b, 'agent', 'status', id=r['id'])['state'] == 'active'
    assert 'static/*.css' in Path('pyproject.toml').read_text()
    assert 'static/*.js' in Path('pyproject.toml').read_text()


def test_errors_and_password_field_do_not_echo(ui):
    _, pw, client, base = ui
    page = client.get('/login', base_url=base)
    assert 'autocomplete="current-password"' in page.text
    assert not re_password_value(page.text)
    page = client.post('/login', base_url=base, headers={'Origin': base},
                       data={'csrf': 'invalid', 'password': pw})
    assert page.status_code == 403 and 'role="alert"' in page.text
    assert pw not in page.text and 'Traceback' not in page.text


def re_password_value(html):
    import re
    return re.search(r'<input[^>]*type="password"[^>]*value=', html)
