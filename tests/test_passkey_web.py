"""Exercise WebAuthn web routing independently of the broker's cryptographic tests."""
import re
from types import SimpleNamespace

from host_access.web import create_app

ORIGIN = 'https://approval.example.test'
RID = 'a' * 32


def csrf_from(page, names=b'csrf'):
    match = re.search(rb'name="(?:'+names+rb')"\s+(?:content|value)="([^"]+)"', page.data)
    assert match is not None
    return match[1].decode()


def test_external_notification_cookie_and_exact_request_redirect():
    def transport(message):
        assert message == {'op': 'login', 'password': 'test-only'}
        return {'token': 'test-session'}

    c = create_app(SimpleNamespace(origin=ORIGIN), transport=transport).test_client()
    page = c.get('/login?request='+RID, base_url=ORIGIN)
    csrf = csrf_from(page)
    result = c.post('/login?request='+RID, base_url=ORIGIN, headers={'Origin': ORIGIN},
                    data={'csrf': csrf, 'password': 'test-only'})
    assert result.location == '/request/'+RID
    cookie = next(h for h in result.headers.getlist('Set-Cookie') if h.startswith('pha_session='))
    assert 'SameSite=Lax' in cookie and 'Secure' in cookie and 'HttpOnly' in cookie
    assert 'Max-Age=900' in cookie


def test_passkey_login_bound_to_browser_and_request():
    calls = []

    def transport(message):
        calls.append(message)
        match message['op']:
            case 'auth_info':
                return {'auth_mode': 'passkey', 'passkey_available': True}
            case 'passkey_login_start':
                return {'challenge': 'test', 'rpId': 'approval.example.test'}
            case 'passkey_login_finish':
                return {'token': 'test-session', 'max_age': 1800}
        raise AssertionError(message['op'])

    app = create_app(SimpleNamespace(origin=ORIGIN, auth_mode='passkey'), transport=transport)
    c, other = app.test_client(), app.test_client()
    page = c.get('/login?request='+RID, base_url=ORIGIN)
    csrf = csrf_from(page, b'csrf|passkey-csrf')
    headers = {'Origin': ORIGIN}
    fields = {'csrf': csrf, 'request': RID}
    assert c.post('/passkeys/login/start', base_url=ORIGIN, headers={'Origin': 'https://wrong.test'},
                  data=fields).status_code == 403
    assert other.post('/passkeys/login/start', base_url=ORIGIN, headers=headers, data=fields).status_code == 403
    start = c.post('/passkeys/login/start', base_url=ORIGIN, headers=headers, data=fields)
    assert start.json['rpId'] == 'approval.example.test'
    finish = c.post('/passkeys/login/finish', base_url=ORIGIN, headers=headers,
                    data={**fields, 'credential': '{"id":"test"}'})
    assert finish.status_code == 200
    assert finish.json == {'location': '/request/'+RID}
    assert any('Max-Age=1800' in v for v in finish.headers.getlist('Set-Cookie'))
    assert [c['op'] for c in calls] == ['auth_info', 'passkey_login_start', 'passkey_login_finish']
    assert calls[1]['binding'] == calls[2]['binding']


def test_passkey_only_rejects_password_post_before_broker():
    def transport(message):
        raise AssertionError(message)

    c = create_app(SimpleNamespace(origin=ORIGIN, auth_mode='passkey'), transport=transport).test_client()
    response = c.post('/login', base_url=ORIGIN, headers={'Origin': ORIGIN},
                      data={'csrf': 'x', 'password': 'test-only'})
    assert response.status_code == 403


def test_passkey_routes_absent_when_disabled():
    def transport(message):
        raise AssertionError(message)

    c = create_app(SimpleNamespace(origin=ORIGIN), transport=transport).test_client()
    assert c.get('/passkeys/enroll', base_url=ORIGIN).status_code == 404
    for path in ('/passkeys/enroll/start', '/passkeys/login/start', '/request/'+RID+'/approve/start'):
        assert c.post(path, base_url=ORIGIN, headers={'Origin': ORIGIN}, data={'csrf': 'x'}).status_code == 404
