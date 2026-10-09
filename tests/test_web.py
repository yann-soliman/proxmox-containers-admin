import re
from host_access.web import create_app
from test_broker import call


def hidden(html, name):
    return re.search(r'name="'+name+r'" value="([^"]+)"', html).group(1)


def test_web_password_csrf_origin_host_replay_and_readback(running):
    b, pw = running
    r = call(b, 'agent', 'request', mode='full', duration=900, reason='<script>alert(1)</script>')
    app = create_app(b.config, transport=lambda message: call(b, 'web', message.pop('op'), **message))
    client = app.test_client()
    base = b.config.origin
    page = client.get('/request/'+r['id'], base_url=base)
    assert page.status_code == 303
    login = client.get('/login?request='+r['id'], base_url=base)
    csrf = hidden(login.text, 'csrf')
    assert client.post('/login', base_url=base, data={'password':pw, 'csrf':csrf}).status_code == 403
    response = client.post('/login?request='+r['id'], base_url=base,
                           headers={'Origin':base}, data={'password':pw, 'csrf':csrf})
    assert response.status_code == 303
    cookies = response.headers.getlist('Set-Cookie')
    assert any('Secure' in s and 'HttpOnly' in s and 'SameSite=Strict' in s for s in cookies)
    page = client.get('/request/'+r['id'], base_url=base)
    assert '&lt;script&gt;' in page.text and 'FULL' in page.text
    assert call(b, 'agent', 'status', id=r['id'])['state'] == 'pending'
    data = {'csrf':hidden(page.text,'csrf'), 'challenge':hidden(page.text,'challenge')}
    path = '/request/'+r['id']+'/approve'
    assert client.post(path, base_url=base, headers={'Origin':base}, data={**data, 'csrf': 'wrong'}).status_code == 403
    page = client.get('/request/'+r['id'], base_url=base)
    data['challenge'] = hidden(page.text,'challenge')

    assert client.post(path, base_url=base, headers={'Origin':'https://evil.example'}, data=data).status_code == 403
    assert client.post(path, base_url=base, headers={'Origin':base}, data=data).status_code == 303
    assert call(b, 'agent', 'status', id=r['id'])['state'] == 'active'
    assert client.post(path, base_url=base, headers={'Origin':base}, data=data).status_code == 403
    page = client.get('/request/'+r['id'], base_url=base)
    assert client.post('/request/'+r['id']+'/revoke', base_url=base,
                       headers={'Origin':base}, data={'csrf':hidden(page.text,'csrf')}).status_code == 303
    assert call(b, 'agent', 'status', id=r['id'])['state'] == 'revoked'
    assert client.get('/login', base_url='https://evil.example').status_code == 400
    response = client.get('/login?next=https://evil.example', base_url=base)
    assert response.status_code == 303 and response.location == '/'
    assert response.headers['Content-Security-Policy'] and response.headers['Cache-Control'] == 'no-store'
    assert client.get('/login', base_url='http://approve.example').status_code == 403
    assert client.post('/signup', base_url=base, headers={'Origin':base}, data={'unused':'x'}).status_code == 404


def test_form_referrer_policy_preserves_same_origin_post(running):
    b, _ = running
    app = create_app(b.config, transport=lambda message: call(b, 'web', message.pop('op'), **message))
    client = app.test_client()
    response = client.get('/login', base_url=b.config.origin)
    # no-referrer makes native browser form POST serialize Origin as null,
    # contradicting the mandatory exact-origin check even for legitimate forms.
    assert response.headers['Referrer-Policy'] == 'same-origin'
    assert client.post('/login', base_url=b.config.origin,
                       headers={'Origin':'null'}, data={}).status_code == 403
    assert client.post('/login', base_url=b.config.origin,
                       headers={'Origin':'https://evil.example'}, data={}).status_code == 403
