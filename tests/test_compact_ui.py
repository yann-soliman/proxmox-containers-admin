from html.parser import HTMLParser

from host_access.web import create_app
from test_broker import call
from test_dashboard import sign_in


class ActionOrder(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.tags.append(attrs.get('action', ''))
        if tag == 'details':
            self.tags.append('details')


def test_full_action_precedes_secondary_metadata(running):
    broker, password = running
    record = call(broker, 'agent', 'request', mode='full', duration=900, reason='Vérification PVE')
    app = create_app(broker.config, transport=lambda m: call(broker, 'web', m.pop('op'), **m))
    client = app.test_client()
    sign_in(client, broker.config.origin, password, record['id'])
    path = '/request/'+record['id']
    page = client.get(path, base_url=broker.config.origin)
    parsed = ActionOrder()
    parsed.feed(page.text)
    assert parsed.tags.index(path+'/approve') < parsed.tags.index('details')
    assert page.text.index('Accès root sans restriction') < page.text.index(path+'/approve')
    assert page.text.index('Vérification PVE') < page.text.index(path+'/approve')
    assert 'Session limitée à' not in page.text


def test_compact_password_login_removes_promotional_copy(running):
    broker, _ = running
    app = create_app(broker.config)
    page = app.test_client().get('/login', base_url=broker.config.origin)
    assert 'Se connecter' in page.text
    assert 'Un mot de passe pour entrer' not in page.text
    assert 'Espace approbateur' not in page.text
