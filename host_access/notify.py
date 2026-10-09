"""Gotify is delivery only, never authentication or an approval API."""
import json
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from .config import protected


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Gotify:
    def __init__(self, config, *, owner=0, allow_test_http=False):
        u = urlsplit(config.gotify_url)
        if (u.scheme != 'https' and not (allow_test_http and u.scheme == 'http' and u.hostname == '127.0.0.1')) or not u.hostname or u.username or u.password or u.query or u.fragment:
            raise ValueError('Gotify requires a credential-free HTTPS URL')
        self.url = config.gotify_url.rstrip('/') + '/message'
        self.origin = config.origin
        self.token = protected(config.gotify_token_file, owner=owner).read_text().strip()
        if not self.token or len(self.token) > 512 or any(ord(c) < 33 for c in self.token):
            raise ValueError('invalid Gotify token file')
        self.opener = build_opener(NoRedirect())

    def __call__(self, r):
        link = self.origin + '/request/' + r['id']
        payload = dict(title='Host access ' + r['state'].upper(), priority=5,
            message=f"{r['target']} — {r['agent']} — {r['mode'].upper()} — {r['duration']}s\n{r['reason']}\n{link}\nCe lien ne peut pas autoriser l’accès.",
            extras={'client::notification': {'click': {'url':link}}})
        req = Request(self.url, data=json.dumps(payload).encode(), method='POST',
                      headers={'Content-Type':'application/json', 'X-Gotify-Key':self.token})
        try:
            with self.opener.open(req, timeout=3) as response:
                return 200 <= response.status < 300
        except Exception:
            # Transport exceptions may include URL/header information: never log them.
            return False
