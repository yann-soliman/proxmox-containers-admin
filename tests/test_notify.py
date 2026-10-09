import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from host_access.config import Config
from host_access.notify import Gotify


def test_gotify_actual_http_link_is_not_authority(tmp_path):
    token = secrets.token_urlsafe(32)
    secretfile = tmp_path/'token'
    secretfile.write_text(token)
    secretfile.chmod(0o600)
    received = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            received.append((self.path, self.headers.get('X-Gotify-Key'), json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{}')
    server = HTTPServer(('127.0.0.1',0), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    c = Config(origin='https://approve.example', agent_uid=123, web_uid=124,
               gotify_url='http://127.0.0.1:'+str(server.server_port), gotify_token_file=str(secretfile))
    try:
        notify = Gotify(c, owner=os.getuid(), allow_test_http=True)
        assert notify(dict(id='a'*32, mode='safe', duration=900, state='pending', agent='agent', target='node', reason='inspect'))
        path, header, body = received[0]
        assert path == '/message' and header == token
        serialized = json.dumps(body)
        assert token not in serialized and 'password' not in serialized
        assert body['extras']['client::notification']['click']['url'] == 'https://approve.example/request/'+'a'*32
    finally:
        server.shutdown()
        server.server_close()
        t.join()
    assert not notify(dict(id='a'*32, mode='safe', duration=900, state='revoked', agent='a', target='n', reason='x'))
