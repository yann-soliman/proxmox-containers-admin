import http.client
import os
import ssl
import subprocess
import threading
import urllib.parse
from dataclasses import replace
from http.cookies import SimpleCookie
from werkzeug.serving import make_server, WSGIRequestHandler
from host_access.web import create_app
from test_broker import call
from test_web import hidden


class Quiet(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


def test_real_https_to_unix_password_execution_and_revoke(running, tmp_path):
    b, pw = running
    key, cert = tmp_path/'key.pem', tmp_path/'cert.pem'
    r = subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),
                        '-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'], capture_output=True)
    assert r.returncode == 0
    os.chmod(key, 0o600)
    c = replace(b.config, origin='https://localhost')
    app = create_app(c)
    server = make_server('127.0.0.1',0,app,threaded=True,ssl_context=(str(cert),str(key)),request_handler=Quiet)
    thread = threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    ctx = ssl.create_default_context(cafile=str(cert))
    jar = {}
    def request_http(method, path, data=None):
        connection = http.client.HTTPSConnection('localhost',server.server_port,context=ctx,timeout=5)
        headers = {'Host':'localhost','Origin':c.origin}
        if jar:
            headers['Cookie'] = '; '.join(k+'='+v for k,v in jar.items())
        if data is not None:
            data = urllib.parse.urlencode(data)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        connection.request(method,path,body=data,headers=headers)
        response = connection.getresponse()
        body = response.read().decode()
        for k,v in response.getheaders():
            if k.lower() == 'set-cookie':
                cookie = SimpleCookie(v)
                for name,morsel in cookie.items():
                    jar[name] = morsel.value
        status = response.status
        connection.close()
        return status, body
    try:
        request = call(b,'agent','request',mode='full',duration=900,reason='local real TLS integration')
        rid = request['id']
        assert request_http('GET','/request/'+rid)[0] == 303
        _, page = request_http('GET','/login?request='+rid)
        assert request_http('POST','/login?request='+rid,dict(csrf=hidden(page,'csrf'),password=pw))[0] == 303
        _, page = request_http('GET','/request/'+rid)
        payload = dict(csrf=hidden(page,'csrf'),challenge=hidden(page,'challenge'))
        assert request_http('POST','/request/'+rid+'/approve',{**payload, 'csrf': 'wrong'})[0] == 403
        assert call(b,'agent','status',id=rid)['state'] == 'pending'
        _, page = request_http('GET','/request/'+rid)
        payload.update(challenge=hidden(page,'challenge'))
        assert request_http('POST','/request/'+rid+'/approve',payload)[0] == 303
        assert call(b,'agent','status',id=rid)['state'] == 'active'
        result = call(b,'agent','execute',command='printf local-e2e; exit 3')
        assert result['stdout'] == 'local-e2e' and result['exitcode'] == 3
        _, page = request_http('GET','/request/'+rid)
        assert request_http('POST','/request/'+rid+'/revoke',dict(csrf=hidden(page,'csrf')))[0] == 303
        assert call(b,'agent','status',id=rid)['state'] == 'revoked'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
