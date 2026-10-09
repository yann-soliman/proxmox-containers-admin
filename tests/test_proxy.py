import http.client
import threading
from dataclasses import replace
from waitress import create_server
from host_access.web import create_app


def test_actual_waitress_trusts_only_configured_proxy(running):
    b,_ = running
    for trusted,status in [('192.0.2.99',403),('127.0.0.1',200)]:
        c = replace(b.config,trusted_proxy=trusted)
        server = create_server(create_app(c),host='127.0.0.1',port=0,threads=2,
                               trusted_proxy=c.trusted_proxy,trusted_proxy_headers={'x-forwarded-proto'},
                               clear_untrusted_proxy_headers=True,max_request_body_size=8192,ident='')
        thread = threading.Thread(target=server.run,daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection('127.0.0.1',int(server.effective_port),timeout=3)
            connection.request('GET','/login',headers={'Host':'approve.example','X-Forwarded-Proto':'https'})
            response = connection.getresponse()
            assert response.status == status
            response.read()
            connection.close()
        finally:
            server.close()
            server.task_dispatcher.shutdown()
            thread.join(3)
