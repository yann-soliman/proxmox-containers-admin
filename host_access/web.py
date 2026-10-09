"""Mobile password UI. Unix broker remains the authentication authority."""
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from flask import Flask, abort, make_response, redirect, render_template, request, session
from werkzeug.exceptions import HTTPException
from .broker import rpc
from .config import load
from .leases import AccessError

ID = re.compile(r'^[0-9a-f]{32}$')
STATES = {'pending': 'En attente', 'active': 'Actif', 'denied': 'Refusé', 'expired': 'Expiré', 'revoked': 'Révoqué'}


def minutes(seconds):
    m, s = divmod(seconds, 60)
    return f'{m} min' + (f' {s} s' if s else '') if m else f'{s} s'


def timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).strftime('%d/%m/%Y · %H:%M:%S UTC')


def iso_timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def create_app(config, *, transport=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secrets.token_bytes(32), SESSION_COOKIE_NAME='pha_pre',
                      SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE='Strict', MAX_CONTENT_LENGTH=8192,
                      PERMANENT_SESSION_LIFETIME=900)
    app.jinja_env.filters.update(minutes=minutes, timestamp=timestamp, iso_timestamp=iso_timestamp)
    app.jinja_env.globals['states'] = STATES
    send = transport if transport is not None else lambda m: rpc(Path(config.socket_dir)/'web.sock', m, timeout=15)
    authority = urlsplit(config.origin).netloc

    def broker(op, **kwargs):
        try:
            return send(dict(op=op, **kwargs))
        except AccessError as exc:
            # Only this exact authority response permits stale-cookie recovery.
            if str(exc) == 'authentication required' and request.method == 'GET':
                raise
            if str(exc) == 'broker unavailable':
                abort(503)
            abort(403)
        except (OSError, ValueError):
            abort(503)

    def token():
        return request.cookies.get('pha_session', '')

    def rid_arg():
        value = request.args.get('request', '')
        return value if ID.fullmatch(value) else ''

    def login_page(rid='', stale=False):
        session.clear()
        session['csrf'] = secrets.token_urlsafe(32)
        response = make_response(render_template('login.html', csrf=session['csrf'], rid=rid, stale=stale))
        if stale:
            response.delete_cookie('pha_session', secure=True, httponly=True, samesite='Strict', path='/')
        return response

    @app.before_request
    def guard():
        if request.host != authority:
            abort(400)
        if not request.is_secure:
            abort(403)
        if request.method == 'POST':
            if request.headers.get('Origin') != config.origin:
                abort(403)
            if request.mimetype != 'application/x-www-form-urlencoded':
                abort(415)
        if any(k.lower() in {'password', 'token', 'csrf', 'challenge'} for k in request.args):
            abort(400)

    @app.after_request
    def headers(response):
        response.headers.update({'Cache-Control':'no-store', 'Pragma':'no-cache',
            'Content-Security-Policy':"default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'same-origin',
            'Strict-Transport-Security':'max-age=31536000', 'X-Frame-Options':'DENY'})
        return response

    @app.errorhandler(HTTPException)
    def error_page(error):
        messages = {
            400: ('Requête invalide', 'Vérifiez l’adresse utilisée. Aucun accès n’a été autorisé.'),
            403: ('Action refusée', 'Authentification, origine ou confirmation invalide ou expirée. Rechargez la page avant de réessayer. Si votre session a expiré, reconnectez-vous.'),
            404: ('Page introuvable', 'Cette adresse ne correspond pas à une page disponible.'),
            413: ('Requête trop volumineuse', 'Le formulaire dépasse la taille autorisée.'),
            415: ('Format refusé', 'Utilisez le formulaire de cette application.'),
            503: ('Autorité indisponible', 'Le service d’autorisation est indisponible. Réessayez plus tard ; aucun accès supplémentaire n’a été accordé.'),
        }
        title, message = messages.get(error.code, ('Requête refusée', 'Cette action ne peut pas être traitée.'))
        return render_template('error.html', title=title, message=message, code=error.code), error.code

    @app.get('/')
    def index():
        if not token():
            return redirect('/login', code=303)
        try:
            result = broker('overview', token=token())
        except AccessError:
            return login_page(stale=True)
        records = result['records']
        current = next((r for r in records if r['state'] in {'pending', 'active'}), None)
        return render_template('dashboard.html', records=records, current=current,
                               latest=records[0] if records else None, csrf=result['csrf'])

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        rid = rid_arg()
        if request.method == 'GET':
            if token():
                try:
                    broker('session', token=token())
                except AccessError:
                    return login_page(rid, stale=True)
                return redirect('/request/'+rid if rid else '/', code=303)
            return login_page(rid)
        csrf = request.form.get('csrf', '')
        expected = session.pop('csrf', '')
        if not expected or not secrets.compare_digest(csrf, expected):
            abort(403)
        result = broker('login', password=request.form.get('password', ''))
        response = redirect('/request/'+rid if rid else '/', code=303)
        response.set_cookie('pha_session', result['token'], max_age=900, secure=True,
                            httponly=True, samesite='Strict', path='/')
        session.clear()
        return response

    @app.get('/request/<rid>')
    def view(rid):
        if not ID.fullmatch(rid):
            abort(404)
        if not token():
            return redirect('/login?request='+rid, code=303)
        try:
            result = broker('view', token=token(), id=rid)
        except AccessError:
            return login_page(rid, stale=True)
        return render_template('approval.html', r=result['request'], csrf=result['csrf'],
                               challenge=result['challenge'])

    @app.post('/request/<rid>/<decision>')
    def decide(rid, decision):
        if not ID.fullmatch(rid) or decision not in {'approve', 'deny', 'revoke'}:
            abort(404)
        m = dict(token=token(), csrf=request.form.get('csrf', ''), id=rid)
        if decision == 'approve':
            m.update(challenge=request.form.get('challenge', ''))
        broker(decision, **m)
        return redirect('/request/'+rid, code=303)

    @app.post('/logout')
    def logout():
        broker('logout', token=token(), csrf=request.form.get('csrf', ''))
        response = redirect('/login', code=303)
        response.delete_cookie('pha_session', secure=True, httponly=True, samesite='Strict')
        session.clear()
        return response

    return app


def main():
    c = load()
    if os.geteuid() != c.web_uid or os.geteuid() == 0:
        raise SystemExit('web must run as configured nonroot UID')
    from waitress import serve
    # HTTPS terminates at exactly one configured trusted proxy. Restrict the
    # backend port to its source IP in the host firewall; never trust forwarded Host.
    serve(create_app(c), host=c.bind, port=c.port, threads=4, clear_untrusted_proxy_headers=True,
          trusted_proxy=c.trusted_proxy, trusted_proxy_headers={'x-forwarded-proto'},
          max_request_body_size=8192, ident='')


if __name__ == '__main__':
    main()
