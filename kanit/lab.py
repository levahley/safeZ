"""Deliberately vulnerable and fixed fixtures. Loopback only; synthetic data."""
import json
import secrets
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie, CookieError
from urllib.parse import parse_qs, urlsplit


class Lab:
    def __init__(self, mode, port):
        self.mode = mode
        self.sessions = {'a': 'safez-lab-session-a-' + secrets.token_hex(8), 'b': 'safez-lab-session-b-' + secrets.token_hex(8)}
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                p = urlsplit(self.path)
                query = parse_qs(p.query)
                if p.path == '/':
                    return self.reply(200, '''<!doctype html><html lang="tr"><title>safeZ test mağazası</title><h1>Test mağazası</h1><p>Tüm veriler yapaydır.</p><a href="/api/products?id=1">Ürün</a><form action="/api/products" method="get"><input name="id" value="1"><button>Ürün getir</button></form><form action="/login" method="post"><input name="username"><input name="password" type="password"></form><a href="/redirect">Dış yönlendirme</a></html>''', 'text/html')
                if p.path == '/redirect':
                    return self.reply(302, '', 'text/plain', {'Location': 'http://169.254.169.254/latest/meta-data/'})
                if p.path == '/api/products':
                    db = sqlite3.connect(':memory:')
                    db.execute('create table products(id integer, name text, tenant text)')
                    db.executemany('insert into products values (?, ?, ?)', [(1, 'Test defteri', 'public'), (2, 'SAFEZ_SQL_PRIVATE', 'private')])
                    value = query.get('id', ['1'])[0]
                    try:
                        if owner.mode == 'vulnerable':
                            rows = db.execute("select id, name from products where tenant = 'public' AND id = " + value).fetchall()
                        else:
                            rows = db.execute("select id, name from products where tenant = 'public' AND id = ?", (value,)).fetchall()
                        return self.reply(200, {'products': [{'id': r[0], 'name': r[1]} for r in rows]})
                    except sqlite3.Error:
                        return self.reply(400, {'error': 'Geçersiz ürün sorgusu'})
                    finally:
                        db.close()
                account = None
                cookie = SimpleCookie()
                try:
                    cookie.load(self.headers.get('Cookie', ''))
                except CookieError:
                    pass
                for who, value in owner.sessions.items():
                    if cookie.get('sid') and cookie['sid'].value == value:
                        account = who
                if p.path == '/api/me':
                    return self.reply(200, {'user_id': account}) if account else self.reply(401, {'error': 'Giriş gerekli'})
                if p.path in ('/api/orders/101', '/api/orders/202'):
                    who = 'a' if p.path.endswith('101') else 'b'
                    if not account:
                        return self.reply(401, {'error': 'Giriş gerekli'})
                    if owner.mode == 'fixed' and account != who:
                        return self.reply(403, {'error': 'Bu kayda erişiminiz yok'})
                    return self.reply(200, {'order': p.path.rsplit('/', 1)[1], 'email': who + '@example.test', 'private_marker': 'SAFEZ_PRIVATE_' + who.upper(), 'total': 120})
                if p.path == '/api/private':
                    if owner.mode == 'fixed' and not account:
                        return self.reply(401, {'error': 'Giriş gerekli'})
                    return self.reply(200, {'private_marker': 'SAFEZ_AUTH_ONLY', 'test_account': 'a@example.test', 'invoice_total': 890})
                return self.reply(404, {'error': 'Bulunamadı'})

            def do_POST(self):
                self.reply(405, {'error': 'Laboratuvar taraması yalnızca GET kullanır'})

            def reply(self, status, data, mime='application/json', headers=None):
                body = (json.dumps(data, ensure_ascii=False) if isinstance(data, dict) else data).encode()
                self.send_response(status)
                self.send_header('Content-Type', mime + '; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
        self.server.daemon_threads = True
        self.origin = 'http://127.0.0.1:' + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def test_config(self):
        return {
            'accounts': {'a': {'cookie': 'sid=' + self.sessions['a']}, 'b': {'cookie': 'sid=' + self.sessions['b']}},
            'identity': {'url': self.origin + '/api/me', 'field': 'user_id'},
            'authorization': {'a_url': self.origin + '/api/orders/101', 'b_url': self.origin + '/api/orders/202', 'a_marker': 'SAFEZ_PRIVATE_A', 'b_marker': 'SAFEZ_PRIVATE_B', 'impact': 'sensitive'},
            'authentication': {'url': self.origin + '/api/private', 'marker': 'SAFEZ_AUTH_ONLY', 'impact': 'sensitive'},
            'injection': [{'url': self.origin + '/api/products?id=1', 'parameter': 'id', 'restricted_marker': 'SAFEZ_SQL_PRIVATE', 'restricted_value': '2', 'impact': 'sensitive'}],
        }

    def shutdown(self):
        self.server.shutdown()
        self.server.server_close()


def start_lab(mode, port=0):
    if mode not in ('vulnerable', 'fixed'):
        raise ValueError('Laboratuvar modu geçersiz')
    return Lab(mode, port)
