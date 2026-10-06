#!/usr/bin/env python3
"""Local single-user API. No outbound scope bypass or account persistence."""
import argparse
import hmac
import json
import os
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from kanit.engine import Scanner
from kanit.lab import start_lab
from kanit.scope import Policy, ScopeError, Cancelled, canonical_origin
from kanit.store import Store
from kanit.zap import Zap

ROOT = Path(__file__).resolve().parent


class Application:
    def __init__(self, data_dir, lab_ports=(9121, 9122), rate=2, zap=None):
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(data_dir, 0o700)
        self.store = Store(data_dir / 'kanit.db')
        self.key = secrets.token_urlsafe(32)
        self.cookie = secrets.token_urlsafe(32)
        self.labs = {mode: start_lab(mode, port) for mode, port in zip(('vulnerable', 'fixed'), lab_ports)}
        self.policy = Policy(labs={lab.origin for lab in self.labs.values()})
        self.rate = rate
        self.zap = zap
        self.scan_lock = threading.Lock()
        self.events = {}
        self.events_lock = threading.RLock()

    def add_site(self, url):
        if not isinstance(url, str):
            raise ScopeError('Geçerli bir domain veya http/https adresi girin.')
        url = url.strip()
        if '://' not in url:
            url = 'https://' + url
        origin = canonical_origin(url)
        self.policy.address(origin)
        site = {'id': secrets.token_hex(8), 'origin': origin, 'created_at': time.time()}
        self.store.save_site(site)
        return site

    def start(self, site_id, config, read_only):
        if read_only is not True:
            raise ScopeError('Yalnızca size ait salt okunur test uçları kullandığınızı belirtin.')
        site = self.store.get_site(site_id)
        if not isinstance(config, dict):
            raise ScopeError('Test ayarları geçersiz.')
        scanner = Scanner(site['origin'], self.policy, rate=self.rate, zap=self.zap)
        scanner.validate_config(config)
        if not self.scan_lock.acquire(blocking=False):
            raise ScopeError('Zaten bir tarama çalışıyor. Tamamlanmasını bekleyin veya durdurun.')
        job = {'id': secrets.token_hex(8), 'site_id': site_id, 'origin': site['origin'], 'created_at': time.time(), 'status': 'queued', 'stage': 'Tarama hazırlanıyor', 'percent': 0, 'requests': 0, 'report': None}
        self.store.save_scan(job)
        with self.events_lock:
            self.events[job['id']] = scanner.transport.stop

        def progress(stage, percent, requests):
            job.update(stage=stage, percent=percent, requests=requests, status='running')
            self.store.save_scan(job)
        scanner.progress = progress

        def worker():
            try:
                scanner.transport.check()
                job['report'] = scanner.run(config)
                job.update(status='complete' if job['report']['complete'] else 'partial', percent=100, stage='Rapor hazır' if job['report']['complete'] else 'Kısmi rapor hazır')
            except Cancelled:
                job.update(status='stopped', stage='Tarama durduruldu', report=scanner.report, requests=scanner.transport.count)
                job['report']['requests'] = scanner.transport.count
                job['report']['warnings'].append('Kullanıcı durdurdu; kapsamın bir bölümü incelenmedi.')
            except (ScopeError, ValueError, KeyError, TypeError) as e:
                job.update(status='failed', stage='Tarama tamamlanamadı', error=str(e)[:250], report=scanner.report)
            except Exception:
                job.update(status='failed', stage='Tarama tamamlanamadı', error='Beklenmeyen sunucu hatası; önceki kanıtlar korunuyor.', report=scanner.report)
            finally:
                # RAM-only credential configuration is removed when the job ends.
                config.clear()
                scanner.har_entries.clear()
                scanner.finish_coverage()
                job['finished_at'] = time.time()
                self.store.save_scan(job)
                with self.events_lock:
                    self.events.pop(job['id'], None)
                self.scan_lock.release()
        threading.Thread(target=worker, daemon=True, name='safez-scan').start()
        return job.copy()

    def stop(self, scan_id):
        job = self.store.get_scan(scan_id)
        with self.events_lock:
            event = self.events.get(scan_id)
            if event:
                event.set()
        return {'id': scan_id, 'stopping': bool(event)}

    def close(self):
        with self.events_lock:
            for event in self.events.values():
                event.set()
        # Outstanding requests have a 6-second network timeout.
        if self.scan_lock.acquire(timeout=8):
            self.scan_lock.release()
        for lab in self.labs.values():
            lab.shutdown()


def make_server(app, port=8787):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            # Never log target queries, cookies or submitted account fields.
            pass

        def local_request(self, mutation=False):
            allowed = {'127.0.0.1:' + str(self.server.server_port), 'localhost:' + str(self.server.server_port)}
            if self.headers.get('Host', '') not in allowed:
                return False
            origin = self.headers.get('Origin')
            if origin and origin not in {'http://' + host for host in allowed}:
                return False
            if self.headers.get('Sec-Fetch-Site') == 'cross-site':
                return False
            if self.path.startswith('/api/'):
                try:
                    cookie = SimpleCookie(self.headers.get('Cookie', ''))
                    value = cookie['kanit_local'].value if 'kanit_local' in cookie else ''
                except Exception:
                    return False
                if not hmac.compare_digest(value.encode('utf-8'), app.cookie.encode()):
                    return False
            if mutation and not hmac.compare_digest(self.headers.get('X-Kanit-Key', '').encode('utf-8'), app.key.encode()):
                return False
            return True

        def respond(self, status, body, mime='application/json; charset=utf-8', headers=None):
            if not isinstance(body, bytes):
                body = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            if not self.local_request():
                return self.respond(403, {'error': 'Yerel oturum veya adres doğrulaması başarısız.'})
            try:
                path = urlsplit(self.path).path
                static = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8'), '/favicon.svg': ('favicon.svg', 'image/svg+xml')}
                if path in static:
                    file, mime = static[path]
                    headers = {'Set-Cookie': 'kanit_local=' + app.cookie + '; HttpOnly; SameSite=Strict; Path=/'} if path == '/' else {}
                    return self.respond(200, (ROOT / 'web' / file).read_bytes(), mime, headers)
                if path == '/api/bootstrap':
                    engine = {'name': 'OWASP ZAP', 'configured': bool(app.zap), 'detail': 'Ayrılmış yerel pasif motor bağlı.' if app.zap else 'Pasif motor bağlı değil; karşılaştırmalı çekirdek çalışır.'}
                    return self.respond(200, {'key': app.key, 'sites': app.store.sites(), 'scans': [{k: v for k, v in s.items() if k != 'report'} for s in app.store.scans()], 'engine': engine, 'rate': app.rate, 'limits': {'pages': 32, 'requests': 240}})
                if path == '/api/sites':
                    return self.respond(200, app.store.sites())
                if path == '/api/scans':
                    return self.respond(200, [{k: v for k, v in s.items() if k != 'report'} for s in app.store.scans()])
                parts = path.strip('/').split('/')
                if len(parts) in (3, 4) and parts[:2] == ['api', 'scans']:
                    job = app.store.get_scan(parts[2])
                    if len(parts) == 4 and parts[3] == 'pdf':
                        if not job.get('report'):
                            raise ScopeError('Rapor henüz hazır değil.')
                        from kanit.report import make_pdf
                        return self.respond(200, make_pdf(job), 'application/pdf', {'Content-Disposition': 'attachment; filename="safeZ-' + job['id'] + '.pdf"'})
                    if len(parts) == 3:
                        return self.respond(200, job)
                self.respond(404, {'error': 'Adres bulunamadı.'})
            except KeyError:
                self.respond(404, {'error': 'Kayıt bulunamadı.'})
            except (ScopeError, ValueError) as e:
                self.respond(400, {'error': str(e)[:250]})
            except Exception:
                self.respond(500, {'error': 'Rapor veya dosya üretilemedi. Kurulumu ve yazı tiplerini kontrol edin.'})

        def do_POST(self):
            if not self.local_request(mutation=True):
                return self.respond(403, {'error': 'İstek yerel oturumdan gelmeli; sayfayı yenileyin.'})
            try:
                if self.headers.get('Transfer-Encoding') or 'application/json' not in self.headers.get('Content-Type', ''):
                    raise ScopeError('JSON isteği gerekli.')
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 65536:
                    raise ScopeError('İstek boyutu geçersiz veya 64 KB sınırını aşıyor.')
                self.connection.settimeout(5)
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ScopeError('JSON nesnesi gerekli.')
                path = urlsplit(self.path).path
                if path == '/api/sites':
                    return self.respond(200, app.add_site(data['url']))
                if path == '/api/lab':
                    lab = app.labs[data['mode']]
                    site = app.add_site(lab.origin)
                    return self.respond(200, {'site': site, 'config': lab.test_config(), 'mode': lab.mode})
                if path == '/api/scans':
                    return self.respond(202, app.start(data['site_id'], data.get('config', {}), data.get('read_only')))
                parts = path.strip('/').split('/')
                if len(parts) == 4 and parts[:2] == ['api', 'scans'] and parts[3] == 'stop':
                    return self.respond(200, app.stop(parts[2]))
                self.respond(404, {'error': 'İşlem bulunamadı.'})
            except KeyError:
                self.respond(400, {'error': 'Gerekli alan veya kayıt bulunamadı.'})
            except (ScopeError, ValueError, TypeError) as e:
                self.respond(400, {'error': str(e)[:250]})
            except Exception:
                self.respond(500, {'error': 'İşlem tamamlanamadı; uygulamayı kontrol edin.'})

    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.daemon_threads = True
    return server


def main(zap=None):
    parser = argparse.ArgumentParser(description='safeZ yerel güvenlik inceleme uygulaması')
    parser.add_argument('--port', type=int, default=8787)
    parser.add_argument('--lab-ports', nargs=2, type=int, default=(9121, 9122), metavar=('OPEN', 'FIXED'))
    parser.add_argument('--data-dir', default=str(ROOT / 'work' / 'data'))
    args = parser.parse_args()
    app = Application(args.data_dir, lab_ports=args.lab_ports, zap=zap)
    server = make_server(app, args.port)
    print('safeZ hazır: http://127.0.0.1:' + str(server.server_port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.close()


if __name__ == '__main__':
    main()
