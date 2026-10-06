"""Exact-origin policy and DNS-pinned, bounded GET transport."""
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit, urljoin, unquote_plus, parse_qsl


class ScopeError(ValueError):
    pass


class HaltScan(ScopeError):
    pass


class Cancelled(Exception):
    pass


def canonical_origin(url):
    if not isinstance(url, str) or len(url) > 2048 or re.search(r'[\x00-\x20\x7f\\]', url):
        raise ScopeError('Geçerli bir http/https adresi girin.')
    try:
        p = urlsplit(url)
        if p.scheme not in ('http', 'https') or not p.hostname or p.username is not None or p.password is not None or p.fragment:
            raise ValueError()
        host = p.hostname.encode('idna').decode('ascii').lower()
        if host.endswith('.') or '%' in host or not re.fullmatch(r'[a-z0-9.:-]+', host):
            raise ValueError()
        port = p.port or (443 if p.scheme == 'https' else 80)
        if not 1 <= port <= 65535:
            raise ValueError()
        authority = '[' + host + ']' if ':' in host else host
        if port != (443 if p.scheme == 'https' else 80):
            authority += ':' + str(port)
        return p.scheme + '://' + authority
    except (ValueError, UnicodeError):
        raise ScopeError('Adresin şeması, alan adı veya portu geçersiz.') from None


def resolve(host, port):
    try:
        return sorted({x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    except OSError:
        raise ScopeError('Alan adı çözümlenemedi.') from None


class Policy:
    def __init__(self, labs=()):
        # This exception can only be populated by locally started lab servers.
        self.labs = frozenset(labs)

    def address(self, url, stop=None, deadline=None):
        origin = canonical_origin(url)
        p = urlsplit(origin)
        if origin in self.labs and p.hostname == '127.0.0.1':
            return '127.0.0.1'
        port = p.port or (443 if p.scheme == 'https' else 80)
        stop = stop or threading.Event()
        deadline = deadline if deadline is not None else time.monotonic() + 6
        if stop.is_set():
            raise Cancelled('Tarama durduruldu.')
        done = threading.Event()
        result = []
        def lookup():
            try:
                result.append(resolve(p.hostname, port))
            except Exception as error:
                result.append(error)
            finally:
                done.set()
        threading.Thread(target=lookup, daemon=True).start()
        while not done.wait(.025):
            if stop.is_set():
                raise Cancelled('Tarama durduruldu.')
            if time.monotonic() >= deadline:
                raise HaltScan('DNS çözümleme toplam süre sınırını aştı; tarama kısmi sonlandı.')
        if stop.is_set():
            raise Cancelled('Tarama durduruldu.')
        if time.monotonic() >= deadline:
            raise HaltScan('DNS çözümleme toplam süre sınırını aştı; tarama kısmi sonlandı.')
        if isinstance(result[0], Exception):
            raise result[0]
        addresses = result[0]
        if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
            raise ScopeError('Özel, yerel veya ayrılmış ağ adreslerine erişim engellendi.')
        # Validate every answer, then pin one to the actual socket.
        return addresses[0]


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    body: bytes

    @property
    def text(self):
        return self.body.decode('utf-8', errors='replace')

    @property
    def digest(self):
        return hashlib.sha256(self.body).hexdigest()


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, secure, timeout=6):
        super().__init__(host, port, timeout=timeout)
        self.ip = ip
        self.secure = secure
        self.active_socket = None

    def connect(self):
        sock = socket.create_connection((self.ip, self.port), self.timeout)
        self.sock = self.active_socket = sock
        if self.secure:
            try:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host, do_handshake_on_connect=False)
                self.sock = self.active_socket = sock
                sock.do_handshake()
            except Exception:
                sock.close()
                raise
        self.sock = sock


# GET can still have side effects. Never auto-visit operation-looking routes/queries.
UNSAFE = re.compile(r'(?:delete|remove|logout|signout|reset|transfer|pay|purchase|checkout|unsubscribe|disable|activate|execute|cancel|update|create|upload|write|password|token|session)', re.I)


def decoded_layers(value):
    layers = [value]
    for _ in range(8):
        decoded = unquote_plus(layers[-1])
        if decoded == layers[-1]:
            return layers
        layers.append(decoded)
    if unquote_plus(layers[-1]) != layers[-1]:
        raise ScopeError('Aşırı iç içe kodlanmış değer reddedildi.')
    return layers


def read_only_url(url):
    network_keys = {'url', 'uri', 'host', 'hostname', 'callback', 'redirect', 'redirect_uri', 'destination', 'endpoint', 'webhook', 'proxy'}
    try:
        for value in decoded_layers(url):
            p = urlsplit(value)
            if UNSAFE.search(p.path + '?' + p.query) or any(k.lower() in network_keys or '://' in v for k, v in parse_qsl(p.query)):
                return False
    except (ScopeError, ValueError):
        return False
    return True


class Transport:
    def __init__(self, origin, policy, stop=None, rate=2, budget=160, timeout=6):
        self.origin = canonical_origin(origin)
        self.policy = policy
        self.stop = stop or threading.Event()
        self.interval = 1 / max(0.5, min(float(rate), 100))
        self.budget = min(int(budget), 500)
        self.count = 0
        self.last = 0.0
        self.timeout = min(6, max(.1, float(timeout)))

    def check(self):
        if self.stop.is_set():
            raise Cancelled('Tarama durduruldu.')

    def get(self, url, cookie='', bearer='', follow=True):
        self.check()
        if canonical_origin(url) != self.origin:
            raise ScopeError('Kapsam dışı adres veya yönlendirme engellendi.')
        if self.count >= self.budget:
            raise HaltScan('İstek bütçesi doldu; tarama kısmi sonuçlarla sonlandı.')
        if any(c in cookie + bearer for c in '\r\n') or len(cookie + bearer) > 8192:
            raise ScopeError('Oturum değeri geçersiz.')
        delay = max(0, self.last + self.interval - time.monotonic())
        if self.stop.wait(delay):
            self.check()
        deadline = time.monotonic() + self.timeout
        ip = self.policy.address(url, self.stop, deadline)
        self.check()
        p = urlsplit(url)
        conn = _PinnedHTTP(p.hostname, p.port or (443 if p.scheme == 'https' else 80), ip, p.scheme == 'https', max(.01, deadline - time.monotonic()))
        finished = threading.Event()
        def interrupt():
            while not finished.wait(.025):
                if self.stop.is_set() or time.monotonic() >= deadline:
                    active = conn.active_socket
                    if active is not None:
                        try:
                            active.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                    # Keep watching if cancellation occurred during TCP connect.
        threading.Thread(target=interrupt, daemon=True).start()
        headers = {'User-Agent': 'safeZ/1.0 (bounded-read-only)', 'Accept': 'text/html,application/json,text/plain', 'Accept-Encoding': 'identity', 'Connection': 'close'}
        if cookie:
            headers['Cookie'] = cookie
        if bearer:
            headers['Authorization'] = 'Bearer ' + bearer
        self.count += 1
        self.last = time.monotonic()
        raw = None
        try:
            conn.request('GET', urlunsplit(('', '', p.path or '/', p.query, '')), headers=headers)
            raw = conn.getresponse()
            if raw.status == 429:
                raise HaltScan('Hedef hız sınırı bildirdi; tarama durduruldu.')
            body = raw.read(262145)
            self.check()
            if time.monotonic() >= deadline:
                raise HaltScan('İsteğin toplam süre sınırı aşıldı; tarama kısmi sonlandı.')
            if len(body) > 262144:
                raise ScopeError('Yanıt boyut sınırını aşıyor; bu adres atlandı.')
            response = Response(url, raw.status, {k.lower(): v for k, v in raw.getheaders()}, body)
        except (OSError, http.client.HTTPException):
            self.check()
            if time.monotonic() >= deadline:
                raise HaltScan('İsteğin toplam süre sınırı aşıldı; tarama kısmi sonlandı.') from None
            raise ScopeError('Hedef bağlantısı başarısız veya zaman aşımına uğradı.') from None
        finally:
            finished.set()
            if raw is not None:
                raw.close()
            conn.close()
        self.check()
        if 300 <= response.status < 400 and response.headers.get('location'):
            try:
                target = urljoin(url, response.headers['location'])
                redirected_origin = canonical_origin(target)
            except (ValueError, ScopeError):
                raise ScopeError('Geçersiz yönlendirme adresi engellendi.') from None
            if redirected_origin != self.origin:
                raise ScopeError('Kapsam dışı yönlendirme engellendi.')
            if follow:
                # Single redirect; a second redirect is returned, never an unbounded chain.
                if not read_only_url(target):
                    raise ScopeError('İşlem içerebilen yönlendirme atlandı.')
                return self.get(target, cookie, bearer, follow=False)
        return response
