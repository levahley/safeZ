"""ZAP passive foundation: import recorded HAR with sendRequests=false.

ZAP never performs discovery, active scanning or networking to the target.
The local, dedicated engine must be owned by this application.
"""
import datetime
import hashlib
import json
import time
import os
import tempfile
from pathlib import Path
import urllib.error
import urllib.request
from urllib.parse import urlencode, urlsplit
from .scope import canonical_origin, Cancelled, ScopeError
from .engine import safe_url
from .explanations import passive_text


class Zap:
    def __init__(self, endpoint, key):
        p = urlsplit(endpoint)
        if p.scheme != 'http' or p.hostname != '127.0.0.1' or not p.port or p.path not in ('', '/'):
            raise ValueError('ZAP yalnızca yerel, ayrılmış 127.0.0.1 portunda çalışmalı.')
        self.endpoint = canonical_origin(endpoint)
        self.key = key
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(self, component, operation, action, params=None):
        url = self.endpoint + '/JSON/' + component + '/' + operation + '/' + action + '/'
        payload = urlencode(params or {}).encode()
        headers = {'X-ZAP-API-Key': self.key, 'Content-Type': 'application/x-www-form-urlencoded'}
        # GET for views, POST for actions; credentials never appear in URL/logs.
        request = urllib.request.Request(url + ('?' + payload.decode() if operation == 'view' else ''), data=payload if operation == 'action' else None, headers=headers)
        with self.opener.open(request, timeout=8) as r:
            body = r.read(2_000_001)
            if len(body) > 2_000_000:
                raise ValueError('Motor yanıtı boyut sınırını aştı.')
            data = json.loads(body)
        if 'code' in data:
            raise ValueError('ZAP API işlemi başarısız.')
        return data

    def inspect(self, responses, origin, stop):
        result = {'engine': {'name': 'OWASP ZAP', 'state': 'unavailable', 'detail': 'Motor bağlı değil; pasif inceleme yapılmadı.'}, 'alerts': []}
        try:
            version = self.api('core', 'view', 'version')['version']
            self.api('core', 'action', 'newSession', {'name': '', 'overwrite': 'true'})
            self.api('core', 'action', 'setMode', {'mode': 'safe'})
            entries = []
            for r in responses:
                if stop.is_set():
                    raise Cancelled()
                headers = [{'name': k, 'value': v} for k, v in r.headers.items() if k not in ('set-cookie', 'cookie', 'authorization', 'proxy-authorization', 'www-authenticate')]
                entries.append({'startedDateTime': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'time': 0, 'request': {'method': 'GET', 'url': r.url, 'httpVersion': 'HTTP/1.1', 'headers': [], 'queryString': [], 'cookies': [], 'headersSize': -1, 'bodySize': 0}, 'response': {'status': r.status, 'statusText': '', 'httpVersion': 'HTTP/1.1', 'headers': headers, 'cookies': [], 'content': {'size': len(r.body), 'mimeType': r.headers.get('content-type', 'text/plain'), 'text': r.text}, 'redirectURL': '', 'headersSize': -1, 'bodySize': len(r.body)}, 'cache': {}, 'timings': {'send': 0, 'wait': 0, 'receive': 0}})
            har = {'log': {'version': '1.2', 'creator': {'name': 'safeZ', 'version': '1.0'}, 'entries': entries}}
            # ZAP 2.17 ships exim 0.16, whose API requires filePath. Supplying
            # recorded responses imports offline; sendHarRequest is never used.
            # Newer exim versions additionally honor sendRequests=false.
            har_dir = Path(__file__).parent.parent / 'work' / 'har'
            har_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(har_dir, 0o700)
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.har', dir=har_dir, delete=False) as stream:
                json.dump(har, stream)
                har_path = stream.name
            try:
                self.api('exim', 'action', 'importHar', {'filePath': har_path, 'sendRequests': 'false', 'maxMessages': str(len(entries))})
            finally:
                os.unlink(har_path)
            deadline = time.monotonic() + 30
            while int(self.api('pscan', 'view', 'recordsToScan')['recordsToScan']) > 0:
                if time.monotonic() > deadline:
                    result['engine'].update(state='partial', detail='Pasif motor zaman sınırına ulaştı; uyarılar eksik olabilir.')
                    break
                if stop.wait(0.3):
                    raise Cancelled()
            else:
                result['engine'].update(state='complete', detail='Keşif yanıtları yerel ZAP ' + version + ' ile pasif incelendi; ZAP hedefe istek göndermedi.')
            alerts = self.api('core', 'view', 'alerts', {'baseurl': origin, 'start': 0, 'count': 100})['alerts']
            seen = set()
            for alert in alerts:
                try:
                    if canonical_origin(alert.get('url', '')) != origin:
                        continue
                except ScopeError:
                    continue
                identity = str(alert.get('pluginId', '')) + alert.get('alert', '') + alert.get('url', '')
                if identity in seen:
                    continue
                seen.add(identity)
                result['alerts'].append({**passive_text(alert), 'url': safe_url(alert['url']), 'status': 'suspected', 'severity': {'High': 'high', 'Medium': 'medium', 'Low': 'low', 'Informational': 'info'}.get(alert.get('risk'), 'info'), 'evidence_sha256': hashlib.sha256(alert.get('evidence', '').encode()).hexdigest()})
            # Drop transient recorded responses from the dedicated ZAP session.
            self.api('core', 'action', 'newSession', {'name': '', 'overwrite': 'true'})
        except (OSError, ValueError, KeyError, urllib.error.URLError):
            result['engine'].update(state='unavailable', detail='Yerel ZAP bağlantısı/API işlemi başarısız; pasif inceleme tamamlanmadı.')
        return result
