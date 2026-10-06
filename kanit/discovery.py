"""Bounded discovery: static HTML/GET forms/JS literals and XML sitemaps."""
import json
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl, urlencode
from xml.etree import ElementTree
from .scope import canonical_origin, read_only_url, ScopeError, HaltScan

MAX_PAGES = 32
PARAMETER = re.compile(r'[A-Za-z_][A-Za-z0-9_.\[\]-]{0,79}')
ID_NAMES = {'id', 'item_id', 'product_id', 'record_id', 'article_id', 'page'}


def default_value(name):
    return '1' if name.lower() in ID_NAMES or name.lower().endswith('_id') else 'safezprobe'


def js_links(text):
    found = []
    pattern = r'''(?:fetch\s*\(|(?:axios\.)?get\s*\(|\burl\s*:)\s*["']([^"'`<>\s]{1,500})["']'''
    found.extend(re.findall(pattern, text[:131072]))
    found.extend(re.findall(r'''["'](/(?:api|rest|v[1-9])/[A-Za-z0-9_./?=&%-]{1,300})["']''', text[:131072]))
    return found[:24]


class Page(HTMLParser):
    def __init__(self, base):
        super().__init__()
        self.base, self.links, self.scripts, self.forms = base, [], [], []
        self.form = None
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and attrs.get('href'):
            self.links.append((attrs['href'], 'HTML bağlantısı'))
        if tag == 'script':
            self.in_script = True
            if attrs.get('src'):
                self.scripts.append(attrs['src'])
        if tag == 'form':
            try:
                action = urljoin(self.base, attrs.get('action') or '')
                canonical_origin(action)
            except (ValueError, ScopeError):
                self.form = None
                return
            self.form = {'url': action, 'method': (attrs.get('method') or 'GET').upper(), 'fields': []}
            self.forms.append(self.form)
        if tag in ('input', 'select', 'textarea') and self.form and PARAMETER.fullmatch(attrs.get('name') or ''):
            self.form['fields'].append({'name': attrs['name'], 'type': (attrs.get('type') or 'text').lower(), 'value': attrs.get('value') or default_value(attrs['name'])})

    def handle_data(self, data):
        if self.in_script:
            self.links.extend((link, 'Satır içi JavaScript') for link in js_links(data))

    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_script = False
        if tag == 'form' and self.form:
            if self.form['method'] == 'GET':
                p = urlsplit(self.form['url'])
                fields = [(f['name'], f['value']) for f in self.form['fields'] if f['type'] not in ('password', 'submit', 'file', 'button')]
                self.form['request_url'] = urlunsplit((p.scheme, p.netloc, p.path or '/', urlencode(fields), ''))
                self.links.append((self.form['request_url'], 'GET formu / varsayılan değer'))
            self.form = None


def discover(scanner):
    from .engine import _rows, safe_url
    origin = scanner.origin
    queue = [(origin + '/', 'Başlangıç'), (origin + '/robots.txt', 'Standart keşif'),
             (origin + '/sitemap.xml', 'Standart keşif')]
    queue.extend((origin + path, 'Yaygın salt okunur API adayı') for path in ('/api/products', '/api/items', '/api/search'))
    seen, derived = set(), set()
    numeric, targets = [], []
    scanner.observations = {}
    sources = {}
    report = scanner.report['discovery']
    scripts = set()
    form_requests = {}

    def enqueue(base, link, source):
        try:
            url = urljoin(base, link)
            p = urlsplit(url)
            url = urlunsplit((p.scheme, p.netloc, p.path or '/', p.query, ''))
            if canonical_origin(url) == origin and read_only_url(url) and url not in seen and len(queue) < 96:
                queue.append((url, source))
        except (ValueError, ScopeError):
            pass

    while queue and len(seen) < MAX_PAGES:
        scanner.transport.check()
        url, source = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            response = scanner.request(url, follow=False)
            scanner.observations[url] = response
            sources[url] = source
            report['pages'].append({'url': safe_url(url), 'status': response.status,
                                    'type': response.headers.get('content-type', '')[:100], 'source': source})
            scanner.har_entries.append(response)
            for form in form_requests.get(url, []):
                form['tested'] = True
            mime = response.headers.get('content-type', '').lower()
            if 300 <= response.status < 400 and response.headers.get('location'):
                enqueue(url, response.headers['location'], 'Kapsam içi yönlendirme')
            if response.status != 200:
                continue
            if 'html' in mime:
                parser = Page(response.url)
                parser.feed(response.text)
                for form in parser.forms:
                    form_report = {'url': safe_url(form['url']), 'method': form['method'],
                                            'fields': [{'name': f['name'], 'type': f['type']} for f in form['fields']],
                                            'tested': form.get('request_url') in scanner.observations, 'request_url': safe_url(form['request_url']) if form.get('request_url') else '', 'source': safe_url(url)}
                    report['forms'].append(form_report)
                    if form.get('request_url'):
                        form_requests.setdefault(form['request_url'], []).append(form_report)
                for link, why in parser.links:
                    enqueue(url, link, why)
                for link in parser.scripts:
                    if len(scripts) < 6:
                        scripts.add(link)
                        enqueue(url, link, 'JavaScript kaynağı')
            if 'javascript' in mime or urlsplit(url).path.endswith('.js'):
                for link in js_links(response.text):
                    enqueue(url, link, 'JavaScript ' + safe_url(url) + ' • satır ' + str(response.text.count('\n', 0, response.text.find(link)) + 1))
            if urlsplit(url).path == '/robots.txt':
                for line in response.text.splitlines()[:80]:
                    match = re.match(r'(?:Sitemap|Allow|Disallow):\s*(\S+)', line, re.I)
                    if match and '*' not in match[1] and match[1] != '/':
                        enqueue(url, match[1], 'robots.txt')
            if ('xml' in mime or urlsplit(url).path.endswith('.xml')) and '<!DOCTYPE' not in response.text.upper() and '<!ENTITY' not in response.text.upper():
                try:
                    tree = ElementTree.fromstring(response.text)
                    for element in tree.iter():
                        if element.tag.rsplit('}', 1)[-1] == 'loc' and element.text:
                            enqueue(url, element.text.strip(), 'XML sitemap')
                except ElementTree.ParseError:
                    pass
            query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
            for key, value in query:
                if not PARAMETER.fullmatch(key) or len(value) > 160:
                    continue
                report['parameters'].append({'url': safe_url(url), 'name': key, 'source': source})
                target = {'url': url, 'parameter': key, 'source': source}
                if sum(k == key for k, _ in query) != 1:
                    continue
                targets.append(target)
                if re.fullmatch(r'\d{1,8}', value) and _rows(response) not in (None, '[]'):
                    numeric.append(target)
            # Derive an id only from a real structured response; ignored ids must
            # still pass absent-record comparisons before any finding is emitted.
            if not query and _rows(response) not in (None, '[]') and url not in derived and len(derived) < 6:
                derived.add(url)
                data = json.loads(_rows(response))
                record = data[0]
                ids = [(key, str(value)) for key, value in record.items()
                       if key.lower() in ID_NAMES and isinstance(value, (int, str)) and re.fullmatch(r'\d{1,8}', str(value))]
                key, value = ids[0] if ids else ('id', '1')
                enqueue(url, urlsplit(url).path + '?' + urlencode({key: value}), 'JSON kaydı / türetilmiş parametre')
        except HaltScan:
            raise
        except ScopeError as error:
            report['skipped'].append({'url': safe_url(url), 'reason': str(error)})
    if queue:
        scanner.report['warnings'].append('Keşif 32 yanıtla sınırlandı. Dinamik JavaScript yürütülmez; statik API adresleri ve GET formları incelendi.')
    scanner.targets = targets[:8]
    scanner.sources = sources
    return numeric[:6]
