"""Read-only anonymous probes. Suspicions are kept separate from proved behavior."""
import json
import re
import secrets
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from .scope import ScopeError, HaltScan
from .engine import _rows, _query, snapshot, safe_url, digest


class Tables(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tables, self.rows, self.row, self.cell = [], None, None, None
        self.invalid = False

    def handle_starttag(self, tag, attrs):
        if self.invalid:
            return
        if tag == 'table':
            if self.rows is not None:
                self.invalid = True
                return
            self.rows = []
        if tag == 'tr' and self.rows is not None:
            if self.row is not None:
                self.invalid = True
                return
            self.row = []
        if tag == 'td' and self.row is not None:
            if self.cell is not None:
                self.invalid = True
                return
            self.cell = ''

    def handle_data(self, data):
        if not self.invalid and self.cell is not None:
            self.cell += data

    def handle_endtag(self, tag):
        if self.invalid:
            return
        if tag == 'td' and self.cell is not None:
            if self.row is None:
                self.invalid = True
                return
            self.row.append(' '.join(self.cell.split()))
            self.cell = None
        if tag == 'tr' and self.row is not None:
            if self.rows is None or self.cell is not None:
                self.invalid = True
                return
            if len(self.row) >= 2:
                self.rows.append(self.row)
            self.row = None
        if tag == 'table' and self.rows is not None:
            if self.row is not None or self.cell is not None:
                self.invalid = True
                return
            self.tables.append(self.rows)
            self.rows = None


def records(response):
    if response is None or response.status != 200:
        return None
    rows = _rows(response)
    if rows is not None:
        return rows
    if 'html' in response.headers.get('content-type', ''):
        parser = Tables()
        parser.feed(response.text)
        if not parser.invalid and parser.rows is None and len(parser.tables) == 1:
            return json.dumps(parser.tables[0], ensure_ascii=False)
    return None


def probe(scanner, url):
    try:
        return scanner.request(url)
    except HaltScan:
        raise
    except ScopeError as error:
        scanner.check_error = True
        scanner.report['discovery']['skipped'].append({'url': safe_url(url), 'reason': str(error)})
        return None


def value_of(target):
    return next((value for key, value in parse_qsl(urlsplit(target['url']).query, keep_blank_values=True)
                 if key == target['parameter']), '')


def summarize(scanner, kind, name, start, applicable, detail):
    count = scanner.transport.count - start
    state = 'inconclusive' if scanner.check_error else ('tested' if count else 'skipped')
    scanner.coverage(kind, name, state,
                     detail if count else 'Uygun girdi bulunamadı; hedefte API/parametre oluşturulamaz.', count)


def string_sql(scanner, targets):
    start = scanner.transport.count
    applicable = []
    for target in targets:
        observed = scanner.observations.get(target['url'])
        value = value_of(target)
        if observed is None or re.fullmatch(r'\d{1,8}', value) and _rows(observed) not in (None, '[]'):
            continue
        if len(value) > 80 or not value:
            continue
        applicable.append(target)
        if len(applicable) == 3:
            break
    for target in applicable:
        url, key, value = target['url'], target['parameter'], value_of(target)
        evidence, valid = [], True
        for number in (451, 927):
            normal = probe(scanner, url)
            truth = probe(scanner, _query(url, key, value + "' AND 'safez" + str(number) + "'='safez" + str(number)))
            false = probe(scanner, _query(url, key, value + "' AND 'safez" + str(number) + "'='safez" + str(number + 1)))
            absent = probe(scanner, _query(url, key, 'SAFEZ_ABSENT_' + secrets.token_hex(6)))
            if not all((normal, truth, false, absent)):
                valid = False
                break
            base = records(normal)
            valid &= base not in (None, '[]') and records(truth) == base and records(false) == records(absent) == '[]'
            evidence.extend([snapshot(normal, 'Normal metin sorgusu'), snapshot(truth, 'Doğru SQL metin koşulu'),
                             snapshot(false, 'Yanlış SQL metin koşulu'), snapshot(absent, 'Bulunmayan kayıt kontrolü')])
            if not valid:
                break
        if valid:
            scanner.finding('sqli', 'Metin parametresi SQL kayıt filtresini değiştiriyor', 'medium', url,
                            'İki bağımsız doğru/yanlış sabit koşul, JSON kayıt veya HTML tablo sonuçlarını normal ve bulunmayan kayıtla karşılaştırdı.',
                            'Kullanıcı girdisi SQL kayıt filtresini etkiliyor. Hassas veriye erişim, yazma veya komut yürütme kanıtlanmadı.',
                            'SQL metnine kullanıcı girdisi eklemeyin. Parametreli sorgu ve sunucu tarafında kullanıcı/tenant filtresi kullanın.',
                            ['Etkilenen GET parametresini sabit, yapay kayıtla okuyun.', 'Doğru/yanlış metin sabit koşulları ve bulunmayan kayıt değerini karşılaştırın.', 'Farklı sabitlerle ikinci kez deneyin; ilgili sorguyu sunucu kodunda inceleyin.'], evidence, key)
    count = scanner.transport.count - start
    if count:
        previous = next((c for c in scanner.report['coverage'] if c['kind'] == 'sqli'), None)
        scanner.coverage('sqli', 'SQL enjeksiyonu', 'tested',
                         'Sayısal ve/veya metin GET parametrelerinde kontrollü koşul karşılaştırmaları yapıldı. JSON kayıtları ve tek HTML tablo desteklenir; hata mesajı/yansıma tek başına kanıt değildir.',
                         count + (previous['requests'] if previous else 0))


def operator_url(url, key, operator, value):
    p = urlsplit(url)
    query = [(key + '[' + operator + ']', value) if k == key else (k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(query), ''))


def nosql(scanner, targets):
    start = scanner.transport.count
    applicable = [t for t in targets if '[' not in t['parameter'] and records(scanner.observations.get(t['url'])) not in (None, '[]')][:3]
    for target in applicable:
        url, key, value = target['url'], target['parameter'], value_of(target)
        evidence, valid = [], True
        for _ in range(2):
            responses = [probe(scanner, url), probe(scanner, operator_url(url, key, '$eq', value)),
                         probe(scanner, operator_url(url, key, '$ne', value)),
                         probe(scanner, operator_url(url, key, '$eq', '987654321'))]
            if not all(responses):
                valid = False
                break
            base, eq, ne, absent = map(records, responses)
            valid &= base not in (None, '[]') and eq == base and ne not in (None, '[]', base) and absent == '[]'
            evidence.extend(snapshot(r, label) for r, label in zip(responses, ('Skaler normal sorgu', 'Eşitlik operatörü', 'Eşitsizlik operatörü', 'Bulunmayan kayıt kontrolü')))
            if not valid:
                break
        if valid:
            scanner.finding('nosql', 'Skaler parametre NoSQL operatörlerini kabul ediyor', 'medium', url,
                            'Skaler, eşitlik, eşitsizlik ve bulunmayan kayıt sonuçları iki turda aynı karşılaştırmayı verdi.',
                            'Operatör girdisi kayıt filtresini değiştirdi. API operatörleri bilinçli destekliyor olabilir; özel kayıt erişimi ve yetki atlama doğrulanmadı.',
                            'Skaler alanların türünü doğrulayın; beklenmeyen iç içe/operatör anahtarlarını reddedin. Zorunlu sahiplik filtresini kullanıcı girdisinden bağımsız kurun.',
                            ['Yapay kayıtta skaler ve $eq/$ne biçimlerini karşılaştırın.', 'Bulunmayan kaydı kontrol edin; ikinci turda tekrarlayın.', 'Operatör desteğinin tasarım gereği olup olmadığını ve sahiplik filtresini kodda inceleyin.'], evidence, key, status='suspected')
    summarize(scanner, 'nosql', 'NoSQL skaler / operatör kontrolü', start, applicable,
              'Yapılandırılmış GET kayıtlarında skaler/$eq/$ne ve bulunmayan kayıt karşılaştırıldı. Operatör kabulü tek başına yetki açığı sayılmaz.')


def ssti(scanner, targets):
    start = scanner.transport.count
    applicable = [t for t in targets if len(value_of(t)) <= 80][:3]
    for target in applicable:
        url, key = target['url'], target['parameter']
        found = False
        for opening, closing in (('{{', '}}'), ('${', '}')):
            evidence, valid = [], True
            for left, right in ((137, 193), (149, 211)):
                prefix = 'SZ' + secrets.token_hex(5) + '_'
                suffix = '_END'
                payload = prefix + opening + str(left) + '*' + str(right) + closing + suffix
                expected = prefix + str(left * right) + suffix
                responses = [probe(scanner, url), probe(scanner, _query(url, key, payload)),
                             probe(scanner, _query(url, key, prefix + 'LITERAL' + suffix)),
                             probe(scanner, _query(url, key, prefix + opening + str(left) + '*' + closing + suffix))]
                if not all(responses):
                    valid = False
                    break
                normal, evaluated, literal, malformed = responses
                valid &= evaluated.status == 200 and expected in evaluated.text and payload not in evaluated.text
                valid &= all(expected not in r.text for r in (normal, literal, malformed))
                evidence.extend(snapshot(r, label, expected) for r, label in zip(responses, ('Normal değer', 'Aritmetik şablon ifadesi', 'Düz metin negatif kontrol', 'Geçersiz ifade negatif kontrol')))
                if not valid:
                    break
            if valid:
                scanner.finding('ssti', 'Girdi sunucu tarafında şablon ifadesi olarak hesaplanıyor', 'medium', url,
                                'İki farklı aritmetik ifade benzersiz işaretleyiciler arasında hesaplanmış sonucu verdi; düz metin ve geçersiz ifade kontrolleri vermedi.',
                                'Bu parametrede sunucu tarafı ifade değerlendirmesi doğrulandı. İşletim sistemi komutu, dosya erişimi veya kod yürütme etkisi doğrulanmadı.',
                                'Kullanıcı girdisini şablon kaynak kodu olarak derlemeyin. Sabit şablonda veri olarak bağlayın ve bağlama uygun çıktı kaçışı uygulayın.',
                                ['Etkilenen GET parametresine zararsız, işaretleyicili bir çarpma ifadesi girin.', 'Normal değer, düz metin ve geçersiz ifadeyle karşılaştırın.', 'Farklı sayılarla tekrarlayın; sunucunun şablon derleme çağrısını inceleyin.'], evidence, key)
                found = True
                break
        if found:
            continue
    summarize(scanner, 'ssti', 'Sunucu tarafı şablon ifadesi (SSTI)', start, applicable,
              'Zararsız {{…}} ve ${…} aritmetik ifadeleri negatif kontrollerle denendi. Komut yürütme ve dosya erişimi denenmedi.')


class ElementProbe(HTMLParser):
    # Python 3.9 HTMLParser only recognizes script/style raw text by default.
    # Match browser inert contexts conservatively without executing JavaScript.
    RAW_TEXT = ('script', 'style', 'textarea', 'title', 'xmp', 'iframe',
                'noembed', 'noframes', 'noscript', 'plaintext')
    CDATA_CONTENT_ELEMENTS = RAW_TEXT

    def __init__(self, marker):
        super().__init__()
        self.marker, self.found = marker, False
        self.raw_tag, self.template_depth = None, 0

    def handle_starttag(self, tag, attrs):
        if self.raw_tag:
            return
        if tag in self.RAW_TEXT:
            self.raw_tag = tag
        elif tag == 'template':
            self.template_depth += 1
        elif not self.template_depth and tag == 'safez-probe' and dict(attrs).get('data-safez') == self.marker:
            self.found = True

    def handle_endtag(self, tag):
        if self.raw_tag:
            if tag == self.raw_tag and tag != 'plaintext':
                self.raw_tag = None
        elif tag == 'template' and self.template_depth:
            self.template_depth -= 1


def reflected(scanner, targets):
    start = scanner.transport.count
    applicable = [t for t in targets if 'html' in scanner.observations[t['url']].headers.get('content-type', '')][:3]
    for target in applicable:
        url, key = target['url'], target['parameter']
        evidence, valid = [], True
        for _ in range(2):
            marker = secrets.token_hex(10)
            payload = '<safez-probe data-safez="' + marker + '"></safez-probe>'
            normal = probe(scanner, url)
            response = probe(scanner, _query(url, key, payload))
            control = probe(scanner, _query(url, key, marker))
            if not all((normal, response, control)):
                valid = False
                break
            parser = ElementProbe(marker)
            parser.feed(response.text)
            negative = ElementProbe(marker)
            negative.feed(control.text)
            valid &= response.status == 200 and 'html' in response.headers.get('content-type', '') and parser.found and not negative.found
            evidence.extend([snapshot(normal, 'Normal HTML'), snapshot(response, 'Zararsız özel HTML öğesi', marker), snapshot(control, 'Düz işaretleyici negatif kontrol', marker)])
            if not valid:
                break
        if valid:
            scanner.finding('xss_reflection', 'Girdi HTML öğesi oluşturabiliyor; XSS etkisi incelenmeli', 'medium', url,
                            'Zararsız özel HTML öğesi iki yanıtta HTML ayrıştırıcısında oluştu; düz işaretleyici kontrolünde oluşmadı.',
                            'HTML enjeksiyonu gözlendi. JavaScript yürütmesi, kalıcılık ve ayrıcalıklı kullanıcı etkisi doğrulanmadığından XSS şüpheli kalır.',
                            'Girdiyi bulunduğu HTML bağlamına göre kaçırın. Güvensiz innerHTML/şablon eklemesinden kaçının; izin verilen işaretlemeyi temizleyin.',
                            ['GET parametresine zararsız özel öğe işaretleyicisi girin.', 'Düz işaretleyiciyle karşılaştırın ve yeni işaretleyiciyle tekrarlayın.', 'Çıktı bağlamını sunucu/istemci kodunda inceleyin; yansımayı tek başına çalışan XSS saymayın.'], evidence, key, status='suspected')
    summarize(scanner, 'xss_reflection', 'HTML yansıma / XSS adayı', start, applicable,
              'HTML yanıtlarına zararsız özel öğe ve düz metin kontrolü gönderildi. Tarayıcıda JavaScript ve kalıcı kayıt testi yapılmadı.')


SECRET_NAME = r'(?:DB|DATABASE)[_-]?(?:PASSWORD|PASS|URL)|SECRET[_-]?KEY|CLIENT[_-]?SECRET|AWS[_-]?SECRET[_-]?ACCESS[_-]?KEY'
SECRET_ASSIGNMENT = re.compile(r'''(?im)^[ \t]*["']?(''' + SECRET_NAME + r''')["']?\s*[:=]\s*["']?([^\r\n"',]{8,300})''')
PLACEHOLDER = re.compile(r'^(?:[xX*•]+|null|none|undefined|changeme|change_me|password|secret|example|your[_-].*|\$\{.*\}|<.*>)$', re.I)


def credentials(response):
    if response is None or response.status != 200 or 'html' in response.headers.get('content-type', '').lower():
        return []
    text = response.text
    candidates = []
    if text.lstrip().startswith(('{', '[')):
        try:
            data = json.loads(text)
        except (ValueError, RecursionError):
            return []
        pending = [data]
        # Iterative traversal avoids Python recursion on untrusted response data.
        visited = 0
        while pending and visited < 8192:
            item = pending.pop()
            visited += 1
            if isinstance(item, dict):
                for name, value in item.items():
                    if re.fullmatch(SECRET_NAME, name, re.I) and isinstance(value, str):
                        token = json.dumps(name, ensure_ascii=False)
                        position = text.find(token)
                        line = text.count('\n', 0, position) + 1 if position >= 0 and text.count(token) == 1 else None
                        candidates.append((name, value, line))
                    elif isinstance(value, (dict, list)):
                        pending.append(value)
            elif isinstance(item, list):
                pending.extend(value for value in item if isinstance(value, (dict, list)))
    else:
        candidates = [(match[1], match[2].strip(), text.count('\n', 0, match.start()) + 1)
                      for match in SECRET_ASSIGNMENT.finditer(text)]
    found = []
    for name, value, line in candidates:
        if not 8 <= len(value) <= 300 or PLACEHOLDER.fullmatch(value) or len(set(value)) < 5:
            continue
        if name.upper().endswith('URL'):
            try:
                parsed = urlsplit(value)
                if not parsed.username or not parsed.password or PLACEHOLDER.fullmatch(parsed.password):
                    continue
            except ValueError:
                continue
        found.append({'name': name, 'value_sha256': digest(value),
                      'line': line})
    return found


def exposure(scanner):
    start = scanner.transport.count
    absent_url = scanner.origin + '/safez-absent-' + secrets.token_hex(12) + '.txt'
    absent = probe(scanner, absent_url)
    if absent is None:
        return summarize(scanner, 'secrets', 'Açık yapılandırma / sır sızıntısı', start, [], 'Negatif kontrol tamamlanamadı.')
    for path in ('/.env', '/config.json', '/config.yml', '/config.yaml'):
        url = scanner.origin + path
        first = probe(scanner, url)
        hints = credentials(first)
        if not hints or credentials(absent):
            continue
        second = probe(scanner, url)
        if second is None or credentials(second) != hints or first.digest == absent.digest:
            continue
        evidence = [snapshot(absent, 'Bulunmayan dosya negatif kontrolü'), snapshot(first, 'Yapılandırma dosyası ilk okuma'), snapshot(second, 'Yapılandırma dosyası ikinci okuma')]
        scanner.finding('secrets', 'Yapılandırma dosyası kimlik bilgisine benzeyen değerler içeriyor', 'high', url,
                        'Açık dosyada maskelenmemiş kimlik bilgisi atamaları iki okumada aynıydı; rastgele bulunmayan dosyada yoktu.',
                        'Sunucu yapılandırma içeriği bu adreste herkese açık. Bulunan değerler raporda saklanmaz; geçerlilikleri veya hesap yetkileri denenmedi.',
                        'Yapılandırmaları web kökünden kaldırın ve erişimi sunucuda engelleyin. Açığa çıkan değerleri döndürün, erişim günlüklerini inceleyin ve sır yöneticisi kullanın.',
                        ['Bildirilen dosya adresini GET ile kontrol edin; içeriği paylaşmayın.', 'Yanıttaki bildirilen satır ve atama adını yerel olarak inceleyin.', 'Erişimi engelledikten sonra bulunmayan dosya kontrolüyle yeniden karşılaştırın.'], evidence,
                        location={'response_line': hints[0]['line'], 'fields': [h['name'] for h in hints]})
    summarize(scanner, 'secrets', 'Açık yapılandırma / sır sızıntısı', start, [True],
              'Dört yapılandırma adresi ve rastgele bulunmayan dosya karşılaştırıldı. Maske/örnek değerler elenir; sırların kullanılabilirliği denenmez.')
    start = scanner.transport.count
    scanner.active_check = {'kind': 'source', 'name': 'Açık depo üst bilgisi', 'start': start}
    scanner.check_error = False
    url = scanner.origin + '/.git/HEAD'
    first = probe(scanner, url)
    pattern = r'ref: refs/heads/[A-Za-z0-9_./-]+\s*'
    if first and first.status == 200 and re.fullmatch(pattern, first.text) and not re.fullmatch(pattern, absent.text):
        second = probe(scanner, url)
        if second and second.status == 200 and second.text == first.text:
            scanner.finding('source', 'Git depo üst bilgisi dışarıdan okunabiliyor', 'low', url,
                            'Git HEAD başvurusu iki okumada aynıydı; bulunmayan dosya kontrolünde yoktu.',
                            'Depo üst bilgisi açığa çıkıyor. Kaynak kodu veya sırlar indirilmedi; hassas etki doğrulanmadı.',
                            '.git dizinine erişimi engelleyin; yalnızca gerekli derleme dosyalarını web köküne dağıtın.',
                            ['Bildirilen .git/HEAD adresini kontrol edin.', 'Rastgele bulunmayan dosyayla karşılaştırın.', 'Dizini engelleyip yeniden kontrol edin; depo nesnelerini indirmeyin.'],
                            [snapshot(first, 'Git HEAD ilk okuma'), snapshot(second, 'Git HEAD ikinci okuma'), snapshot(absent, 'Bulunmayan dosya negatif kontrolü')], status='suspected')
    summarize(scanner, 'source', 'Açık depo üst bilgisi', start, [True], 'Git HEAD ve bulunmayan dosya kontrol edildi; kaynak kodu/depo nesneleri indirilmedi.')


def run_extra(scanner):
    targets = scanner.targets
    def run(kind, name, function, *args):
        scanner.active_check = {'kind': kind, 'name': name, 'start': scanner.transport.count}
        scanner.check_error = False
        function(scanner, *args)
        scanner.active_check = None
    scanner.stage('Metin SQL ve NoSQL karşılaştırmaları', 42)
    run('sqli', 'SQL enjeksiyonu', string_sql, targets)
    run('nosql', 'NoSQL skaler / operatör kontrolü', nosql, targets)
    scanner.stage('Şablon ifadeleri ve HTML bağlamı', 55)
    run('ssti', 'Sunucu tarafı şablon ifadesi', ssti, targets)
    run('xss_reflection', 'HTML yansıma / XSS adayı', reflected, targets)
    scanner.stage('Açık yapılandırma ve depo kontrolü', 68)
    run('secrets', 'Açık yapılandırma / sır sızıntısı', exposure)
