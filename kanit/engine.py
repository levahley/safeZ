"""Comparative checks. Findings only contain hashes and masked evidence."""
import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from .scope import Cancelled, Policy, ScopeError, HaltScan, Transport, canonical_origin, read_only_url, decoded_layers


LIMITATIONS = [
    ('command', 'İşletim sistemi komut enjeksiyonu', 'İşletim sistemi komutu yürütülmedi; izole komut testi senaryosu yok.'),
    ('files', 'Dosya yazma / yükleme', 'Açık yapılandırma dosyaları ayrıca kontrol edildi. Yazma/yükleme ve keyfi dosya okuma için izole test kaydı/temizleme senaryosu yok.'),
    ('ssrf', 'SSRF', 'Kontrol edilen dış doğrulama servisi kurulmadı; SSRF testi gönderilmedi.'),
    ('xss', 'Kalıcı / ayrıcalıklı XSS', 'Tarayıcı yürütmesi ve kalıcı kayıt kontrolü uygulanmadı.'),
    ('logic', 'İş mantığı / işlev düzeyi yetki', 'İşlem yazma, yönetici işlevi ve akış atlama testleri uygulanmadı.'),
    ('recovery', 'Parola sıfırlama / oturum yaşam döngüsü', 'Sıfırlama, oturum sabitleme ve çıkış sonrası geçersizleştirme uygulanmadı.'),
]


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def safe_url(url):
    p = urlsplit(url)
    # Preserve parameter names, never persist user values or secrets in URLs.
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode([(k, '[maskeli]') for k, v in parse_qsl(p.query)]), ''))


def snapshot(response, label, marker=None):
    row = {'request': safe_url(response.url), 'method': 'GET', 'test': label, 'http_status': response.status, 'sha256': response.digest, 'bytes': len(response.body)}
    if marker is not None:
        row.update(marker_sha256=digest(marker), marker_present=marker in response.text)
    return row


def _rows(response):
    if response.status != 200 or 'json' not in response.headers.get('content-type', ''):
        return None
    try:
        data = json.loads(response.text)
    except (ValueError, RecursionError):
        return None
    if isinstance(data, list):
        arrays = [data]
    elif isinstance(data, dict):
        arrays = [v for v in data.values() if isinstance(v, list)]
    else:
        return None
    if len(arrays) != 1 or any(not isinstance(x, dict) for x in arrays[0]):
        return None
    # Ignore reflected scalar inputs; only compare actual structured records.
    try:
        return json.dumps(arrays[0], sort_keys=True, ensure_ascii=False)
    except RecursionError:
        return None


def _query(url, key, value):
    p = urlsplit(url)
    query = parse_qsl(p.query, keep_blank_values=True)
    if sum(k == key for k, v in query) != 1:
        raise ScopeError('Enjeksiyon parametresi adreste tek kez bulunmalı.')
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode([(k, value if k == key else v) for k, v in query]), ''))


class Scanner:
    def __init__(self, origin, policy, stop=None, rate=2, budget=240, progress=None, zap=None):
        self.origin = canonical_origin(origin)
        self.transport = Transport(origin, policy, stop, rate, budget)
        self.progress = progress or (lambda *args: None)
        self.zap = zap
        self.report = {'origin': self.origin, 'findings': [], 'coverage': [], 'discovery': {'pages': [], 'forms': [], 'parameters': [], 'skipped': []}, 'warnings': [], 'relationships': [], 'engine': {'name': 'OWASP ZAP', 'state': 'unavailable', 'detail': 'Motor bağlı değil; pasif inceleme yapılmadı.'}, 'passive_alerts': [], 'requests': 0, 'conclusion': 'Bu sonuçlar sitenin tamamen güvenli olduğunu göstermez.'}
        self.har_entries = []
        self.targets, self.observations, self.sources = [], {}, {}
        self.active_check = None
        self.check_error = False
        self.report['complete'] = False

    def stage(self, name, percent):
        self.transport.check()
        self.progress(name, percent, self.transport.count)

    def request(self, url, account=None, follow=True):
        if not read_only_url(url):
            raise ScopeError('İşlem içerebilen adres atlandı. Yalnızca salt okunur test uçlarını kullanın.')
        return self.transport.get(url, follow=follow, **{k: v for k, v in (account or {}).items() if k in ('cookie', 'bearer')})

    def coverage(self, kind, name, state, detail, requests=0):
        from .explanations import NAMES, coverage_text
        row = {'kind': kind, 'name': name, 'name_en': NAMES.get(kind, kind), 'state': state,
               'detail': detail, 'detail_en': coverage_text(kind, state, detail), 'requests': requests}
        self.report['coverage'] = [c for c in self.report['coverage'] if c['kind'] != kind]
        self.report['coverage'].append(row)
        if self.active_check and self.active_check['kind'] == kind:
            self.active_check = None

    def finding(self, kind, title, severity, url, condition, impact, fix, steps, evidence, parameter='', status='confirmed', location=None):
        from .explanations import finding_text
        p = urlsplit(url)
        where = {'method': 'GET', 'endpoint': urlunsplit((p.scheme, p.netloc, p.path, '', '')),
                 'parameter': parameter, 'discovery_source': self.sources.get(url, 'Test adresi'),
                 'server_code_line_known': False}
        where.update(location or {})
        self.report['findings'].append({'id': digest(kind + url + parameter), 'kind': kind, 'title': title,
             'status': status, 'severity': severity, 'url': safe_url(url), 'parameter': parameter,
             'condition': condition, 'impact': impact, 'note': impact if status == 'suspected' else '',
             'fix': fix, 'steps': steps, 'evidence': evidence, 'repeats': 2, 'location': where,
             'english': finding_text(kind, status, severity), 'cwe': {'sqli': 89, 'nosql': 943, 'ssti': 1336,
             'xss_reflection': 79, 'secrets': 200, 'source': 538, 'bola': 639, 'auth': 306}.get(kind)})

    def discover(self):
        from .discovery import discover
        return discover(self)

    def sqli(self, configs):
        self.active_check = {'kind': 'sqli', 'name': 'SQL enjeksiyonu', 'start': self.transport.count}
        count = 0
        notes = []
        for cfg in configs[:6]:
            start = self.transport.count
            url, key = cfg['url'], cfg['parameter']
            values = [v for k, v in parse_qsl(urlsplit(url).query) if k == key]
            if len(values) != 1 or not re.fullmatch(r'\d{1,8}', values[0]):
                notes.append('Yalnızca sayısal GET parametreleri ve yapılandırılmış JSON kayıtları desteklenir.')
                continue
            value = values[0]
            evidence = []
            success = True
            positive_rounds = 0
            for number in (451, 927):
                base = self.request(url)
                truth = self.request(_query(url, key, value + ' AND (SELECT ' + str(number) + ')=' + str(number)))
                false = self.request(_query(url, key, value + ' AND (SELECT ' + str(number) + ')=' + str(number + 1)))
                empty = self.request(_query(url, key, '987654321'))
                rows = _rows(base)
                valid = rows not in (None, '[]') and _rows(truth) == rows and _rows(false) == '[]' and _rows(empty) == '[]'
                evidence.extend([snapshot(base, 'Normal sorgu'), snapshot(truth, 'Doğru SQL sabit koşulu'), snapshot(false, 'Yanlış SQL sabit koşulu'), snapshot(empty, 'Bulunmayan kayıt kontrolü')])
                if not valid:
                    success = False
                    break
                positive_rounds += 1
            if success:
                severity = 'medium'
                impact = 'Kullanıcı girdisi sorgunun SQL koşulunu değiştiriyor. İki farklı sabit SELECT koşulu normal ve boş kayıt sonuçlarını tekrarladı. Hassas veri erişimi veya yazma etkisi henüz kanıtlanmadı.'
                marker = cfg.get('restricted_marker', '')
                restricted = cfg.get('restricted_value', '')
                if marker and re.fullmatch(r'\d{1,8}', restricted) and cfg.get('impact') == 'sensitive':
                    expanded = []
                    for number in (451, 927):
                        denied = self.request(_query(url, key, restricted))
                        bypass = self.request(_query(url, key, value + ' OR (SELECT ' + str(number) + ')=' + str(number)))
                        evidence.extend([snapshot(denied, 'Kısıtlı test kaydı normal erişim', marker), snapshot(bypass, 'Kapsam koşulu atlama', marker)])
                        expanded.append(marker not in base.text and denied.status in (200, 403, 404) and marker not in denied.text and bypass.status == 200 and marker in bypass.text and _rows(bypass) not in (None, '[]', rows))
                    if all(expanded):
                        severity = 'high'
                        impact = 'Normal sorguyla erişilemeyen, hassas olarak tanımladığınız test kaydı iki farklı SQL sabit koşuluyla okundu. Kayıt/tenant filtresi atlanabiliyor; gerçek veri değiştirilmedi.'
                self.finding('sqli', 'SQL sorgu koşulu kullanıcı girdisiyle değişiyor', severity, url, 'Sayısal GET parametresi; sabit SQL alt sorguları iki turda aynı kayıt karşılaştırmasını verdi.', impact, 'Sorguyu parametreli hazırlayın. Kullanıcı/tenant koşulunu sunucuda uygulayın; erişim kontrolünü SQL metni birleştirerek kurmayın. Veritabanı hesabının yetkilerini daraltın.', ['Kendi test kaydınızın sayısal parametresini normal değeriyle okuyun.', 'Aynı değere AND (SELECT 451)=451 ve AND (SELECT 451)=452 ekleyerek kayıt sonuçlarını karşılaştırın.', 'İkinci turda 927/928 sabitleriyle tekrarlayın. Hassas test kaydı varsa normal erişim ile OR sabit koşulunun etkisini karşılaştırın.'], evidence, key)
            elif positive_rounds:
                self.finding('sqli', 'SQL koşulu karşılaştırması tutarlı tekrarlanamadı', 'medium', url, 'Bir turda SQL sabit koşulu kayıt sonuçlarını değiştirdi.', 'İkinci tur ilk sonucu doğrulamadı. Dinamik yanıt veya farklı bir girdi işleme davranışı olabilir; SQL enjeksiyonu doğrulanmadı.', 'İlgili sorgunun parametreli olduğunu kodda inceleyin; sabit test kayıtlarıyla tekrar karşılaştırın.', ['Salt okunur test kaydında iki farklı sabit koşul çiftini tekrar karşılaştırın.'], evidence, key, status='suspected')
            count += self.transport.count - start
        self.coverage('sqli', 'SQL enjeksiyonu', 'tested' if count else 'skipped', '; '.join(notes) or ('Sabit koşul ve boş kayıt karşılaştırmaları çalıştı. Bulgusuz sonuç yalnızca test edilen parametreleri kapsar.' if count else 'Uygun JSON/sayısal parametre keşfedilmedi veya eklenmedi.'), count)

    def bola(self, cfg, accounts, identity=None):
        self.active_check = {'kind': 'bola', 'name': 'Kullanıcılar arası yetki (BOLA)', 'start': self.transport.count}
        if not cfg or not accounts.get('a') or not accounts.get('b'):
            return self.coverage('bola', 'Kullanıcılar arası yetki (BOLA)', 'skipped', 'İki farklı test hesabı ve her birinin özel test kaydı gerekli.')
        if accounts['a'] == accounts['b']:
            return self.coverage('bola', 'Kullanıcılar arası yetki (BOLA)', 'skipped', 'İki hesabın oturumu aynı; bağımsız sahiplik kontrolü yapılamadı.')
        if not identity:
            return self.coverage('bola', 'Kullanıcılar arası yetki (BOLA)', 'skipped', 'A/B hesaplarının ayrı olduğunu kanıtlamak için oturum kimliği JSON adresi ve kimlik alanı gerekli.')
        start = self.transport.count
        evidence = []
        confirmed = True
        positive_rounds = 0
        principals = None
        def principal(response):
            if response.status != 200:
                return None
            try:
                value = json.loads(response.text)
                for part in identity['field'].split('.'):
                    value = value[part]
                if isinstance(value, bool) or not isinstance(value, (str, int)) or not str(value) or len(str(value)) > 256:
                    return None
                return digest(json.dumps(value, ensure_ascii=False))
            except (ValueError, TypeError, KeyError, RecursionError):
                return None
        for _ in range(2):
            identities = [self.request(identity['url'], accounts[who]) for who in ('a', 'b')]
            anonymous_identity = self.request(identity['url'])
            current = tuple(principal(response) for response in identities)
            if not all(current) or current[0] == current[1] or (principals is not None and current != principals) or anonymous_identity.status not in (401, 403, 404):
                return self.coverage('bola', 'Kullanıcılar arası yetki (BOLA)', 'inconclusive', 'İki ayrı ve kararlı oturum kimliği doğrulanamadı. Aynı hesaba ait iki oturum yetki açığı kanıtı sayılmaz.', self.transport.count - start)
            principals = current
            for who, response, hashed in zip(('A', 'B'), identities, current):
                evidence.append(dict(snapshot(response, who + ' oturum kimliği'), principal_sha256=hashed))
            evidence.append(snapshot(anonymous_identity, 'Kimlik adresi anonim negatif kontrol'))
            own_a = self.request(cfg['a_url'], accounts['a'])
            own_b = self.request(cfg['b_url'], accounts['b'])
            anonymous = self.request(cfg['b_url'])
            crossed = self.request(cfg['b_url'], accounts['a'])
            a_on_a = cfg['a_marker'] in own_a.text and cfg['b_marker'] not in own_a.text
            b_on_b = cfg['b_marker'] in own_b.text and cfg['a_marker'] not in own_b.text
            private = anonymous.status in (401, 403, 404) and cfg['b_marker'] not in anonymous.text
            valid = own_a.status == own_b.status == 200 and a_on_a and b_on_b and private
            if not valid:
                return self.coverage('bola', 'Kullanıcılar arası yetki (BOLA)', 'inconclusive', 'Hesapların ayrı özel kayıtları ve anonim erişim engeli doğrulanamadı. Oturumları/özel işaretleyicileri kontrol edin.', self.transport.count - start)
            confirmed &= crossed.status == 200 and cfg['b_marker'] in crossed.text
            positive_rounds += int(crossed.status == 200 and cfg['b_marker'] in crossed.text)
            evidence.extend([snapshot(own_a, 'A hesabı kendi kaydı', cfg['a_marker']), snapshot(own_b, 'B hesabı kendi kaydı', cfg['b_marker']), snapshot(anonymous, 'B kaydı anonim kontrol', cfg['b_marker']), snapshot(crossed, 'A hesabı B kaydı', cfg['b_marker'])])
        if confirmed:
            sensitive = cfg.get('impact') == 'sensitive'
            self.finding('bola', 'Başka test hesabının özel kaydına erişiliyor', 'high' if sensitive else 'medium', cfg['b_url'], 'A/B oturum kimlikleri farklı ve iki turda kararlı; sahiplik işaretleyicileri ayrık; anonim erişim reddedildi.', 'A hesabı B hesabının özel test kaydını iki turda okuyabildi. ' + ('Hassas test verisinin kullanıcılar arası izolasyonu bozuluyor.' if sensitive else 'Kaydın hassasiyeti veya işlem yetkisi ayrıca değerlendirilmeli.'), 'Her nesne okumasında oturum sahibini kayıt sahibiyle karşılaştırın. Nesneyi kullanıcı/tenant kapsamı içinde sorgulayın. Kimliği tahmin edilemez yapmak erişim kontrolünün yerine geçmez.', ['A ve B test hesaplarının ayrı özel kayıtlarına farklı zararsız işaretleyiciler koyun.', 'Her hesabın kendi kaydını okuyabildiğini ve anonim erişimin reddedildiğini kontrol edin.', 'A oturumuyla B kaydını iki kez okuyun. B işaretleyicisi görünüyorsa erişim kontrolü eksik.'], evidence)
        elif positive_rounds:
            self.finding('bola', 'Kullanıcılar arası erişim sonucu tutarsız', 'medium', cfg['b_url'], 'A hesabı bir turda B test işaretleyicisini okuyabildi.', 'Erişim ikinci turda tekrarlanmadı; kullanıcılar arası yetki açığı doğrulanmadı. Test kayıtları ve önbellek davranışı elle incelenmeli.', 'Sahiplik kontrollerini sunucuda inceleyin; sabit test kayıtlarıyla karşılaştırmayı tekrarlayın.', ['A ve B kendi kayıtları ile A → B erişimini yeniden karşılaştırın.'], evidence, status='suspected')
        self.coverage('bola', 'Kullanıcılar arası yetki (BOLA)', 'tested', 'Ayrı ve kararlı hesap kimlikleri, kendi kayıtları, anonim negatif kontrol ve A → B karşılaştırması iki tur çalıştı. Yazma/yönetici işlevleri test edilmedi.', self.transport.count - start)

    def auth(self, cfg, accounts):
        self.active_check = {'kind': 'auth', 'name': 'Anonim erişim', 'start': self.transport.count}
        if not cfg or not accounts.get('a'):
            return self.coverage('auth', 'Oturum gerektiren kayda anonim erişim', 'skipped', 'A test hesabı ve özel salt okunur test ucu gerekli.')
        start = self.transport.count
        evidence = []
        confirmed = True
        positive_rounds = 0
        for _ in range(2):
            logged = self.request(cfg['url'], accounts['a'])
            anonymous = self.request(cfg['url'])
            invalid = self.request(cfg['url'], {'cookie': 'kanit_invalid_session=constant-negative-control'})
            if logged.status != 200 or cfg['marker'] not in logged.text:
                return self.coverage('auth', 'Oturum gerektiren kayda anonim erişim', 'inconclusive', 'A oturumu özel test işaretleyicisini okuyamadı; oturumun geçerliliği kanıtlanmadı.', self.transport.count - start)
            confirmed &= anonymous.status == invalid.status == 200 and cfg['marker'] in anonymous.text and cfg['marker'] in invalid.text
            positive_rounds += int(anonymous.status == invalid.status == 200 and cfg['marker'] in anonymous.text and cfg['marker'] in invalid.text)
            evidence.extend([snapshot(logged, 'A geçerli oturum', cfg['marker']), snapshot(anonymous, 'Çerezsiz / anonim', cfg['marker']), snapshot(invalid, 'Geçersiz oturum negatif kontrolü', cfg['marker'])])
        if confirmed:
            self.finding('auth', 'Oturum olmadan özel test verisi okunuyor', 'high' if cfg.get('impact') == 'sensitive' else 'medium', cfg['url'], 'Kullanıcı özel olarak tanımlanan işaretleyiciyi geçerli oturumla okuyabiliyor.', 'Oturum olmadan ve geçersiz çerezle aynı özel test verisine iki turda erişildi. Giriş gerektiren veri herkese açılabiliyor; hesap ele geçirme veya parola değiştirme kanıtlanmadı.', 'Özel API uçlarında kimlik doğrulamayı sunucuda zorunlu tutun. Eksik/geçersiz oturumları 401 ile reddedin. Kimliği yalnızca doğrulanmış oturumdan üretin; özel yanıtları ortak önbelleğe koymayın.', ['Yalnızca test hesabına ait özel kayda zararsız benzersiz işaretleyici ekleyin.', 'Geçerli oturumla, oturumsuz ve geçersiz oturumla aynı GET isteğini gönderin.', 'İşaretleyicinin anonim yanıt içinde bulunduğunu ikinci turda doğrulayın.'], evidence)
        elif positive_rounds:
            self.finding('auth', 'Anonim erişim sonucu tutarlı tekrarlanamadı', 'medium', cfg['url'], 'Bir turda anonim ve geçersiz oturum yanıtında özel işaretleyici göründü.', 'İkinci tur erişimi doğrulamadı; kimlik doğrulama açığı kesinleşmedi. Önbellek veya değişken yanıt etkisi incelenmeli.', 'Özel uçta kimlik doğrulama ve önbellek kurallarını inceleyin; sabit test kaydıyla karşılaştırmayı tekrarlayın.', ['Geçerli, anonim ve geçersiz oturumla iki tur yeniden karşılaştırın.'], evidence, status='suspected')
        self.coverage('auth', 'Oturum gerektiren kayda anonim erişim', 'tested', 'Geçerli, anonim ve geçersiz oturum yanıtları iki tur karşılaştırıldı. Oturum yaşam döngüsü kapsam dışı.', self.transport.count - start)

    def validate_config(self, config):
        markers = []
        request_values = []
        for account in config.get('accounts', {}).values():
            for value in account.values():
                request_values.extend(decoded_layers(str(value)))
        for group in ('authorization', 'authentication', 'identity'):
            cfg = config.get(group) or {}
            for key, value in cfg.items():
                if key.endswith('url') and (canonical_origin(value) != self.origin or not read_only_url(value)):
                    raise ScopeError('Test adresi doğrulanmış kapsamda ve salt okunur olmalı.')
                if 'marker' in key and (not isinstance(value, str) or not 6 <= len(value) <= 160):
                    raise ScopeError('İşaretleyiciler 6-160 karakter arasında ve test kaydına özel olmalı.')
                if 'marker' in key:
                    markers.append(value)
                if key.endswith('url'):
                    request_values.extend(decoded_layers(value))
        for cfg in config.get('injection', []):
            if canonical_origin(cfg['url']) != self.origin or not read_only_url(cfg['url']):
                raise ScopeError('Enjeksiyon test adresi kapsam dışı veya işlem içeriyor.')
            marker = cfg.get('restricted_marker', '')
            if marker:
                if not isinstance(marker, str) or not 6 <= len(marker) <= 160:
                    raise ScopeError('SQL test işaretleyicisi 6-160 karakter arasında olmalı.')
                markers.append(marker)
            request_values.extend(decoded_layers(cfg['url']))
        if any(marker in value for marker in markers for value in request_values):
            raise ScopeError('Özel işaretleyici isteğin URL veya oturum değerinde yer alamaz; yalnızca özel test kaydında bulunmalı.')
        a = config.get('authorization') or {}
        if a and (not all(a.get(k) for k in ('a_url', 'b_url', 'a_marker', 'b_marker')) or a['a_url'] == a['b_url'] or a['a_marker'] == a['b_marker'] or a['a_marker'] in a['b_marker'] or a['b_marker'] in a['a_marker']):
            raise ScopeError('A/B için ayrı adresler ve birbirini içermeyen farklı özel işaretleyiciler gerekli.')
        auth = config.get('authentication') or {}
        if auth and not all(auth.get(k) for k in ('url', 'marker')):
            raise ScopeError('Oturum testi için adres ve özel işaretleyici gerekli.')
        identity = config.get('identity') or {}
        if identity and (not identity.get('url') or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,5}', identity.get('field', ''))):
            raise ScopeError('Oturum kimliği için salt okunur JSON adresi ve id veya user.id gibi bir alan gerekli.')

    def run(self, config=None):
        config = config or {}
        self.validate_config(config)
        try:
            self.stage('Sayfa, form ve parametre keşfi', 12)
            candidates = self.discover()
            self.stage('SQL koşullarının karşılaştırılması', 35)
            configured = config.get('injection') or []
            known = {(c['url'], c['parameter']) for c in configured}
            self.sqli(configured + [c for c in candidates if (c['url'], c['parameter']) not in known])
            from .checks import run_extra
            run_extra(self)
            self.stage('İki test hesabının yetki karşılaştırması', 76)
            self.bola(config.get('authorization'), config.get('accounts', {}), config.get('identity'))
            self.stage('Anonim ve geçersiz oturum kontrolleri', 84)
            self.auth(config.get('authentication'), config.get('accounts', {}))
            self.stage('Pasif motor ve rapor', 90)
            if self.zap:
                result = self.zap.inspect(self.har_entries, self.origin, self.transport.stop)
                self.report['engine'] = result['engine']
                self.report['passive_alerts'] = result['alerts']
            self.report['complete'] = not self.zap or self.report['engine']['state'] == 'complete'
        except ScopeError as e:
            self.report['warnings'].append(str(e))
        finally:
            self.report['requests'] = self.transport.count
            self.har_entries.clear()
            self.observations.clear()
            self.targets.clear()
            self.finish_coverage()
        kinds = {f['kind'] for f in self.report['findings'] if f['status'] == 'confirmed'}
        if 'bola' in kinds and 'auth' in kinds:
            self.report['relationships'].append('İki bağımsız erişim kontrolü hatası doğrulandı. Aynı saldırı zincirinin parçaları oldukları veya hesap ele geçirmeye yol açtıkları gösterilmedi.')
        self.report['findings'].sort(key=lambda f: (f['status'] != 'confirmed', {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[f['severity']]))
        self.stage('Rapor tamamlandı', 100)
        return self.report

    def finish_coverage(self):
        if self.active_check:
            active = self.active_check
            previous = next((c for c in self.report['coverage'] if c['kind'] == active['kind']), None)
            count = self.transport.count - active['start'] + (previous['requests'] if previous else 0)
            self.coverage(active['kind'], active['name'], 'inconclusive', 'Kontrol başladı ancak tarama erken sonlandı; doğrulama tamamlanmadı.', count)
        present = {r['kind'] for r in self.report['coverage']}
        for kind, name, reason in LIMITATIONS:
            if kind not in present:
                self.coverage(kind, name, 'not_implemented', reason)
        for kind, name in [('sqli', 'SQL enjeksiyonu'), ('bola', 'Kullanıcılar arası yetki'), ('auth', 'Anonim oturum erişimi'), ('nosql', 'NoSQL operatör kontrolü'), ('ssti', 'Şablon ifadesi'), ('xss_reflection', 'HTML yansıma'), ('secrets', 'Açık yapılandırma'), ('source', 'Depo üst bilgisi')]:
            if kind not in present:
                self.coverage(kind, name, 'inconclusive', 'Tarama erken sonlandı; kontrol tamamlanmadı.')
