"""Authored English counterparts; no external translation or invented evidence."""
NAMES = {
    'sqli': 'SQL injection', 'bola': 'Cross-account authorization (BOLA)',
    'auth': 'Anonymous access to a private record', 'nosql': 'NoSQL scalar/operator comparison',
    'ssti': 'Server-side template expression evaluation', 'xss_reflection': 'HTML reflection / XSS candidate',
    'secrets': 'Public configuration and secret exposure', 'source': 'Public repository metadata',
    'command': 'Operating-system command injection', 'files': 'File writing and upload',
    'ssrf': 'Server-side request forgery', 'xss': 'Stored / privileged XSS',
    'logic': 'Business logic / function-level authorization', 'recovery': 'Account recovery / session lifecycle',
}

TEXT = {
    'sqli': ('User input changes a SQL predicate',
             'Two independent true/false SQL predicates were compared with a normal record query and an absent-record control.',
             'The tested parameter influences record selection. Command execution, database writes and account takeover were not tested.',
             'Use parameterized database queries. Enforce ownership/tenant restrictions on the server and minimize database privileges.',
             ['Read a stable synthetic record using its normal parameter value.', 'Compare true and false constant predicates, then repeat with different constants.', 'Verify the absent-record control. Do not run writes or read unrelated private records.']),
    'bola': ('Another test account can read a private record',
             'Distinct, stable account identities, disjoint record markers and an anonymous denial were established before cross-account reads.',
             'Account A read account B’s private test record in two rounds. This demonstrates a missing ownership check on the reported endpoint.',
             'Check ownership for every object access. Query records within the authenticated user/tenant scope; opaque IDs do not replace authorization.',
             ['Use two separate synthetic accounts and records.', 'Verify own-record reads and anonymous denial.', 'Repeat the account A → account B record read.']),
    'auth': ('Private test data is readable without a session',
             'A valid session could read the private marker. Anonymous and invalid-session requests were compared against it twice.',
             'The same private test data was accessible without authentication. Password changes or account takeover were not demonstrated.',
             'Require server-side authentication on private endpoints, reject missing/invalid sessions and avoid shared caching of private responses.',
             ['Read the synthetic private record with a valid test session.', 'Repeat the GET anonymously and with an invalid session.', 'Confirm the private marker appears in both comparison rounds.']),
    'ssti': ('User input is evaluated as a template expression',
             'Two different arithmetic template expressions produced their computed outputs between unique markers; literal and malformed-expression controls did not.',
             'Server-side expression evaluation was observed for this parameter. OS command execution, filesystem access and code execution impact were not demonstrated.',
             'Treat user input as template data. Do not compile/render it as template source; use a fixed template and context-aware output escaping.',
             ['Use a harmless, uniquely marked arithmetic expression on this GET parameter.', 'Compare it with literal and malformed-expression controls.', 'Repeat with different operands; inspect the template rendering call in server code.']),
    'nosql': ('A scalar parameter accepts NoSQL operators',
              'Scalar, equality, inequality and absent-record queries changed structured record sets consistently in two rounds.',
              'This is a candidate, not a confirmed authorization bypass. Some APIs intentionally allow operators; private-data access and the input contract require review.',
              'Validate scalar input types, reject unexpected nested/operator keys and construct database predicates server-side. Keep mandatory ownership filters outside user input.',
              ['Compare the scalar GET parameter with $eq/$ne operator forms on synthetic records.', 'Repeat with an absent-record equality control.', 'Review whether operators are intentional and whether authorization filters can be bypassed.']),
    'xss_reflection': ('Input can introduce an HTML element',
                       'A harmless custom element containing a unique marker was parsed as an element in two responses; the plain-text control did not create that element.',
                       'HTML injection was observed. JavaScript execution, persistence and privileged-user impact were not verified, so XSS remains a candidate.',
                       'Escape untrusted values for their HTML context. Avoid unsafe innerHTML/template insertion; sanitize explicitly allowed markup.',
                       ['Send a harmless custom-element marker in this GET parameter.', 'Compare the parsed HTML with a plain marker and repeat with a new marker.', 'Review the reported output context in server/client code; do not treat reflection alone as executed XSS.']),
    'secrets': ('A configuration file exposes credential-like values',
                'A public file contained non-placeholder credential assignments in two reads; a random nonexistent-file control did not contain them.',
                'Configuration content is publicly readable at this endpoint. Credential validity, privileges and account access were not tested. Secret values are excluded from the report.',
                'Remove configuration files from the public web root, deny access at the server, rotate exposed credentials and inspect access logs. Use a secret manager.',
                ['GET the reported path and verify the configuration format without sharing its contents.', 'Check the reported response line and assignment name locally.', 'Remove public access and repeat against a nonexistent-file control.']),
    'source': ('Git repository metadata is publicly readable',
               'A valid Git HEAD reference was observed twice and was absent from a nonexistent-file control.',
               'Repository metadata is exposed. Source-code or credential retrieval was not performed; sensitive impact remains unverified.',
               'Block access to .git directories and deploy only required build artifacts outside the source checkout.',
               ['Check the reported .git/HEAD path.', 'Verify a nonexistent-file control has different content.', 'Block the directory and retest without retrieving repository objects.']),
}


def finding_text(kind, status, severity):
    title, condition, impact, fix, steps = TEXT.get(kind, TEXT['source'])
    if kind == 'sqli' and severity == 'high':
        impact = 'A synthetic record marked as sensitive was denied by the normal query and read with a constant SQL condition in two rounds. No real data was changed.'
    if status == 'suspected' and kind in ('sqli', 'bola', 'auth'):
        title = 'Inconsistent ' + NAMES[kind].lower() + ' comparison'
        condition = 'One comparison round suggested the issue; a second round did not confirm it.'
        impact = 'The issue is unconfirmed. Dynamic data, caching or input handling can affect the comparison. Review stable synthetic records.'
    return dict(title=title, condition=condition, impact=impact, fix=fix, steps=list(steps))


def coverage_text(kind, state, detail):
    context = {
        'sqli': 'Only observed or safely derived GET parameters are checked. Repeated record comparisons are required for confirmation; response length and SQL errors alone are insufficient.',
        'nosql': 'Structured GET record responses can be compared with scalar/operator controls. Intentional operator support is not automatically a vulnerability.',
        'ssti': 'Harmless arithmetic expressions are compared with literal/invalid controls. This does not establish OS command execution.',
        'xss_reflection': 'HTML parsing is checked with inert markers. Browser JavaScript execution is not performed.',
        'secrets': 'Public configuration paths are checked with repeats and nonexistent-path controls; secret values are not saved or used.',
        'source': 'Only public Git HEAD metadata is checked; repository objects are not downloaded.',
        'bola': 'Two distinct test accounts, stable identities and each account’s private synthetic record are required. They cannot be inferred from an anonymous scan.',
        'auth': 'A valid test session and a known private synthetic record are required to prove missing authentication. Public content is not automatically private.',
        'command': 'OS commands are not executed on the target; a controlled command-execution scenario is not configured.',
        'files': 'File writes/uploads and arbitrary file reads are not performed; isolated test files and a cleanup scenario are required.',
        'ssrf': 'No external callback verifier is configured. Internal-network destinations are not probed.',
        'xss': 'Stored/privileged XSS needs a controlled write/read flow and an isolated browser/account context.',
        'logic': 'Transactions, administrator actions and workflow bypasses need role-specific accounts and synthetic business scenarios.',
        'recovery': 'Password reset, logout invalidation and session fixation need controlled accounts and an explicit lifecycle scenario.',
    }.get(kind, '')
    prefix = {'tested': 'The listed checks ran.', 'skipped': 'No applicable input or required context was available.',
              'inconclusive': 'This check could not be completed or its prerequisites were not verified.',
              'not_implemented': 'This scenario was not executed by the current engine.'}.get(state, state)
    return prefix + ' ' + context


# These describe rule families. Vendor wording remains available in English.
PASSIVE = [
    (('secret', 'sensitive', 'information disclosure'), 'Hassas bilgi sızıntısı adayı', 'Yanıtta hassas bilgiye benzeyen bir örüntü görüldü.', 'Gereksiz hassas alanları yanıttan kaldırın; özel uçlarda kimlik/yetki kontrolünü ve günlük maskelemesini inceleyin.'),
    (('content security policy', 'csp'), 'İçerik güvenliği politikası incelenmeli', 'CSP başlığı eksik veya kuralın beklediği kısıtları sağlamıyor.', 'Uygulamanın gerçek kaynaklarına uygun CSP tanımlayın; gereksiz inline betik ve geniş kaynak izinlerini kaldırın.'),
    (('clickjack', 'frame-options'), 'Sayfanın çerçeve içinde açılma koruması incelenmeli', 'Çerçeveleme başlığı/politikası yetersiz olabilir.', 'CSP frame-ancestors ve uygun X-Frame-Options ile izin verilen çerçeveleme bağlamlarını sınırlandırın.'),
    (('x-content-type', 'mime'), 'Yanıt türü koruması incelenmeli', 'Tarayıcının içerik türünü tahmin etmesini engelleyen kural eksik olabilir.', 'Doğru Content-Type ve X-Content-Type-Options: nosniff kullanın.'),
    (('csrf',), 'İstek sahteciliği koruması incelenmeli', 'Motor formda beklediği istek sahteciliği belirtecini görmedi; işlem etkisi test edilmedi.', 'Durum değiştiren işlemlerde CSRF belirteci, Origin denetimi ve uygun SameSite çerezi uygulayın; yalnız GET formunda belirteç yokluğunu açık saymayın.'),
    (('cache',), 'Önbellek kuralları incelenmeli', 'Yanıtın önbellek ayarları motor kuralıyla eşleşti.', 'Hassas yanıtları ortak önbellekten çıkarın; veri türüne göre Cache-Control kurallarını belirleyin.'),
    (('httponly',), 'Çerezin JavaScript erişim koruması incelenmeli', 'Çerezde HttpOnly niteliği eksik olabilir.', 'JavaScript tarafından okunması gerekmeyen oturum çerezlerine HttpOnly ekleyin.'),
    (('samesite',), 'Çerezin siteler arası gönderim kuralı incelenmeli', 'Çerezde uygun SameSite niteliği görünmedi.', 'Oturum çerezlerinde iş akışına uygun SameSite kullanın; üçüncü taraf akışlarını ayrıca test edin.'),
    (('cookie', 'secure flag'), 'Çerez güvenlik nitelikleri incelenmeli', 'Çerez nitelikleri motorun güvenlik kuralıyla eşleşti.', 'Üretimde HTTPS ve oturum çerezlerinde Secure/HttpOnly/uygun SameSite kullanın; yerel HTTP laboratuvarını üretim yapılandırması saymayın.'),
    (('server', 'x-powered', 'version'), 'Sunucu teknoloji bilgisi açığa çıkabilir', 'Yanıt başlığı/gövdesinde teknoloji bilgisine benzeyen veri görüldü.', 'Gereksiz sürüm başlıklarını ve ayrıntılı hata sayfalarını kaldırın; yazılımları güncel tutun. Sürüm bilgisi tek başına istismar kanıtı değildir.'),
    (('cross-domain', 'cors',), 'Siteler arası erişim kuralı incelenmeli', 'Motor siteler arası erişim başlıklarında inceleme gerektiren bir örüntü gördü.', 'Güvenilen origin listesini sunucuda açıkça tanımlayın; özel veriyi kimlik/yetki kontrolü olmadan paylaşmayın.'),
]


def passive_text(alert):
    original = alert.get('alert', 'Passive HTTP alert')[:180]
    profile = next((row for row in PASSIVE if any(word in original.lower() for word in row[0])), None)
    if profile:
        _, title, condition, fix = profile
    else:
        title = 'Pasif HTTP güvenlik uyarısı'
        condition = 'Yanıt motorun pasif güvenlik kuralıyla eşleşti. Özgün kural adı İngilizce açıklamada yer alır.'
        fix = 'İngilizce açıklamadaki motor kuralını ve önerilen çözümü ilgili uçta inceleyin; kontrollü testle etkisini doğrulayın.'
    impact = 'Bu pasif uyarıda istismar ve gerçek etki doğrulanmadı. Doğrulanmış yüksek/kritik bulgu sayısına eklenmez.'
    english = {'title': original, 'condition': 'ZAP matched a passive HTTP response rule.',
               'impact': 'Exploitability and actual impact were not verified. This alert is excluded from confirmed high/critical counts.',
               'fix': alert.get('solution', '')[:1500] or 'Review the applicable rule and verify its impact with a controlled scenario.',
               'steps': ['Review the affected endpoint and the original ZAP rule.', 'Verify the behavior with a controlled scenario before assigning confirmed impact.']}
    return dict(title=title, condition=condition, impact=impact, fix=fix, note=impact, english=english)
