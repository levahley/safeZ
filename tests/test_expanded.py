"""Real HTTP vulnerable/fixed targets for the unauthenticated scanner."""
import ast
import html
import json
import re
import sqlite3
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from kanit.engine import Scanner
from kanit.scope import Policy, Response
from kanit.checks import records, credentials

SECRET = 'SAFEZ_SYNTHETIC_DB_CREDENTIAL_39105'


class Target:
    def __init__(self, mode='fixed', feature='all'):
        owner = self
        self.visited = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                owner.visited.append(self.path)
                parsed = urlsplit(self.path)
                q = parse_qs(parsed.query, keep_blank_values=True)
                path = parsed.path
                if path == '/':
                    entries = {'discovery': '<script src="/app.js"></script><form method="GET" action="/api/catalog"><input type="number" name="id"></form>',
                               'ssti': '<a href="/render?template=hello">Render</a>',
                               'nosql': '<a href="/api/filter?id=1">Filter</a>',
                               'reflection': '<a href="/search?q=hello">Search</a>',
                               'sql_html': '<a href="/search?q=hello">Search</a>',
                               'sql_table': '<a href="/lookup?name=public">Lookup</a>',
                               'ignored_id': '<script src="/app.js"></script>',
                               'deep_json': '<a href="/deep?id=1">JSON</a>',
                               'forms_budget': '<a href="/search?q=alpha">Search</a>' + ''.join('<a href="/page/' + str(i) + '">Page</a>' for i in range(40)) + '<form action="/search"><input name="q" value="beta"></form>',
                               'redirects': ''.join('<a href="/go/' + str(i) + '">Next</a>' for i in range(60)),
                               'malformed': '<form method><input name></form><form action="http://[bad"><input name="id"></form><script src="http://[bad"></script><a href="/search?q=hello">Search</a>'}
                    return self.reply('<html>' + entries.get(feature, '') + '</html>', 'text/html')
                if path.startswith('/go/'):
                    return self.reply('', 'text/plain', 302, {'Location': '/done/' + path.rsplit('/',1)[1]})
                if path.startswith('/done/'):
                    return self.reply('Done', 'text/plain')
                if path == '/deep':
                    return self.reply('[' * 1200 + '0' + ']' * 1200, 'application/json')
                if path == '/app.js':
                    return self.reply('fetch("/api/catalog"); fetch("https://other.example/api/leak"); fetch("/checkout");', 'text/javascript')
                if path == '/robots.txt':
                    return self.reply('Sitemap: ' + owner.origin + '/sitemap.xml\nDisallow: /logout', 'text/plain')
                if path == '/sitemap.xml':
                    return self.reply('<urlset><url><loc>' + owner.origin + '/api/hidden?id=1</loc></url></urlset>', 'application/xml')
                if path in ('/api/catalog', '/api/hidden') and feature == 'ignored_id':
                    return self.reply('{"items":[{"id":1,"name":"public"}]}', 'application/json')
                if path == '/lookup':
                    db = sqlite3.connect(':memory:')
                    db.execute('create table items(id integer, name text)')
                    db.execute("insert into items values (1, 'public')")
                    value = q.get('name', ['public'])[0]
                    try:
                        rows = db.execute("select * from items where name = '" + value + "'").fetchall() if mode == 'vulnerable' else db.execute('select * from items where name = ?', (value,)).fetchall()
                        return self.reply('<table>' + ''.join('<tr><td>' + str(r[0]) + '</td><td>' + html.escape(r[1]) + '</td></tr>' for r in rows) + '</table>', 'text/html')
                    except sqlite3.Error:
                        return self.reply('Invalid lookup', 'text/html', 400)
                    finally:
                        db.close()
                if path in ('/api/catalog', '/api/hidden') and feature == 'discovery':
                    db = sqlite3.connect(':memory:')
                    db.execute('create table items(id integer, name text)')
                    db.execute("insert into items values (1, 'Public notebook')")
                    value = q.get('id', ['1'])[0]
                    try:
                        rows = db.execute('select * from items where id = ' + value).fetchall() if mode == 'vulnerable' else db.execute('select * from items where id = ?', (value,)).fetchall()
                        return self.reply(json.dumps({'items': [{'id': r[0], 'name': r[1]} for r in rows]}), 'application/json')
                    except sqlite3.Error:
                        return self.reply('{}', 'application/json', 400)
                    finally:
                        db.close()
                if path == '/api/filter':
                    records = [{'id': 1, 'name': 'public one'}, {'id': 2, 'name': 'public two'}]
                    if mode == 'fixed' and any('[' in key for key in q):
                        return self.reply('{}', 'application/json', 400)
                    if 'id[$eq]' in q:
                        rows = [r for r in records if str(r['id']) == q['id[$eq]'][0]]
                    elif 'id[$ne]' in q:
                        rows = [r for r in records if str(r['id']) != q['id[$ne]'][0]]
                    else:
                        rows = [r for r in records if str(r['id']) == q.get('id', ['1'])[0]]
                    return self.reply(json.dumps({'records': rows}), 'application/json')
                if path == '/render':
                    value = q.get('template', ['hello'])[0]
                    if mode == 'vulnerable':
                        def arithmetic(match):
                            node = ast.parse(match[1], mode='eval').body
                            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult) and isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant):
                                return str(node.left.value * node.right.value)
                            return match[0]
                        value = re.sub(r'\{\{(\d+\*\d+)\}\}', arithmetic, value)
                    return self.reply('<p>' + html.escape(value) + '</p>', 'text/html')
                if path == '/search':
                    value = q.get('q', ['hello'])[0]
                    if feature == 'malformed':
                        return self.reply('<table><tr><td>A</tr></td></table>', 'text/html')
                    if feature == 'sql_html':
                        # A response-length/error change is not SQL proof.
                        return self.reply('<p>' + ('database syntax error' if "'" in value else value) + '</p>', 'text/html')
                    return self.reply('<p>' + (value if mode == 'vulnerable' else html.escape(value)) + '</p>', 'text/html')
                if path == '/.env' and feature in ('secrets', 'masked'):
                    value = SECRET if feature == 'secrets' and mode == 'vulnerable' else '************'
                    return self.reply('DB_PASSWORD=' + value + '\nAPP_NAME=safeZ\n', 'text/plain')
                if feature == 'soft404':
                    return self.reply('<html>DB_PASSWORD=' + SECRET + '</html>', 'text/html')
                return self.reply('Not found', 'text/plain', 404)

            def reply(self, body, mime, status=200, headers=None):
                body = body.encode()
                self.send_response(status)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(body)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.origin = 'http://127.0.0.1:' + str(self.server.server_port)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class ExpandedAcceptance(unittest.TestCase):
    def target(self, mode, feature):
        target = Target(mode, feature)
        self.addCleanup(target.close)
        return target

    def scan(self, mode, feature):
        target = self.target(mode, feature)
        scanner = Scanner(target.origin, Policy(labs={target.origin}), rate=1000, budget=240)
        return scanner.run(), target

    def test_js_form_and_sitemap_discover_real_numeric_parameters(self):
        report, target = self.scan('vulnerable', 'discovery')
        self.assertTrue(any(f['kind'] == 'sqli' for f in report['findings']))
        self.assertTrue(any('/api/hidden' in p['url'] for p in report['discovery']['pages']))
        self.assertTrue(any('/app.js' in p['url'] for p in report['discovery']['pages']))
        self.assertTrue(any(p['name'] == 'id' and p.get('source') for p in report['discovery']['parameters']))
        self.assertFalse(any('/checkout' in p or 'other.example' in p for p in target.visited))
        fixed, _ = self.scan('fixed', 'discovery')
        self.assertFalse(any(f['status'] == 'confirmed' for f in fixed['findings']))

    def test_ssti_arithmetic_is_repeated_but_does_not_claim_command_execution(self):
        vulnerable, _ = self.scan('vulnerable', 'ssti')
        found = [f for f in vulnerable['findings'] if f['kind'] == 'ssti']
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['status'], 'confirmed')
        self.assertEqual(found[0]['severity'], 'medium')
        self.assertEqual(found[0]['parameter'], 'template')
        self.assertTrue(found[0]['english']['condition'])
        self.assertTrue(found[0]['location']['endpoint'].endswith('/render'))
        fixed, _ = self.scan('fixed', 'ssti')
        self.assertFalse(any(f['kind'] == 'ssti' for f in fixed['findings']))

    def test_nosql_operator_acceptance_stays_suspected_without_private_data_proof(self):
        report, _ = self.scan('vulnerable', 'nosql')
        found = [f for f in report['findings'] if f['kind'] == 'nosql']
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['status'], 'suspected')
        fixed, _ = self.scan('fixed', 'nosql')
        self.assertFalse(any(f['kind'] == 'nosql' for f in fixed['findings']))

    def test_html_reflection_is_not_reported_as_executed_xss(self):
        report, _ = self.scan('vulnerable', 'reflection')
        found = [f for f in report['findings'] if f['kind'] == 'xss_reflection']
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['status'], 'suspected')
        fixed, _ = self.scan('fixed', 'reflection')
        self.assertFalse(any(f['kind'] == 'xss_reflection' for f in fixed['findings']))

    def test_configuration_exposure_is_repeatable_and_secret_never_persisted(self):
        report, _ = self.scan('vulnerable', 'secrets')
        found = [f for f in report['findings'] if f['kind'] == 'secrets']
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['severity'], 'high')
        self.assertEqual(found[0]['status'], 'confirmed')
        self.assertEqual(found[0]['location']['response_line'], 1)
        serialized = json.dumps(report)
        self.assertNotIn(SECRET, serialized)
        self.assertIn('english', found[0])
        self.assertTrue(found[0]['steps'])
        fixed, _ = self.scan('fixed', 'masked')
        self.assertFalse(any(f['kind'] == 'secrets' for f in fixed['findings']))
        soft404, _ = self.scan('vulnerable', 'soft404')
        self.assertFalse(any(f['kind'] == 'secrets' for f in soft404['findings']))

    def test_text_sql_comparison_can_use_html_records_without_json(self):
        vulnerable, _ = self.scan('vulnerable', 'sql_table')
        found = [f for f in vulnerable['findings'] if f['kind'] == 'sqli']
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['status'], 'confirmed')
        self.assertEqual(found[0]['parameter'], 'name')
        fixed, _ = self.scan('fixed', 'sql_table')
        self.assertFalse(any(f['kind'] == 'sqli' for f in fixed['findings']))

    def test_automatically_added_but_ignored_id_does_not_prove_injection(self):
        report, target = self.scan('vulnerable', 'ignored_id')
        self.assertTrue(any('/api/catalog?id=' in url for url in target.visited))
        self.assertFalse(any(f['status'] == 'confirmed' for f in report['findings']))

    def test_redirect_discovery_respects_the_actual_request_limit(self):
        target = self.target('fixed', 'redirects')
        scanner = Scanner(target.origin, Policy(labs={target.origin}), rate=1000, budget=240)
        scanner.discover()
        self.assertLessEqual(scanner.transport.count, 32)
        self.assertLessEqual(len(target.visited), 32)

    def test_interrupted_template_check_preserves_its_attempted_request_count(self):
        target = self.target('fixed', 'ssti')
        scanner = Scanner(target.origin, Policy(labs={target.origin}), rate=1000, budget=14)
        report = scanner.run()
        self.assertFalse(report['complete'])
        coverage = next(c for c in report['coverage'] if c['kind'] == 'ssti')
        self.assertEqual(coverage['state'], 'inconclusive')
        self.assertEqual(coverage['requests'], 2)

    def test_malformed_forms_scripts_and_tables_do_not_crash_the_scan(self):
        report, _ = self.scan('fixed', 'malformed')
        self.assertTrue(report['complete'])
        self.assertFalse(any(f['status'] == 'confirmed' for f in report['findings']))

    def test_out_of_order_table_closings_are_not_records(self):
        response = Response('http://example.test/', 200, {'content-type': 'text/html'},
                            b'<table><tr><td>A</td><td>B</td></table></tr>')
        self.assertIsNone(records(response))

    def test_deeply_nested_json_does_not_crash_the_scan(self):
        report, _ = self.scan('fixed', 'deep_json')
        self.assertTrue(report['complete'])
        self.assertFalse(report['findings'])

    def test_inert_raw_text_reflection_is_not_an_html_element(self):
        from kanit.checks import ElementProbe
        for tag in ('textarea', 'title', 'xmp', 'iframe', 'plaintext'):
            with self.subTest(tag=tag):
                parser = ElementProbe('sentinel')
                parser.feed('<' + tag + '><safez-probe data-safez="sentinel"></safez-probe></' + tag + '>')
                self.assertFalse(parser.found)

    def test_compact_and_pretty_json_credentials_have_equal_masked_evidence(self):
        data = {'DB_PASSWORD': SECRET}
        for text in (json.dumps(data), json.dumps(data, indent=2)):
            with self.subTest(text_format='pretty' if '\n' in text else 'compact'):
                hints = credentials(Response('http://example.test/config.json', 200,
                                             {'content-type': 'application/json'}, text.encode()))
                self.assertEqual(len(hints), 1)
                self.assertEqual(hints[0]['name'], 'DB_PASSWORD')
                self.assertNotIn(SECRET, json.dumps(hints))

    def test_masking_does_not_mark_an_unvisited_form_as_tested(self):
        target = self.target('fixed', 'forms_budget')
        scanner = Scanner(target.origin, Policy(labs={target.origin}), rate=1000, budget=240)
        scanner.discover()
        self.assertIn('/search?q=alpha', target.visited)
        self.assertNotIn('/search?q=beta', target.visited)
        self.assertFalse(scanner.report['discovery']['forms'][0]['tested'])

    def test_html_error_and_input_reflection_are_not_sql_proof(self):
        report, _ = self.scan('vulnerable', 'sql_html')
        self.assertFalse(any(f['kind'] == 'sqli' for f in report['findings']))
        coverage = {c['kind']: c for c in report['coverage']}
        self.assertEqual(coverage['sqli']['state'], 'tested')
        self.assertGreater(coverage['sqli']['requests'], 0)
        self.assertTrue(coverage['sqli']['detail_en'])


if __name__ == '__main__':
    unittest.main()
