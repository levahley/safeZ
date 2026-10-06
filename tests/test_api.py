import http.client
import json
import tempfile
import threading
import time
import unittest
from app import Application, make_server
from unittest.mock import patch


class ApiAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.app = Application(cls.temp.name, lab_ports=(0, 0), rate=100)
        cls.server = make_server(cls.app, 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_port
        conn = http.client.HTTPConnection('127.0.0.1', cls.port)
        conn.request('GET', '/')
        r = conn.getresponse()
        cls.cookie = r.getheader('Set-Cookie').split(';')[0]
        r.read()
        conn.close()
        cls.key = cls.app.key

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.app.close()
        cls.temp.cleanup()

    def req(self, method, path, data=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port)
        h = {'Cookie': self.cookie, 'X-Kanit-Key': self.key, 'Content-Type': 'application/json'}
        h.update(headers or {})
        conn.request(method, path, json.dumps(data) if data is not None else None, h)
        r = conn.getresponse()
        body = r.read()
        result = (r.status, body, dict(r.getheaders()))
        conn.close()
        return result

    def test_csrf_and_host_are_enforced(self):
        self.assertEqual(self.req('POST', '/api/sites', {'url': 'https://example.com'}, {'X-Kanit-Key': ''})[0], 403)
        self.assertEqual(self.req('GET', '/api/bootstrap', headers={'Host': 'attacker.test'})[0], 403)
        self.assertEqual(self.req('POST', '/api/sites', {}, {'Origin': 'https://attacker.test'})[0], 403)
        self.assertEqual(self.req('GET', '/api/bootstrap', headers={'Cookie': ''})[0], 403)

    def test_registered_target_scans_without_file_or_dns_proof(self):
        lab = self.app.labs['fixed']
        status, body, _ = self.req('POST', '/api/sites', {'url': lab.origin})
        self.assertEqual(status, 200)
        site = json.loads(body)
        status, body, _ = self.req('POST', '/api/scans', {'site_id': site['id'], 'read_only': True})
        self.assertEqual(status, 202)
        job = self.wait_scan(json.loads(body)['id'])
        self.assertEqual(job['status'], 'complete')
        self.assertEqual(job['report']['findings'], [])

    def test_bare_domain_uses_https_without_a_challenge(self):
        with patch('kanit.scope.resolve', return_value=['8.8.8.8']):
            status, body, _ = self.req('POST', '/api/sites', {'url': ' Example.COM '})
        self.assertEqual(status, 200)
        site = json.loads(body)
        self.assertEqual(site['origin'], 'https://example.com')
        self.assertNotIn('token', site)
        self.assertNotIn('file_path', site)
        self.assertNotIn('dns_name', site)

    def test_private_target_stays_blocked_without_ownership_gate(self):
        status, _, _ = self.req('POST', '/api/sites', {'url': 'http://127.0.0.1:1'})
        self.assertEqual(status, 400)

    def wait_scan(self, scan_id):
        deadline = time.time() + 8
        while time.time() < deadline:
            status, body, _ = self.req('GET', '/api/scans/' + scan_id)
            self.assertEqual(status, 200)
            job = json.loads(body)
            if job['status'] not in ('queued', 'running', 'stopping'):
                return job
            time.sleep(.03)
        self.fail('Scan did not finish')

    def scan_lab(self, mode):
        status, body, _ = self.req('POST', '/api/lab', {'mode': mode})
        self.assertEqual(status, 200)
        setup = json.loads(body)
        status, body, _ = self.req('POST', '/api/scans', {'site_id': setup['site']['id'], 'config': setup['config'], 'read_only': True})
        self.assertEqual(status, 202)
        job = json.loads(body)
        return self.wait_scan(job['id'])

    def test_full_http_flow_vulnerable_fixed_and_pdf(self):
        for mode, expected in [('vulnerable', 3), ('fixed', 0)]:
            job = self.scan_lab(mode)
            self.assertEqual(job['status'], 'complete')
            self.assertEqual(len(job['report']['findings']), expected)
            self.assertNotIn('sid=safez-lab-session', json.dumps(job))
            status, pdf, headers = self.req('GET', '/api/scans/' + job['id'] + '/pdf')
            self.assertEqual(status, 200)
            self.assertTrue(pdf.startswith(b'%PDF-'))
            self.assertIn('application/pdf', headers['Content-Type'])


if __name__ == '__main__':
    unittest.main()
