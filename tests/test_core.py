import json
import threading
import unittest
from unittest.mock import patch

from kanit.scope import Policy, ScopeError, Transport, canonical_origin
from kanit.engine import Scanner, Cancelled
from kanit.lab import start_lab


class ScopeTests(unittest.TestCase):
    def test_exact_origin_and_url_validation(self):
        self.assertEqual(canonical_origin('https://Example.COM/a'), 'https://example.com')
        for url in ('file:///etc/passwd', 'http://user:pass@example.com', 'http://example.com\\@127.0.0.1', 'http://example.com/#a'):
            with self.assertRaises(ScopeError):
                canonical_origin(url)

    def test_private_and_mixed_dns_blocked(self):
        policy = Policy()
        for addresses in (['127.0.0.1'], ['169.254.169.254'], ['10.0.0.1'], ['::1'], ['93.184.216.34', '10.0.0.2']):
            with patch('kanit.scope.resolve', return_value=addresses):
                with self.assertRaises(ScopeError):
                    policy.address('https://example.com')

    def test_lab_exception_is_exact(self):
        policy = Policy(labs={'http://127.0.0.1:9123'})
        self.assertEqual(policy.address('http://127.0.0.1:9123/a'), '127.0.0.1')
        with self.assertRaises(ScopeError):
            policy.address('http://127.0.0.1:9124')


class CoreAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = start_lab('vulnerable', 0)
        cls.fixed = start_lab('fixed', 0)
        cls.policy = Policy(labs={cls.vuln.origin, cls.fixed.origin})

    @classmethod
    def tearDownClass(cls):
        cls.vuln.shutdown()
        cls.fixed.shutdown()

    def scan(self, lab):
        scanner = Scanner(lab.origin, self.policy, rate=100, budget=160)
        config = lab.test_config()
        return scanner.run(config)

    def test_vulnerable_produces_repeated_evidence(self):
        report = self.scan(self.vuln)
        found = {f['kind']: f for f in report['findings']}
        self.assertEqual(set(found), {'sqli', 'bola', 'auth'})
        for finding in found.values():
            self.assertEqual(finding['status'], 'confirmed')
            self.assertTrue(finding['evidence'])
            self.assertEqual(finding['repeats'], 2)
            self.assertTrue(finding['fix'])
            self.assertTrue(finding['steps'])
        serialized = json.dumps(report)
        self.assertNotIn('safez-lab-session-a', serialized)
        self.assertNotIn('safez-lab-session-b', serialized)
        self.assertNotIn('SAFEZ_PRIVATE_B', serialized)
        self.assertNotIn('b@example.test', serialized)

    def test_fixed_produces_no_confirmed_findings(self):
        report = self.scan(self.fixed)
        self.assertEqual(report['findings'], [])
        checks = {x['kind']: x for x in report['coverage']}
        for kind in ('sqli', 'bola', 'auth'):
            self.assertEqual(checks[kind]['state'], 'tested')

    def test_marker_is_not_authorization_proof_without_ownership_controls(self):
        config = self.vuln.test_config()
        config['accounts']['b']['cookie'] = config['accounts']['a']['cookie']
        scanner = Scanner(self.vuln.origin, self.policy, rate=100)
        report = scanner.run(config)
        self.assertFalse(any(f['kind'] == 'bola' for f in report['findings']))

    def test_cancel_stops_before_requests(self):
        stop = threading.Event()
        stop.set()
        scanner = Scanner(self.vuln.origin, self.policy, stop=stop, rate=100)
        with self.assertRaises(Cancelled):
            scanner.run(self.vuln.test_config())
        self.assertEqual(scanner.transport.count, 0)

    def test_redirect_out_of_scope_never_followed(self):
        transport = Transport(self.vuln.origin, self.policy, rate=100)
        with self.assertRaises(ScopeError):
            transport.get(self.vuln.origin + '/redirect')
        self.assertEqual(transport.count, 1)

    def test_request_budget_is_enforced(self):
        transport = Transport(self.vuln.origin, self.policy, rate=100, budget=1)
        transport.get(self.vuln.origin + '/')
        with self.assertRaises(ScopeError):
            transport.get(self.vuln.origin + '/')


if __name__ == '__main__':
    unittest.main()
