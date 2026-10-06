import json
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from kanit.scope import Policy, ScopeError
from kanit.lab import start_lab
from kanit.store import Store
from kanit.zap import Zap


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name + '/kanit.db')
        self.lab = start_lab('fixed', 0)

    def tearDown(self):
        self.lab.shutdown()
        self.temp.cleanup()

    def test_saved_scan_has_no_credentials(self):
        self.store.save_scan({'id': 'test', 'status': 'complete', 'report': {'findings': []}})
        self.assertEqual(self.store.get_scan('test')['status'], 'complete')

    def test_zap_import_never_sends_requests_and_alerts_are_not_confirmed(self):
        from kanit.scope import Response
        response = Response(self.lab.origin + '/', 200, {'content-type': 'text/html', 'set-cookie': 'sid=SECRET'}, b'<h1>test</h1>')
        zap = Zap('http://127.0.0.1:9191', 'secret')
        calls = []
        def api(component, operation, action, params=None):
            calls.append((component, operation, action, params or {}))
            if action == 'version':
                return {'version': 'test-double'}
            if action == 'recordsToScan':
                return {'recordsToScan': '0'}
            if action == 'importHar':
                import os
                self.assertIn('filePath', params)
                with open(params['filePath']) as stream:
                    self.assertNotIn('SECRET', stream.read())
                self.assertEqual(os.stat(params['filePath']).st_mode & 0o777, 0o600)
            if action == 'alerts':
                return {'alerts': [{'alert': 'Secret exposure', 'risk': 'High', 'url': self.lab.origin + '/', 'evidence': 'SECRET', 'solution': 'Protect data'}, {'alert': 'Outside', 'risk': 'High', 'url': 'https://outside.test/'}]}
            return {'Result': 'OK'}
        with patch.object(zap, 'api', side_effect=api):
            result = zap.inspect([response], self.lab.origin, threading.Event())
        imported = next(c for c in calls if c[2] == 'importHar')
        self.assertEqual(imported[3]['sendRequests'], 'false')
        import os
        self.assertFalse(os.path.exists(imported[3]['filePath']))
        self.assertEqual(len(result['alerts']), 1)
        self.assertEqual(result['alerts'][0]['status'], 'suspected')
        self.assertEqual(result['alerts'][0]['english']['title'], 'Secret exposure')
        self.assertEqual(result['alerts'][0]['english']['fix'], 'Protect data')
        self.assertIn('sızıntısı', result['alerts'][0]['title'])
        self.assertNotEqual(result['alerts'][0]['fix'], 'Protect data')
        self.assertNotIn('SECRET', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
