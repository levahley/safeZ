import json
import threading
import unittest
from unittest.mock import patch
from kanit.engine import Scanner
from kanit.scope import Policy, Response, ScopeError, read_only_url


class NegativeControls(unittest.TestCase):
    def scanner(self):
        return Scanner('https://example.com', Policy(), rate=100)

    def test_reflection_is_not_sql_injection(self):
        scanner=self.scanner()
        def response(url, account=None):
            scanner.transport.count += 1
            return Response(url,200,{'content-type':'application/json'},json.dumps({'input':url,'products':[{'id':1,'name':'public'}]}).encode())
        with patch.object(scanner,'request',side_effect=response):
            scanner.sqli([{'url':'https://example.com/api?id=1','parameter':'id'}])
        self.assertEqual(scanner.report['findings'],[])

    def test_one_error_message_is_not_proof(self):
        scanner=self.scanner()
        def response(url, account=None):
            scanner.transport.count += 1
            return Response(url,500,{'content-type':'text/html'},b'SQL syntax error')
        with patch.object(scanner,'request',side_effect=response):
            scanner.sqli([{'url':'https://example.com/api?id=1','parameter':'id'}])
        self.assertEqual(scanner.report['findings'],[])

    def test_dynamic_rows_are_not_confirmed(self):
        scanner=self.scanner()
        def response(url, account=None):
            scanner.transport.count += 1
            body=json.dumps({'products':[{'id':scanner.transport.count}]}).encode()
            return Response(url,200,{'content-type':'application/json'},body)
        with patch.object(scanner,'request',side_effect=response):
            scanner.sqli([{'url':'https://example.com/api?id=1','parameter':'id'}])
        self.assertEqual(scanner.report['findings'],[])

    def test_markers_cannot_be_supplied_in_urls(self):
        scanner=self.scanner()
        config={'authentication':{'url':'https://example.com/api?echo=SAFEZ_PRIVATE','marker':'SAFEZ_PRIVATE'}}
        with self.assertRaises(ScopeError):
            scanner.validate_config(config)

    def test_encoded_operation_and_network_parameters_are_not_crawled(self):
        for url in ['https://example.com/%64elete?id=1','https://example.com/%2564elete','https://example.com/fetch?url=http%3A%2F%2F127.0.0.1','https://example.com/a?callback=https%3A%2F%2Foutside.test']:
            self.assertFalse(read_only_url(url),url)

    def test_sqli_type_alone_does_not_make_high_risk(self):
        from kanit.lab import start_lab
        lab=start_lab('vulnerable',0)
        try:
            cfg=lab.test_config()
            cfg['injection'][0].pop('restricted_marker')
            scanner=Scanner(lab.origin,Policy(labs={lab.origin}),rate=100)
            report=scanner.run(cfg)
            sqli=next(f for f in report['findings'] if f['kind']=='sqli')
            self.assertEqual(sqli['severity'],'medium')
        finally: lab.shutdown()

    def test_one_positive_auth_round_stays_suspected(self):
        scanner=self.scanner()
        index=0
        def response(url, account=None):
            nonlocal index
            index+=1
            scanner.transport.count+=1
            denied=index in (5,6)
            return Response(url,401 if denied else 200,{'content-type':'application/json'},b'{}' if denied else b'{"private":"SAFEZ_PRIVATE"}')
        with patch.object(scanner,'request',side_effect=response):
            scanner.auth({'url':'https://example.com/private','marker':'SAFEZ_PRIVATE','impact':'sensitive'},{'a':{'cookie':'sid=test'}})
        self.assertEqual(scanner.report['findings'][0]['status'],'suspected')
        self.assertEqual(scanner.report['findings'][0]['severity'],'medium')

    def test_budget_exhaustion_is_partial_and_coverage_is_complete(self):
        from kanit.lab import start_lab
        lab=start_lab('fixed',0)
        try:
            scanner=Scanner(lab.origin,Policy(labs={lab.origin}),rate=100,budget=1)
            report=scanner.run(lab.test_config())
            self.assertFalse(report['complete'])
            self.assertTrue(any(c['state']=='inconclusive' for c in report['coverage']))
            self.assertEqual(scanner.transport.count,1)
        finally: lab.shutdown()

    def test_cancelled_report_still_lists_untested_checks(self):
        from kanit.scope import Cancelled
        scanner=self.scanner()
        scanner.transport.stop.set()
        with self.assertRaises(Cancelled):scanner.run()
        coverage={c['kind'] for c in scanner.report['coverage']}
        self.assertTrue({'sqli','bola','auth','ssrf','xss'}.issubset(coverage))


if __name__=='__main__': unittest.main()
