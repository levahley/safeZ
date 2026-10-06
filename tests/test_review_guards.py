import threading
import time
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from kanit.engine import Scanner
from kanit.lab import start_lab
from kanit.scope import Cancelled, HaltScan, Policy, ScopeError, Transport, read_only_url


class ReviewGuards(unittest.TestCase):
    def test_dns_deadline_and_cancel_bound_resolver(self):
        stop = threading.Event()
        def slow_resolve(*args):
            time.sleep(1)
            return ['8.8.8.8']
        with patch('kanit.scope.resolve', side_effect=slow_resolve):
            started = time.monotonic()
            with self.assertRaises(HaltScan):
                Policy().address('https://example.com', stop, time.monotonic() + .1)
            self.assertLess(time.monotonic() - started, .5)
            timer = threading.Timer(.05, stop.set)
            timer.start()
            with self.assertRaises(Cancelled): Policy().address('https://example.com', stop)
            timer.join()

    def test_nested_marker_echo_is_rejected(self):
        scanner = Scanner('https://example.com', Policy())
        with self.assertRaises(ScopeError):
            scanner.validate_config({'authentication': {'url': 'https://example.com/echo?v=%2553%2541%2546%2545%255A%255F%2550%2552%2549%2556%2541%2554%2545', 'marker': 'SAFEZ_PRIVATE'}})

    def test_nested_network_query_is_rejected(self):
        self.assertFalse(read_only_url('https://example.com/fetch?%2575%2572%256c=http%253A%252F%252F127.0.0.1'))

    def test_two_sessions_of_one_principal_do_not_confirm_bola(self):
        lab = start_lab('vulnerable', 0)
        try:
            config = lab.test_config()
            config['accounts']['b'] = {'cookie': config['accounts']['a']['cookie'] + '; harmless=1'}
            report = Scanner(lab.origin, Policy(labs={lab.origin}), rate=100).run(config)
            self.assertFalse(any(f['kind'] == 'bola' for f in report['findings']))
            self.assertEqual(next(c for c in report['coverage'] if c['kind'] == 'bola')['state'], 'inconclusive')
        finally:
            lab.shutdown()

    def slow_transport(self, body=False):
        started = threading.Event()
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                try:
                    if body:
                        self.send_response(200)
                        self.send_header('Content-Length', '100')
                        self.end_headers()
                    else:
                        self.wfile.write(b'HTTP/1.1 200 OK\r\nX-Slow: ')
                    started.set()
                    for _ in range(100):
                        self.wfile.write(b'x')
                        self.wfile.flush()
                        time.sleep(.04)
                except OSError: pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        origin = 'http://127.0.0.1:' + str(server.server_port)
        return Transport(origin, Policy(labs={origin}), rate=100, timeout=.25), origin, started

    def test_total_deadline_interrupts_trickled_headers_and_body(self):
        for body in (False, True):
            transport, origin, _ = self.slow_transport(body)
            started = time.monotonic()
            with self.assertRaises(HaltScan): transport.get(origin)
            self.assertLess(time.monotonic() - started, 1)

    def test_cancel_interrupts_active_response(self):
        transport, origin, started = self.slow_transport(True)
        transport.timeout = 6
        result = []
        def request():
            try: transport.get(origin)
            except Exception as error: result.append(error)
        thread = threading.Thread(target=request)
        thread.start()
        self.assertTrue(started.wait(1))
        transport.stop.set()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertIsInstance(result[0], Cancelled)


if __name__ == '__main__': unittest.main()
