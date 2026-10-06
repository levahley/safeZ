"""Exercise the real shortcut controller with disposable local processes."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ShortcutTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT / 'launcher.py').exists(), 'Çift tıklama başlatıcısı eksik')
        self.temp = tempfile.TemporaryDirectory(prefix='safeZ kısayol ')
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        shutil.copy2(ROOT / 'launcher.py', self.folder / 'launcher.py')
        worker = self.folder / 'worker.py'
        worker.write_text('''import argparse, http.server, json, os, signal, subprocess, sys, threading
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int)
args, _ = parser.parse_known_args()
threading.Timer(120, lambda: os._exit(0)).start()
child = subprocess.Popen([sys.executable, '-c', "import http.server,signal,threading,os; from pathlib import Path; signal.signal(signal.SIGTERM, signal.SIG_IGN); threading.Timer(120, lambda: os._exit(0)).start(); s=http.server.HTTPServer(('127.0.0.1',0),http.server.SimpleHTTPRequestHandler); Path('engine.port').write_text(str(s.server_port)); s.serve_forever()"])
Path('engine.pid').write_text(str(child.pid))
server = http.server.HTTPServer(('127.0.0.1', args.port), http.server.SimpleHTTPRequestHandler)
server.serve_forever()
''')
        starter = self.folder / 'start.sh'
        starter.write_text('#!/bin/sh\ncd "$(dirname "$0")"\nexec ' + "'" + sys.executable + "'" + ' worker.py "$@"\n')
        starter.chmod(0o755)
        self.addCleanup(self.cleanup_group)

    def cleanup_group(self):
        self.command('stop')

    def command(self, action, *args):
        return subprocess.run([sys.executable, str(self.folder / 'launcher.py'), action, *args],
                              capture_output=True, text=True, timeout=40,
                              env={**os.environ, 'SAFEZ_STOP_TIMEOUT': '1'})

    def test_start_is_idempotent_and_stop_closes_child_engine(self):
        first = self.command('start', '--no-browser')
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        state_path = self.folder / 'work' / 'launcher.json'
        original = json.loads(state_path.read_text())
        with socket.create_connection(('127.0.0.1', original['control_port']), timeout=2) as client:
            client.sendall(b'{"token":"wrong","action":"stop"}\n')
            self.assertEqual(client.recv(1), b'')
        second = self.command('start', '--no-browser')
        self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
        self.assertEqual(json.loads(state_path.read_text())['pid'], original['pid'])
        deadline = time.monotonic() + 5
        while not (self.folder / 'engine.port').exists() and time.monotonic() < deadline:
            time.sleep(.05)
        engine_port = int((self.folder / 'engine.port').read_text())
        stopped = self.command('stop')
        self.assertEqual(stopped.returncode, 0, stopped.stderr + stopped.stdout)
        self.assertFalse(state_path.exists())
        app_port = int(original['url'].split(':')[-1].rstrip('/'))
        for port in (app_port, engine_port):
            with socket.socket() as probe:
                probe.settimeout(.5)
                self.assertNotEqual(probe.connect_ex(('127.0.0.1', port)), 0, 'Uygulama veya motor hâlâ açık')
        again = self.command('stop')
        self.assertEqual(again.returncode, 0, again.stderr)

    def test_stale_pid_cannot_stop_an_unrelated_process(self):
        other = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'], start_new_session=True)
        self.addCleanup(lambda: (other.terminate(), other.wait()) if other.poll() is None else None)
        work = self.folder / 'work'
        work.mkdir()
        (work / 'launcher.json').write_text(json.dumps({'pid': other.pid, 'control_port': 1, 'token': 'old instance', 'url': 'http://127.0.0.1:1/'}))
        result = self.command('stop')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(other.poll(), 'Eski PID kaydı başka bir süreci kapattı')

    def test_stop_is_available_before_startup_finishes(self):
        starter = self.folder / 'start.sh'
        starter.write_text(starter.read_text().replace('exec ', 'sleep 15\nexec '))
        pending = subprocess.Popen([sys.executable, str(self.folder / 'launcher.py'), 'start', '--no-browser'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (pending.terminate(), pending.wait()) if pending.poll() is None else None)
        deadline = time.monotonic() + 5
        while not (self.folder / 'work' / 'launcher.json').exists() and time.monotonic() < deadline:
            time.sleep(.05)
        stopped = self.command('stop')
        self.assertEqual(stopped.returncode, 0, stopped.stderr)
        _, error = pending.communicate(timeout=5)
        self.assertNotEqual(pending.returncode, 0)
        self.assertFalse((self.folder / 'work' / 'launcher.json').exists())
        self.assertFalse((self.folder / 'engine.pid').exists())

    def test_failed_start_reports_failure_and_cleans_state(self):
        (self.folder / 'start.sh').write_text('#!/bin/sh\nexit 7\n')
        result = self.command('start', '--no-browser')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.folder / 'work' / 'launcher.json').exists())


if __name__ == '__main__':
    unittest.main()
