#!/usr/bin/env python3
"""Own the dedicated local ZAP process and stop it with the app."""
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from app import main
from kanit.zap import Zap
from install_engine import install, ROOT, RUNTIME, restrict_addons


def interrupt(_signal, _frame):
    # Graceful close also works when launched in the background by Finder.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise KeyboardInterrupt


def run():
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    if '--no-zap' in sys.argv:
        sys.argv.remove('--no-zap')
        return main()
    config_path = RUNTIME / 'engine.json'
    config = json.loads(config_path.read_text()) if config_path.exists() else install()
    restrict_addons((ROOT / config['jar']).parent)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    key = secrets.token_urlsafe(32)
    work = ROOT / 'work'
    work.mkdir(exist_ok=True)
    os.chmod(work, 0o700)
    with tempfile.TemporaryDirectory(prefix='zap-', dir=work) as state:
        os.chmod(state, 0o700)
        log_path = work / 'zap.log'
        # Replacing instead of truncating also tolerates cloud placeholder files.
        with tempfile.NamedTemporaryFile(dir=work, prefix='zap-log-', delete=False) as fresh_log:
            fresh_log_path = fresh_log.name
        os.replace(fresh_log_path, log_path)
        with log_path.open('w') as log:
            os.chmod(log_path, 0o600)
            command = [str(ROOT / config['java']), '-Xmx512m', '-Djava.awt.headless=true', '-jar', str(ROOT / config['jar']), '-daemon', '-silent', '-host', '127.0.0.1', '-port', str(port), '-dir', state, '-config', 'api.key=' + key, '-config', 'api.addrs.addr.name=127.0.0.1', '-config', 'api.addrs.addr.regex=false', '-config', 'database.recoverylog=false', '-config', 'autoupdate.checkOnStart=false']
            proc = subprocess.Popen(command, stdout=log, stderr=log, cwd=ROOT)
            try:
                zap = Zap('http://127.0.0.1:' + str(port), key)
                print('Yerel OWASP ZAP pasif motoru başlatılıyor…', flush=True)
                for _ in range(90):
                    if proc.poll() is not None:
                        raise RuntimeError('ZAP başlatılamadı. Ayrıntı: work/zap.log')
                    try:
                        zap.api('core', 'view', 'version')
                        break
                    except Exception:
                        time.sleep(.5)
                else:
                    raise RuntimeError('ZAP başlatma zaman aşımı. Ayrıntı: work/zap.log')
                print('Pasif motor hazır. Aktif ZAP taramaları kapalı.', flush=True)
                main(zap)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == '__main__':
    try:
        run()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print('Başlatma hatası: ' + str(exc) + '\nMotor olmadan karşılaştırmalı çekirdek: ./start.sh --no-zap', file=sys.stderr)
        sys.exit(1)
