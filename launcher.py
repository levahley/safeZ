#!/usr/bin/env python3
"""Double-click launcher. Only the supervisor can stop its own app process group."""
import argparse
import fcntl
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORK = ROOT / 'work'
STATE = WORK / 'launcher.json'


def request(state, action, timeout=2):
    try:
        with socket.create_connection(('127.0.0.1', state['control_port']), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall((json.dumps({'token': state['token'], 'action': action}) + '\n').encode())
            reply = sock.makefile('rb').readline(4096)
        result = json.loads(reply)
        return result if result.get('token') == state['token'] else None
    except (OSError, ValueError, KeyError):
        return None


def read_state():
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return None


def save(state):
    with tempfile.NamedTemporaryFile(mode='w', dir=WORK, delete=False) as file:
        json.dump(state, file)
        temporary = file.name
    os.replace(temporary, STATE)


def close_app(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=float(os.environ.get('SAFEZ_STOP_TIMEOUT', '25')))
        except subprocess.TimeoutExpired:
            pass
    # Includes installation children and an engine left behind by an unexpected exit.
    # This ID comes from our Popen, never from a stale PID file.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def supervise(fd, port, app_args):
    token = os.environ.pop('SAFEZ_CONTROL_TOKEN')
    listener = socket.socket(fileno=fd)
    listener.settimeout(.5)
    process = None
    try:
        process = subprocess.Popen([str(ROOT / 'start.sh'), '--port', str(port),
                                    '--lab-ports', '0', '0', *app_args],
                                   cwd=ROOT, stdin=subprocess.DEVNULL, start_new_session=True)
        while process.poll() is None:
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            with client:
                client.settimeout(2)
                try:
                    data = json.loads(client.makefile('rb').readline(4096))
                except (OSError, ValueError):
                    continue
                if not isinstance(data, dict) or not secrets.compare_digest(str(data.get('token', '')), token):
                    continue
                if data.get('action') == 'stop':
                    close_app(process)
                    process = None
                    client.sendall((json.dumps({'token': token, 'stopped': True}) + '\n').encode())
                    return
                try:
                    client.sendall((json.dumps({'token': token, 'running': True}) + '\n').encode())
                except OSError:
                    pass
    finally:
        if process is not None:
            close_app(process)
        listener.close()


def main():
    parser = argparse.ArgumentParser(description='safeZ Başlat / Durdur')
    parser.add_argument('action', choices=('start', 'stop'))
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--data-dir', default=os.environ.get('SAFEZ_DATA_DIR',
                        str(Path.home() / 'Library' / 'Application Support' / 'safeZ')
                        if sys.platform == 'darwin' else str(ROOT / 'work' / 'data')))
    args, app_args = parser.parse_known_args()
    app_args = ['--data-dir', args.data_dir, *app_args]
    WORK.mkdir(exist_ok=True, mode=0o700)
    os.chmod(WORK, 0o700)
    with (WORK / 'launcher.lock').open('a') as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = read_state()
        running = state and request(state, 'status')
        if args.action == 'stop':
            if running and not request(state, 'stop', timeout=40):
                raise RuntimeError('Kapanış tamamlanamadı; Durdur dosyasını tekrar çalıştırın.')
            STATE.unlink(missing_ok=True)
            print('safeZ ve bağlı tarama motoru kapatıldı.' if running else 'safeZ zaten kapalı.')
            return
        if not running:
            with socket.socket() as sock:
                try:
                    sock.bind(('127.0.0.1', 8787))
                except OSError:
                    sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                listener.listen(4)
                control_port = listener.getsockname()[1]
                token = secrets.token_urlsafe(32)
                with tempfile.NamedTemporaryFile(dir=WORK, delete=False) as file:
                    log_name = file.name
                os.replace(log_name, WORK / 'safez.log')
                with (WORK / 'safez.log').open('a') as log:
                    supervisor = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                                   'serve', str(listener.fileno()), str(port), *app_args],
                                                  cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                                  env={**os.environ, 'SAFEZ_CONTROL_TOKEN': token},
                                                  pass_fds=(listener.fileno(),), start_new_session=True)
                state = {'pid': supervisor.pid, 'control_port': control_port, 'token': token,
                         'url': f'http://127.0.0.1:{port}/'}
                save(state)
            print('safeZ hazırlanıyor… İlk kurulum birkaç dakika sürebilir.', flush=True)
        else:
            print('safeZ zaten açık; mevcut pencere açılıyor.', flush=True)
    # Stop stays available during dependency installation and engine startup.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        if not request(state, 'status'):
            with (WORK / 'launcher.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                if read_state() == state:
                    STATE.unlink(missing_ok=True)
            raise RuntimeError(f'Başlangıç tamamlanmadı veya durduruldu. Ayrıntı: {WORK / "safez.log"}')
        try:
            with opener.open(state['url'], timeout=1) as response:
                if response.status == 200:
                    print('safeZ hazır: ' + state['url'])
                    if not args.no_browser and sys.platform == 'darwin':
                        opened = subprocess.run(['open', state['url']], capture_output=True)
                        if opened.returncode:
                            opened = subprocess.run(['open', '-a', 'Safari', state['url']], capture_output=True)
                        if opened.returncode:
                            print('Tarayıcı açılamadı. Yukarıdaki adresi tarayıcınızda açın.')
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(.5)
    raise RuntimeError(f'Başlangıç uzun sürüyor. Ayrıntı: {WORK / "safez.log"}. Kapatmak için Durdur dosyasını kullanın.')


if __name__ == '__main__':
    try:
        if len(sys.argv) > 1 and sys.argv[1] == 'serve':
            supervise(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4:])
        else:
            main()
    except KeyboardInterrupt:
        print('Kısayol kapatıldı; uygulamayı kapatmak için safeZ Durdur dosyasını kullanın.')
        sys.exit(1)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
