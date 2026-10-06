#!/usr/bin/env python3
"""Install official, checksum-verified ZAP and Temurin into this project only."""
import hashlib
import json
import os
import platform
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Large Java files must stay outside cloud-synced source folders. This cache
# can be recreated from checksum-verified vendor archives after OS cleanup.
RUNTIME = Path(os.environ.get('KANIT_RUNTIME_DIR', str(Path(tempfile.gettempdir()) / ('kanit-runtime-' + str(os.getuid())))))
VERSION = '2.17.0'
ZAP_URL = 'https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip'
ZAP_SHA = '94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0'


def get(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'safeZ/1.0 official-runtime-installer'}), timeout=40)


def download(url, target, expected):
    if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == expected:
        return
    print('İndiriliyor: ' + target.name, flush=True)
    temp = target.with_suffix(target.suffix + '.partial')
    hasher = hashlib.sha256()
    with get(url) as source, temp.open('wb') as out:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
            out.write(chunk)
    if hasher.hexdigest() != expected:
        temp.unlink()
        raise RuntimeError('İndirme SHA-256 doğrulaması başarısız: ' + target.name)
    temp.replace(target)


def contained(base, name):
    candidate = (base / name).resolve()
    return candidate == base.resolve() or base.resolve() in candidate.parents


def install():
    RUNTIME.mkdir(parents=True, exist_ok=True)
    if RUNTIME.stat().st_uid != os.getuid():
        raise RuntimeError('Motor önbelleği bu kullanıcıya ait değil.')
    os.chmod(RUNTIME, 0o700)
    archive = RUNTIME / 'zap.zip'
    zap_dir = RUNTIME / ('ZAP_' + VERSION)
    if not (zap_dir / ('zap-' + VERSION + '.jar')).exists():
        download(ZAP_URL, archive, ZAP_SHA)
        with zipfile.ZipFile(archive) as z:
            if any(not contained(RUNTIME, name) for name in z.namelist()):
                raise RuntimeError('Arşiv yolu geçersiz.')
            z.extractall(RUNTIME)
        archive.unlink()
    java = next(iter(RUNTIME.glob('jdk*/Contents/Home/bin/java')), None) or next(iter(RUNTIME.glob('jdk*/bin/java')), None)
    if java is None:
        system = {'Darwin': 'mac', 'Linux': 'linux'}.get(platform.system())
        arch = {'arm64': 'aarch64', 'aarch64': 'aarch64', 'x86_64': 'x64', 'AMD64': 'x64'}.get(platform.machine())
        if not system or not arch:
            raise RuntimeError('Otomatik motor kurulumu macOS/Linux içindir. Çekirdek için --no-zap kullanın.')
        with get('https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=' + arch + '&image_type=jre&os=' + system + '&vendor=eclipse') as r:
            package = json.load(r)[0]['binary']['package']
        # Only official Temurin release binaries may be installed.
        if not package['link'].startswith('https://github.com/adoptium/temurin21-binaries/releases/download/'):
            raise RuntimeError('Beklenmeyen Java indirme kaynağı.')
        tar_path = RUNTIME / 'java.tar.gz'
        download(package['link'], tar_path, package['checksum'])
        with tarfile.open(tar_path) as tar:
            for member in tar.getmembers():
                if not contained(RUNTIME, member.name):
                    raise RuntimeError('Java arşiv yolu geçersiz.')
                if member.issym() and not contained(RUNTIME, str(Path(member.name).parent / member.linkname)):
                    raise RuntimeError('Java arşiv bağlantısı geçersiz.')
                if member.islnk() and not contained(RUNTIME, member.linkname):
                    raise RuntimeError('Java arşiv bağlantısı geçersiz.')
            tar.extractall(RUNTIME)
        tar_path.unlink()
        java = next(iter(RUNTIME.glob('jdk*/Contents/Home/bin/java')), None) or next(iter(RUNTIME.glob('jdk*/bin/java')), None)
    if java is None:
        raise RuntimeError('Java çalıştırılabilir dosyası bulunamadı.')
    restrict_addons(zap_dir)
    config = {'java': str(java), 'jar': str(zap_dir / ('zap-' + VERSION + '.jar')), 'zap_version': VERSION}
    manifest = RUNTIME / 'engine.json'
    fresh = manifest.with_suffix('.fresh')
    fresh.write_text(json.dumps(config))
    fresh.replace(manifest)
    print('OWASP ZAP ' + VERSION + ' ve Java hazır.', flush=True)
    return config


def restrict_addons(zap_dir):
    # This dedicated engine only needs passive rules and HAR import. Disable
    # bundled browser/OAST/active addons, including their auxiliary listeners.
    allowed = {'callhome', 'commonlib', 'database', 'exim', 'network', 'pscan', 'pscanrules'}
    disabled = RUNTIME / 'disabled-addons'
    disabled.mkdir(exist_ok=True)
    for addon in disabled.glob('*.zap'):
        if addon.name.split('-')[0] in allowed:
            addon.replace(zap_dir / 'plugin' / addon.name)
    for addon in (zap_dir / 'plugin').glob('*.zap'):
        if addon.name.split('-')[0] not in allowed:
            addon.replace(disabled / addon.name)


if __name__ == '__main__':
    install()
