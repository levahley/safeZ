"""Small local SQLite store. Sessions are deliberately never stored."""
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        with self.connect() as db:
            db.executescript('CREATE TABLE IF NOT EXISTS sites (id TEXT PRIMARY KEY, payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, payload TEXT NOT NULL);')
        os.chmod(self.path, 0o600)
        for scan in self.scans():
            if scan['status'] in ('queued', 'running', 'stopping'):
                scan.update(status='interrupted', stage='Uygulama yeniden başlatıldı; tarama yarıda kaldı.')
                self.save_scan(scan)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def _save(self, table, record):
        with self.lock, self.connect() as db:
            db.execute('INSERT OR REPLACE INTO ' + table + ' VALUES (?, ?)', (record['id'], json.dumps(record, ensure_ascii=False)))

    def _get(self, table, key):
        with self.connect() as db:
            row = db.execute('SELECT payload FROM ' + table + ' WHERE id=?', (key,)).fetchone()
        if not row:
            raise KeyError('Kayıt bulunamadı.')
        return json.loads(row[0])

    def _list(self, table):
        with self.connect() as db:
            rows = db.execute('SELECT payload FROM ' + table + ' ORDER BY rowid DESC LIMIT 100').fetchall()
        return [json.loads(row[0]) for row in rows]

    def save_site(self, record):
        self._save('sites', record)

    def get_site(self, key):
        return self._get('sites', key)

    def sites(self):
        return self._list('sites')

    def save_scan(self, record):
        self._save('scans', record)

    def get_scan(self, key):
        return self._get('scans', key)

    def scans(self):
        return self._list('scans')
