#!/usr/bin/env python3
"""SQLite-backed engagement store shared by nmap_scanner.py and nmap_import.py.

One DB file == one engagement. It records:
  - the target hosts and their scan status (pending | completed), so a scan can
    resume and only cover hosts it hasn't hit yet;
  - every open port found, by the scanner or imported from other nmap output;
  - the run configuration (output dir, custom-scan mode, start/pause times).

Uses WAL + synchronous=NORMAL: per-host commits are as cheap as an append while
staying crash-safe (a kill/Ctrl-C never corrupts the DB and loses no committed
host). nmap's own runtime dwarfs the write cost, so this is effectively free.
"""

import json
import sqlite3
import time
from pathlib import Path

SCHEMA_VERSION = 1
DEFAULT_DB_NAME = "engagement.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    ip           TEXT PRIMARY KEY,
    status       TEXT NOT NULL DEFAULT 'pending',  -- pending | completed
    added_at     REAL,
    completed_at REAL
);
CREATE TABLE IF NOT EXISTS open_ports (
    ip      TEXT NOT NULL,
    port    INTEGER NOT NULL,
    proto   TEXT NOT NULL DEFAULT 'tcp',
    service TEXT,
    source  TEXT,                              -- 'discovery' | 'custom' | 'import:<file>'
    seen_at REAL,
    PRIMARY KEY (ip, port, proto)
);
CREATE INDEX IF NOT EXISTS idx_hosts_status   ON hosts(status);
CREATE INDEX IF NOT EXISTS idx_open_ports_ip  ON open_ports(ip);
"""


class EngagementDB:
    def __init__(self, con, path):
        self.con = con
        self.path = str(path)

    # ----------------------- open / create -----------------------

    @classmethod
    def connect(cls, path, create=False):
        """Open an engagement DB. With create=False the file must already exist
        (used by --resume); with create=True it is created if missing."""
        path = Path(path)
        if not create and not path.exists():
            raise FileNotFoundError(path)
        con = sqlite3.connect(str(path))
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA busy_timeout=5000")
        con.executescript(_SCHEMA)
        con.commit()
        db = cls(con, path)
        db._set_meta_default("schema_version", str(SCHEMA_VERSION))
        db._set_meta_default("created_at", repr(time.time()))
        return db

    @staticmethod
    def resolve_path(arg, for_new):
        """Map a --db / --resume value to a concrete DB file path. A directory
        (or '.', or a trailing slash) maps to DEFAULT_DB_NAME inside it; anything
        else is treated as the file path itself."""
        p = Path(arg)
        if arg in (".", "./") or str(arg).endswith("/") or p.is_dir():
            return p / DEFAULT_DB_NAME
        return p

    # ----------------------- meta key/value -----------------------

    def get_meta(self, key, default=None):
        row = self.con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row is not None else default

    def set_meta(self, key, value):
        self.con.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
        self.con.commit()

    def _set_meta_default(self, key, value):
        self.con.execute("INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)", (key, value))
        self.con.commit()

    # ----------------------- engagement config -----------------------
    # Stored in `meta` so the scanner can restore the run on --resume.

    @property
    def output_dir(self):
        return self.get_meta("output_dir")

    @output_dir.setter
    def output_dir(self, value):
        self.set_meta("output_dir", str(value))

    @property
    def custom_args(self):
        raw = self.get_meta("custom_args")
        return json.loads(raw) if raw else None

    @custom_args.setter
    def custom_args(self, value):
        self.set_meta("custom_args", json.dumps(value) if value else None)

    @property
    def started_at(self):
        v = self.get_meta("started_at")
        return float(v) if v else None

    @started_at.setter
    def started_at(self, value):
        self.set_meta("started_at", repr(float(value)))

    @property
    def paused_at(self):
        v = self.get_meta("paused_at")
        return float(v) if v else None

    def set_paused(self, ts=None):
        self.set_meta("paused_at", repr(ts if ts is not None else time.time()))

    def clear_paused(self):
        self.con.execute("DELETE FROM meta WHERE key='paused_at'")
        self.con.commit()

    # ----------------------- hosts -----------------------

    def add_hosts(self, ips):
        """Insert target hosts as 'pending' (no-op for ones already present)."""
        now = time.time()
        self.con.executemany(
            "INSERT OR IGNORE INTO hosts(ip, status, added_at) VALUES(?, 'pending', ?)",
            [(ip, now) for ip in ips])
        self.con.commit()

    def all_hosts(self):
        """All target IPs, in insertion order (the scan order)."""
        return [r[0] for r in self.con.execute("SELECT ip FROM hosts ORDER BY rowid")]

    def completed_hosts(self):
        return [r[0] for r in self.con.execute(
            "SELECT ip FROM hosts WHERE status='completed'")]

    def counts(self):
        total = self.con.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        done = self.con.execute(
            "SELECT COUNT(*) FROM hosts WHERE status='completed'").fetchone()[0]
        return done, total

    def mark_completed(self, ip):
        """Mark one host completed — the per-host resume checkpoint."""
        now = time.time()
        self.con.execute(
            "INSERT INTO hosts(ip, status, added_at, completed_at) "
            "VALUES(?, 'completed', ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET status='completed', completed_at=excluded.completed_at",
            (ip, now, now))
        self.con.commit()

    def set_host_status(self, ip, status, commit=True):
        now = time.time()
        completed = now if status == "completed" else None
        self.con.execute(
            "INSERT INTO hosts(ip, status, added_at, completed_at) VALUES(?, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET status=excluded.status, "
            "completed_at=COALESCE(excluded.completed_at, hosts.completed_at)",
            (ip, status, now, completed))
        if commit:
            self.con.commit()

    # ----------------------- open ports -----------------------

    def record_open_ports(self, ip, ports, source, commit=True):
        """Record open ports for a host. `ports` is an iterable of either bare
        ints (proto defaults to tcp) or (port, proto, service) tuples. Existing
        rows are updated, keeping any previously-known service name if the new
        record doesn't carry one."""
        now = time.time()
        rows = []
        for p in ports:
            if isinstance(p, (tuple, list)):
                port = int(p[0])
                proto = (p[1] if len(p) > 1 and p[1] else "tcp")
                svc = (p[2] if len(p) > 2 else None) or None
            else:
                port, proto, svc = int(p), "tcp", None
            rows.append((ip, port, proto, svc, source, now))
        if not rows:
            return
        self.con.executemany(
            "INSERT INTO open_ports(ip, port, proto, service, source, seen_at) "
            "VALUES(?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip, port, proto) DO UPDATE SET "
            "  service = COALESCE(excluded.service, open_ports.service), "
            "  source  = excluded.source, "
            "  seen_at = excluded.seen_at",
            rows)
        if commit:
            self.con.commit()

    # ----------------------- misc -----------------------

    def commit(self):
        self.con.commit()

    def close(self):
        self.con.commit()
        self.con.close()
