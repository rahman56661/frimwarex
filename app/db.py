"""SQLite store (swap for PostgreSQL later -- same shape). Includes a hash-chained,
append-only audit log (PRD 4.3: immutable audit log)."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

DATA_DIR = os.environ.get("FWX_DATA", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data"))
DB_PATH = os.path.join(DATA_DIR, "fwx.db")
_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS firmware(id TEXT PRIMARY KEY, filename TEXT, sha256 TEXT, size INTEGER,
    status TEXT, created_at TEXT, summary TEXT);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, firmware_id TEXT, stage TEXT, status TEXT,
    started_at TEXT, finished_at TEXT, error TEXT, stages TEXT);
CREATE TABLE IF NOT EXISTS artifacts(firmware_id TEXT, name TEXT, body TEXT, PRIMARY KEY(firmware_id,name));
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, firmware_id TEXT, body TEXT);
CREATE TABLE IF NOT EXISTS audit_log(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, firmware_id TEXT,
    event TEXT, detail TEXT, prev_hash TEXT, hash TEXT);
"""


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


@contextmanager
def conn():
    os.makedirs(DATA_DIR, exist_ok=True)
    with _lock:
        c = sqlite3.connect(DB_PATH)
        c.row_factory = sqlite3.Row
        try:
            c.executescript(SCHEMA)
            yield c
            c.commit()
        finally:
            c.close()


def audit(firmware_id: str, event: str, detail: Any = None) -> None:
    detail_s = json.dumps(detail, sort_keys=True, default=str) if detail is not None else ""
    with conn() as c:
        row = c.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else "0" * 64
        ts = now()
        h = hashlib.sha256(f"{prev}|{ts}|{firmware_id}|{event}|{detail_s}".encode()).hexdigest()
        c.execute("INSERT INTO audit_log(ts,firmware_id,event,detail,prev_hash,hash) VALUES(?,?,?,?,?,?)",
                  (ts, firmware_id, event, detail_s, prev, h))


def verify_audit_chain() -> bool:
    with conn() as c:
        prev = "0" * 64
        for r in c.execute("SELECT * FROM audit_log ORDER BY seq"):
            exp = hashlib.sha256(f"{prev}|{r['ts']}|{r['firmware_id']}|{r['event']}|{r['detail']}".encode()).hexdigest()
            if r["prev_hash"] != prev or r["hash"] != exp:
                return False
            prev = r["hash"]
    return True


def audit_rows(firmware_id: str) -> List[Dict]:
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT ts,event,detail FROM audit_log WHERE firmware_id=? ORDER BY seq", (firmware_id,))]


def put_artifact(fid: str, name: str, body: Any) -> None:
    with conn() as c:
        c.execute("INSERT OR REPLACE INTO artifacts VALUES(?,?,?)", (fid, name, json.dumps(body, default=str)))


def get_artifact(fid: str, name: str) -> Optional[Any]:
    with conn() as c:
        r = c.execute("SELECT body FROM artifacts WHERE firmware_id=? AND name=?", (fid, name)).fetchone()
    return json.loads(r["body"]) if r else None


def put_findings(fid: str, findings: List[Any]) -> None:
    with conn() as c:
        c.execute("DELETE FROM findings WHERE firmware_id=?", (fid,))
        c.executemany("INSERT INTO findings VALUES(?,?,?)",
                      [(f.vulnerability_id, fid, f.model_dump_json()) for f in findings])


def get_findings(fid: str) -> List[Dict]:
    with conn() as c:
        return [json.loads(r["body"]) for r in c.execute("SELECT body FROM findings WHERE firmware_id=?", (fid,))]
