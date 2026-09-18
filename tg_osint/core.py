from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

USERNAME_RE = re.compile(r"(?<![A-Za-z0-9_])@([A-Za-z0-9_]{5,32})")
URL_RE = re.compile(r"https?://[^\s<>\"']+")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(r"(?<![@\w])(?:[a-zA-Z0-9-]+\.)+[A-Za-z]{2,}(?![\w])")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

@dataclass
class Evidence:
    source_type: str
    source_url: str
    collected_at: str
    title: str | None
    text: str
    sha256: str
    metadata: dict

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()

def normalize_target(target: str) -> dict:
    raw = target.strip()
    if raw.startswith("@"):
        username = raw[1:]
    elif raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        if parsed.netloc.lower() not in {"t.me", "www.t.me", "telegram.me", "www.telegram.me"}:
            raise ValueError("Only public t.me/telegram.me URLs are accepted.")
        parts = [p for p in parsed.path.split("/") if p]
        if not parts:
            raise ValueError("Telegram URL has no public username/path.")
        username = parts[0].lstrip("@")
    else:
        username = raw.lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_]{5,32}", username):
        raise ValueError("Target must be a Telegram public username (5-32 letters/numbers/underscore).")
    return {"username": username, "handle": f"@{username}", "url": f"https://t.me/{username}"}

def extract_iocs(text: str) -> dict:
    return {
        "urls": sorted(set(URL_RE.findall(text))),
        "usernames": sorted({f"@{x}" for x in USERNAME_RE.findall(text)}),
        "emails": sorted(set(EMAIL_RE.findall(text))),
        "domains": sorted(set(DOMAIN_RE.findall(text))),
        "ipv4": sorted(set(IP_RE.findall(text))),
    }

class CaseDB:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("""CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, target TEXT NOT NULL, created_at TEXT NOT NULL, report_path TEXT, notes TEXT DEFAULT '')""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL, source_type TEXT, source_url TEXT, collected_at TEXT, title TEXT, text TEXT, sha256 TEXT, metadata_json TEXT, FOREIGN KEY(case_id) REFERENCES cases(id))""")
        self.db.commit()
    def create_case(self, target: str) -> int:
        cur = self.db.execute("INSERT INTO cases(target,created_at) VALUES(?,?)", (target, now_iso()))
        self.db.commit()
        return int(cur.lastrowid)
    def add_evidence(self, case_id: int, ev: Evidence) -> None:
        self.db.execute("INSERT INTO evidence(case_id,source_type,source_url,collected_at,title,text,sha256,metadata_json) VALUES(?,?,?,?,?,?,?,?)", (case_id, ev.source_type, ev.source_url, ev.collected_at, ev.title, ev.text, ev.sha256, json.dumps(ev.metadata, sort_keys=True)))
        self.db.commit()
    def search_evidence(self, case_id: int, query: str) -> list[tuple]:
        q=f"%{query.lower()}%"
        return self.db.execute("SELECT source_type,source_url,collected_at,title,text,sha256 FROM evidence WHERE case_id=? AND lower(text) LIKE ? ORDER BY collected_at DESC",(case_id,q)).fetchall()
    def close(self):
        self.db.close()

def sleep_rate(seconds: float):
    if seconds > 0:
        time.sleep(seconds)