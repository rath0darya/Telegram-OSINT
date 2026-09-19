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
    if re.fullmatch(r"-?\d{5,20}", raw):
        telegram_id = int(raw)
        return {"target_type": "telegram_id", "telegram_id": telegram_id, "username": None, "handle": str(telegram_id), "url": None}
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
    return {"target_type": "username", "telegram_id": None, "username": username, "handle": f"@{username}", "url": f"https://t.me/{username}"}

def extract_iocs(text: str) -> dict:
    return {
        "urls": sorted(set(URL_RE.findall(text))),
        "usernames": sorted({f"@{x}" for x in USERNAME_RE.findall(text)}),
        "emails": sorted(set(EMAIL_RE.findall(text))),
        "domains": sorted(set(DOMAIN_RE.findall(text))),
        "ipv4": sorted(set(IP_RE.findall(text))),
    }

class CaseDB:
    """MariaDB-backed case/evidence store."""

    def __init__(self, database: str = "telegram_osint"):
        from .mysql import connect
        self.db = connect()
        with self.db.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    target VARCHAR(255) NOT NULL,
                    created_at VARCHAR(64) NOT NULL,
                    report_path TEXT,
                    notes TEXT
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    case_id BIGINT UNSIGNED NOT NULL,
                    source_type VARCHAR(128),
                    source_url TEXT,
                    collected_at VARCHAR(64),
                    title TEXT,
                    text LONGTEXT,
                    sha256 CHAR(64),
                    metadata_json LONGTEXT,
                    UNIQUE KEY uq_case_evidence_sha (case_id, sha256),
                    CONSTRAINT fk_case_evidence FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
        self.db.commit()

    def create_case(self, target: str) -> int:
        with self.db.cursor() as cur:
            cur.execute("INSERT INTO cases(target,created_at) VALUES(%s,%s)", (target, now_iso()))
            return int(cur.lastrowid)

    def add_evidence(self, case_id: int, ev: Evidence) -> None:
        with self.db.cursor() as cur:
            cur.execute(
                "INSERT IGNORE INTO evidence(case_id,source_type,source_url,collected_at,title,text,sha256,metadata_json) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                (case_id, ev.source_type, ev.source_url, ev.collected_at, ev.title, ev.text, ev.sha256,
                 json.dumps(ev.metadata, sort_keys=True)),
            )
        self.db.commit()

    def search_evidence(self, case_id: int, query: str) -> list[tuple]:
        q = f"%{query.lower()}%"
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT source_type,source_url,collected_at,title,text,sha256 FROM evidence "
                "WHERE case_id=%s AND LOWER(text) LIKE %s ORDER BY collected_at DESC",
                (case_id, q),
            )
            rows = cur.fetchall()
        return [
            (r["source_type"], r["source_url"], r["collected_at"], r["title"], r["text"], r["sha256"])
            for r in rows
        ]

    def close(self):
        self.db.close()

def sleep_rate(seconds: float):
    if seconds > 0:
        time.sleep(seconds)