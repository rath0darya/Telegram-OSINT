from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from .core import Evidence, extract_iocs, now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
 id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, target TEXT, evidence_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS entities (
 id INTEGER PRIMARY KEY, telegram_id INTEGER UNIQUE, username TEXT, display_name TEXT,
 entity_type TEXT NOT NULL DEFAULT 'unknown', first_observed TEXT NOT NULL, last_observed TEXT NOT NULL,
 metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS chats (
 id INTEGER PRIMARY KEY, telegram_id INTEGER UNIQUE, username TEXT, title TEXT,
 chat_type TEXT NOT NULL DEFAULT 'unknown', first_observed TEXT NOT NULL, last_observed TEXT NOT NULL,
 metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY, chat_id INTEGER NOT NULL, telegram_message_id INTEGER NOT NULL,
 observed_at TEXT NOT NULL, message_date TEXT, text TEXT NOT NULL, source_url TEXT,
 views INTEGER, forwards INTEGER, sha256 TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}',
 UNIQUE(chat_id, telegram_message_id)
);
CREATE TABLE IF NOT EXISTS observations (
 id INTEGER PRIMARY KEY, entity_id INTEGER, chat_id INTEGER, observed_at TEXT NOT NULL,
 observation_type TEXT NOT NULL, source_url TEXT, evidence_sha256 TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS identifiers (
 id INTEGER PRIMARY KEY, entity_id INTEGER NOT NULL, identifier_type TEXT NOT NULL, value TEXT NOT NULL,
 first_observed TEXT NOT NULL, last_observed TEXT NOT NULL, UNIQUE(entity_id, identifier_type, value)
);
CREATE TABLE IF NOT EXISTS edges (
 id INTEGER PRIMARY KEY, source_entity_id INTEGER, target_entity_id INTEGER, source_chat_id INTEGER,
 edge_type TEXT NOT NULL, observed_at TEXT NOT NULL, source_url TEXT, evidence_sha256 TEXT NOT NULL,
 UNIQUE(source_entity_id, target_entity_id, source_chat_id, edge_type, evidence_sha256)
);
CREATE INDEX IF NOT EXISTS idx_entities_username ON entities(username);
CREATE INDEX IF NOT EXISTS idx_identifiers_value ON identifiers(value);
CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(message_date);
CREATE INDEX IF NOT EXISTS idx_observations_time ON observations(observed_at);
CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_entity_id);
"""

class IntelligenceDB:
    """Persistent store for public observations actually collected by this project."""

    def __init__(self, path: str = "cases/intelligence.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    def _entity(self, telegram_id, username, display_name, entity_type, observed_at, metadata):
        row = None
        if telegram_id is not None:
            row = self.db.execute("SELECT id FROM entities WHERE telegram_id=?", (telegram_id,)).fetchone()
        if row is None and username:
            row = self.db.execute("SELECT id FROM entities WHERE lower(username)=lower(?)", (username,)).fetchone()
        if row:
            eid = row["id"]
            self.db.execute(
                """UPDATE entities SET username=COALESCE(?,username), display_name=COALESCE(?,display_name),
                entity_type=?, last_observed=?, metadata_json=? WHERE id=?""",
                (username, display_name, entity_type, observed_at, json.dumps(metadata, sort_keys=True), eid))
            return eid
        cur = self.db.execute(
            """INSERT INTO entities(telegram_id,username,display_name,entity_type,first_observed,last_observed,metadata_json)
            VALUES(?,?,?,?,?,?,?)""",
            (telegram_id, username, display_name, entity_type, observed_at, observed_at, json.dumps(metadata, sort_keys=True)))
        return cur.lastrowid

    def _chat(self, telegram_id, username, title, chat_type, observed_at, metadata):
        row = None
        if telegram_id is not None:
            row = self.db.execute("SELECT id FROM chats WHERE telegram_id=?", (telegram_id,)).fetchone()
        if row is None and username:
            row = self.db.execute("SELECT id FROM chats WHERE lower(username)=lower(?)", (username,)).fetchone()
        if row:
            cid = row["id"]
            self.db.execute(
                """UPDATE chats SET username=COALESCE(?,username), title=COALESCE(?,title),
                chat_type=?, last_observed=?, metadata_json=? WHERE id=?""",
                (username, title, chat_type, observed_at, json.dumps(metadata, sort_keys=True), cid))
            return cid
        cur = self.db.execute(
            """INSERT INTO chats(telegram_id,username,title,chat_type,first_observed,last_observed,metadata_json)
            VALUES(?,?,?,?,?,?,?)""",
            (telegram_id, username, title, chat_type, observed_at, observed_at, json.dumps(metadata, sort_keys=True)))
        return cur.lastrowid

    def _identifier(self, entity_id, kind, value, observed_at):
        if not value or entity_id is None:
            return
        self.db.execute(
            """INSERT INTO identifiers(entity_id,identifier_type,value,first_observed,last_observed)
            VALUES(?,?,?,?,?) ON CONFLICT(entity_id,identifier_type,value)
            DO UPDATE SET last_observed=excluded.last_observed""",
            (entity_id, kind, value, observed_at, observed_at))

    def start_run(self, target: str) -> int:
        cur = self.db.execute("INSERT INTO runs(started_at,target) VALUES(?,?)", (now_iso(), target))
        self.db.commit()
        return int(cur.lastrowid)

    def finish_run(self, run_id: int, count: int):
        self.db.execute("UPDATE runs SET finished_at=?,evidence_count=? WHERE id=?", (now_iso(), count, run_id))
        self.db.commit()

    def ingest(self, evidence: Iterable[Evidence]) -> int:
        count = 0
        for ev in evidence:
            meta = ev.metadata or {}
            entity_meta = meta.get("entity") if isinstance(meta.get("entity"), dict) else {}
            eid = None
            if entity_meta:
                eid = self._entity(
                    entity_meta.get("id"), entity_meta.get("username"),
                    entity_meta.get("title") or entity_meta.get("first_name"),
                    "user" if entity_meta.get("first_name") is not None else "channel_or_group",
                    ev.collected_at, entity_meta)
                self._identifier(eid, "telegram_username", entity_meta.get("username"), ev.collected_at)

            if ev.source_type == "telegram_public_message":
                parts = ev.source_url.rstrip("/").split("/")
                target_username = parts[-2] if len(parts) >= 2 else None
                row = self.db.execute("SELECT id FROM chats WHERE lower(username)=lower(?)",
                                      (target_username,)).fetchone() if target_username else None
                chat_id = row["id"] if row else self._chat(None, target_username, target_username, "public",
                                                            ev.collected_at, {})
                m = meta
                self.db.execute(
                    """INSERT INTO messages(chat_id,telegram_message_id,observed_at,message_date,text,source_url,
                    views,forwards,sha256,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(chat_id,telegram_message_id) DO UPDATE SET observed_at=excluded.observed_at,
                    text=excluded.text, views=excluded.views, forwards=excluded.forwards, sha256=excluded.sha256,
                    metadata_json=excluded.metadata_json""",
                    (chat_id, int(m.get("message_id", 0)), ev.collected_at, m.get("date"), ev.text, ev.source_url,
                     m.get("views"), m.get("forwards"), ev.sha256, json.dumps(m, sort_keys=True)))
                if eid:
                    self.db.execute(
                        """INSERT OR IGNORE INTO observations(entity_id,chat_id,observed_at,observation_type,
                        source_url,evidence_sha256,metadata_json) VALUES(?,?,?,?,?,?,?)""",
                        (eid, chat_id, ev.collected_at, "public_message", ev.source_url, ev.sha256,
                         json.dumps(m, sort_keys=True)))
            elif eid:
                self.db.execute(
                    """INSERT OR IGNORE INTO observations(entity_id,observed_at,observation_type,
                    source_url,evidence_sha256,metadata_json) VALUES(?,?,?,?,?,?)""",
                    (eid, ev.collected_at, ev.source_type, ev.source_url, ev.sha256, json.dumps(meta, sort_keys=True)))
            count += 1
        self.db.commit()
        return count

    def search(self, query: str, limit: int = 50) -> list[dict]:
        q = f"%{query.lower()}%"
        rows = self.db.execute(
            """SELECT id,username,display_name,entity_type,first_observed,last_observed
            FROM entities WHERE lower(COALESCE(username,'')) LIKE ? OR lower(COALESCE(display_name,'')) LIKE ?
            ORDER BY last_observed DESC LIMIT ?""", (q, q, limit)).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        self.db.close()
