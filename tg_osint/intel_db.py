from __future__ import annotations

import json
from .mysql import connect
from pathlib import Path
from typing import Iterable

from .core import Evidence, now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, target TEXT, evidence_count INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS entities (id INTEGER PRIMARY KEY, telegram_id INTEGER UNIQUE, username TEXT, display_name TEXT, entity_type TEXT NOT NULL DEFAULT 'unknown', first_observed TEXT NOT NULL, last_observed TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS identifiers (id INTEGER PRIMARY KEY, entity_id INTEGER NOT NULL, identifier_type TEXT NOT NULL, value TEXT NOT NULL, first_observed TEXT NOT NULL, last_observed TEXT NOT NULL, observation_count INTEGER NOT NULL DEFAULT 1, UNIQUE(entity_id, identifier_type, value));
CREATE TABLE IF NOT EXISTS profile_snapshots (id INTEGER PRIMARY KEY, entity_id INTEGER NOT NULL, observed_at TEXT NOT NULL, username TEXT, first_name TEXT, last_name TEXT, display_name TEXT, title TEXT, about TEXT, verified INTEGER, scam INTEGER, fake INTEGER, source_url TEXT, evidence_sha256 TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}', UNIQUE(entity_id, observed_at, evidence_sha256));
CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY, telegram_id INTEGER UNIQUE, username TEXT, title TEXT, chat_type TEXT NOT NULL DEFAULT 'unknown', first_observed TEXT NOT NULL, last_observed TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, chat_id INTEGER NOT NULL, telegram_message_id INTEGER NOT NULL, author_entity_id INTEGER, observed_at TEXT NOT NULL, message_date TEXT, text TEXT NOT NULL, source_url TEXT, views INTEGER, forwards INTEGER, reply_to_message_id INTEGER, forward_from_entity_id INTEGER, sha256 TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}', UNIQUE(chat_id, telegram_message_id));
CREATE TABLE IF NOT EXISTS reactions (id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL, reaction TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, observed_at TEXT NOT NULL, source_url TEXT, evidence_sha256 TEXT NOT NULL, UNIQUE(message_id,reaction,evidence_sha256));
CREATE TABLE IF NOT EXISTS memberships (id INTEGER PRIMARY KEY, entity_id INTEGER NOT NULL, chat_id INTEGER NOT NULL, status TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', observed_at TEXT NOT NULL, first_observed TEXT NOT NULL, last_observed TEXT NOT NULL, source_url TEXT, evidence_sha256 TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}', UNIQUE(entity_id, chat_id, status, role, observed_at, evidence_sha256));
CREATE TABLE IF NOT EXISTS observations (id INTEGER PRIMARY KEY, entity_id INTEGER, chat_id INTEGER, observed_at TEXT NOT NULL, observation_type TEXT NOT NULL, source_url TEXT, evidence_sha256 TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS edges (id INTEGER PRIMARY KEY, source_entity_id INTEGER, target_entity_id INTEGER, source_chat_id INTEGER, message_id INTEGER, edge_type TEXT NOT NULL, observed_at TEXT NOT NULL, source_url TEXT, evidence_sha256 TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}', UNIQUE(source_entity_id, target_entity_id, source_chat_id, message_id, edge_type, evidence_sha256));
CREATE INDEX IF NOT EXISTS idx_entities_username ON entities(username);
CREATE INDEX IF NOT EXISTS idx_identifiers_value ON identifiers(value);
CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(message_date);

CREATE INDEX IF NOT EXISTS idx_observations_time ON observations(observed_at);
CREATE INDEX IF NOT EXISTS idx_memberships_entity ON memberships(entity_id);
CREATE INDEX IF NOT EXISTS idx_memberships_chat ON memberships(chat_id);
CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_entity_id);
"""

class IntelligenceDB:
    """Persistent store for public observations collected by this project."""

    def __init__(self, path: str = "cases/intelligence.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        # The filename argument is retained for CLI compatibility; persistence
        # is now MariaDB and is configured with TELEGRAM_OSINT_DB_* environment variables.
        self.db = connect()
        with self.db.cursor() as cur:
            for statement in SCHEMA.split(";"):
                statement = statement.strip()
                if statement:
                    statement = statement.replace("INTEGER PRIMARY KEY", "BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY")
                    statement = statement.replace("INSERT OR IGNORE", "INSERT IGNORE")
                    cur.execute(statement)
        self._migrate()
        self.db.commit()

    def _ensure_column(self, table: str, column: str, ddl: str):
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT COLUMN_NAME AS name FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s",
                (table,),
            )
            cols = {r["name"] for r in cur.fetchall()}
            if column not in cols:
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    def _migrate(self):
        with self.db.cursor() as cur:
            cur.execute(
                "SELECT COLUMN_NAME AS name FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='messages'"
            )
            cols = {r["name"] for r in cur.fetchall()}
            for name, ddl in {
                "author_entity_id": "ALTER TABLE messages ADD COLUMN author_entity_id BIGINT",
                "reply_to_message_id": "ALTER TABLE messages ADD COLUMN reply_to_message_id BIGINT",
                "forward_from_entity_id": "ALTER TABLE messages ADD COLUMN forward_from_entity_id BIGINT",
            }.items():
                if name not in cols:
                    cur.execute(ddl)

    def _entity(self, telegram_id, username, display_name, entity_type, observed_at, metadata):
        # Numeric Telegram ID is the authoritative identity key. Never merge
        # two numeric IDs because a username happens to be equal/reused.
        row = self.db.execute("SELECT id FROM entities WHERE telegram_id=?", (int(telegram_id),)).fetchone() if telegram_id is not None else None
        if row is None and telegram_id is None and username:
            row = self.db.execute("SELECT id FROM entities WHERE lower(username)=lower(?) AND telegram_id IS NULL", (username,)).fetchone()
        if row:
            eid = row["id"]
            self.db.execute("UPDATE entities SET telegram_id=COALESCE(?,telegram_id), username=COALESCE(?,username), display_name=COALESCE(?,display_name), entity_type=?, last_observed=?, metadata_json=? WHERE id=?", (telegram_id, username, display_name, entity_type, observed_at, json.dumps(metadata, sort_keys=True), eid))
        else:
            cur = self.db.execute("INSERT INTO entities(telegram_id,username,display_name,entity_type,first_observed,last_observed,metadata_json) VALUES(?,?,?,?,?,?,?)", (telegram_id, username, display_name, entity_type, observed_at, observed_at, json.dumps(metadata, sort_keys=True)))
            eid = cur.lastrowid
        self._identifier(eid, "telegram_username", username, observed_at)
        return eid

    def _chat(self, telegram_id, username, title, chat_type, observed_at, metadata):
        # Chat/channel numeric ID is authoritative too; a reused username
        # must never merge two different chats.
        row = self.db.execute("SELECT id FROM chats WHERE telegram_id=?", (int(telegram_id),)).fetchone() if telegram_id is not None else None
        if row is None and telegram_id is None and username:
            row = self.db.execute("SELECT id FROM chats WHERE lower(username)=lower(?) AND telegram_id IS NULL", (username,)).fetchone()
        if row:
            cid = row["id"]
            self.db.execute("UPDATE chats SET username=COALESCE(?,username), title=COALESCE(?,title), chat_type=?, last_observed=?, metadata_json=? WHERE id=?", (username, title, chat_type, observed_at, json.dumps(metadata, sort_keys=True), cid))
            return cid
        cur = self.db.execute("INSERT INTO chats(telegram_id,username,title,chat_type,first_observed,last_observed,metadata_json) VALUES(?,?,?,?,?,?,?)", (telegram_id, username, title, chat_type, observed_at, observed_at, json.dumps(metadata, sort_keys=True)))
        return cur.lastrowid

    def _identifier(self, entity_id, kind, value, observed_at):
        if entity_id is None or not value:
            return
        self.db.execute("INSERT INTO identifiers(entity_id,identifier_type,value,first_observed,last_observed,observation_count) VALUES(?,?,?,?,?,1) ON DUPLICATE KEY UPDATE last_observed=VALUES(last_observed), observation_count=identifiers.observation_count+1", (entity_id, kind, value, observed_at, observed_at))

    def _snapshot(self, eid, data, observed_at, source_url, evidence_sha):
        display_name = data.get("display_name") or " ".join(x for x in (data.get("first_name"), data.get("last_name")) if x) or data.get("title")
        self.db.execute("INSERT IGNORE INTO profile_snapshots(entity_id,observed_at,username,first_name,last_name,display_name,title,about,verified,scam,fake,source_url,evidence_sha256,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (eid, observed_at, data.get("username"), data.get("first_name"), data.get("last_name"), display_name, data.get("title"), data.get("about"), data.get("verified"), data.get("scam"), data.get("fake"), source_url, evidence_sha, json.dumps(data, sort_keys=True)))
        self._identifier(eid, "telegram_username", data.get("username"), observed_at)
        self._identifier(eid, "display_name", display_name, observed_at)

    def _edge(self, source, target, chat_id, message_id, edge_type, ev):
        if source is None or target is None:
            return
        self.db.execute("INSERT IGNORE INTO edges(source_entity_id,target_entity_id,source_chat_id,message_id,edge_type,observed_at,source_url,evidence_sha256,metadata_json) VALUES(?,?,?,?,?,?,?,?,?)", (source, target, chat_id, message_id, edge_type, ev.collected_at, ev.source_url, ev.sha256, json.dumps(ev.metadata or {}, sort_keys=True)))

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
                entity_type = entity_meta.get("entity_type") or ("user" if entity_meta.get("first_name") is not None else "channel_or_group")
                eid = self._entity(entity_meta.get("id"), entity_meta.get("username"), entity_meta.get("display_name") or entity_meta.get("title") or entity_meta.get("first_name"), entity_type, ev.collected_at, entity_meta)
                self._snapshot(eid, entity_meta, ev.collected_at, ev.source_url, ev.sha256)
                self.db.execute("INSERT IGNORE INTO observations(entity_id,observed_at,observation_type,source_url,evidence_sha256,metadata_json) VALUES(?,?,?,?,?,?)", (eid, ev.collected_at, ev.source_type, ev.source_url, ev.sha256, json.dumps(meta, sort_keys=True)))

            if ev.source_type == "telegram_public_message":
                m = meta
                chat_meta = m.get("chat") if isinstance(m.get("chat"), dict) else {}
                chat = self._chat(chat_meta.get("id"), chat_meta.get("username"), chat_meta.get("title"), chat_meta.get("type") or "public", ev.collected_at, chat_meta)
                author_meta = m.get("author") if isinstance(m.get("author"), dict) else {}
                author_id = None
                if author_meta:
                    author_id = self._entity(author_meta.get("id"), author_meta.get("username"), author_meta.get("display_name") or author_meta.get("title"), author_meta.get("entity_type") or "user", ev.collected_at, author_meta)
                    self._snapshot(author_id, author_meta, ev.collected_at, ev.source_url, ev.sha256)
                forward_meta = m.get("forward_from") if isinstance(m.get("forward_from"), dict) else {}
                forward_id = None
                if forward_meta:
                    forward_id = self._entity(forward_meta.get("id"), forward_meta.get("username"), forward_meta.get("display_name"), "user", ev.collected_at, forward_meta)
                msg_id = int(m.get("message_id", 0))
                self.db.execute("INSERT INTO messages(chat_id,telegram_message_id,author_entity_id,observed_at,message_date,text,source_url,views,forwards,reply_to_message_id,forward_from_entity_id,sha256,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE author_entity_id=VALUES(author_entity_id), observed_at=VALUES(observed_at), message_date=VALUES(message_date), text=VALUES(text), source_url=VALUES(source_url), views=VALUES(views), forwards=VALUES(forwards), reply_to_message_id=VALUES(reply_to_message_id), forward_from_entity_id=VALUES(forward_from_entity_id), sha256=VALUES(sha256), metadata_json=VALUES(metadata_json)", (chat, msg_id, author_id, ev.collected_at, m.get("date"), ev.text, ev.source_url, m.get("views"), m.get("forwards"), m.get("reply_to_message_id"), forward_id, ev.sha256, json.dumps(m, sort_keys=True)))
                stored_message = self.db.execute("SELECT id FROM messages WHERE chat_id=? AND telegram_message_id=?", (chat, msg_id)).fetchone()
                if stored_message:
                    for reaction in m.get("reaction_summary", []):
                        if isinstance(reaction, dict):
                            self.db.execute("INSERT IGNORE INTO reactions(message_id,reaction,count,observed_at,source_url,evidence_sha256) VALUES(?,?,?,?,?,?)", (stored_message["id"], str(reaction.get("reaction") or "unknown"), int(reaction.get("count") or 0), ev.collected_at, ev.source_url, ev.sha256))
                self.db.execute("INSERT IGNORE INTO observations(entity_id,chat_id,observed_at,observation_type,source_url,evidence_sha256,metadata_json) VALUES(?,?,?,?,?,?,?)", (author_id or eid, chat, ev.collected_at, "public_message", ev.source_url, ev.sha256, json.dumps(m, sort_keys=True)))
                reply_meta = m.get("reply_to_author")
                if author_id and isinstance(reply_meta, dict):
                    reply_id = self._entity(reply_meta.get("id"), reply_meta.get("username"), reply_meta.get("display_name"), "user", ev.collected_at, reply_meta)
                    self._edge(author_id, reply_id, chat, msg_id, "replied_to", ev)
                if author_id and m.get("search_context") and m.get("resolved_target_id") is not None:
                    target_id = self._entity(m.get("resolved_target_id"), None, None, "user", ev.collected_at, {})
                    self._edge(author_id, target_id, chat, msg_id, "search_hit_for_target", ev)
                for mention in m.get("mentions", []):
                    mention_entity = mention if isinstance(mention, dict) else {"username": str(mention).lstrip("@")}
                    mid = self._entity(mention_entity.get("id"), mention_entity.get("username"), mention_entity.get("display_name"), "user", ev.collected_at, mention_entity)
                    self._edge(author_id, mid, chat, msg_id, "mentioned", ev)
                if forward_id and author_id:
                    self._edge(author_id, forward_id, chat, msg_id, "forwarded_from", ev)

            membership = meta.get("membership")
            if isinstance(membership, dict) and eid:
                cm = membership.get("chat") if isinstance(membership.get("chat"), dict) else {}
                cid = self._chat(cm.get("id"), cm.get("username"), cm.get("title"), cm.get("type") or "unknown", ev.collected_at, cm)
                self.db.execute("INSERT IGNORE INTO memberships(entity_id,chat_id,status,role,observed_at,first_observed,last_observed,source_url,evidence_sha256,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (eid, cid, membership.get("status","unknown"), membership.get("role","member"), ev.collected_at, ev.collected_at, ev.collected_at, ev.source_url, ev.sha256, json.dumps(membership, sort_keys=True)))
            count += 1
        self.db.commit()
        return count

    def resolve_identifier(self, identifier_type: str, value: str) -> int | None:
        """Resolve a previously observed identifier to its stable Telegram ID."""
        row = self.db.execute(
            "SELECT e.telegram_id FROM identifiers i JOIN entities e ON e.id=i.entity_id "
            "WHERE i.identifier_type=? AND lower(i.value)=lower(?) ORDER BY e.last_observed DESC LIMIT 1",
            (identifier_type, value),
        ).fetchone()
        return int(row["telegram_id"]) if row and row["telegram_id"] is not None else None

    def search(self, query: str, limit: int = 50) -> list[dict]:
        q = f"%{query.lower()}%"
        rows = self.db.execute("SELECT id,telegram_id,username,display_name,entity_type,first_observed,last_observed FROM entities WHERE lower(COALESCE(username,'')) LIKE ? OR lower(COALESCE(display_name,'')) LIKE ? OR CAST(telegram_id AS TEXT) LIKE ? ORDER BY last_observed DESC LIMIT ?", (q,q,q,limit)).fetchall()
        return [dict(r) for r in rows]

    def entity_history(self, telegram_id: int) -> dict:
        entity = self.db.execute("SELECT * FROM entities WHERE telegram_id=?", (telegram_id,)).fetchone()
        if not entity:
            return {}
        eid = entity["id"]
        return {
            "entity": dict(entity),
            "identifiers": [dict(r) for r in self.db.execute("SELECT * FROM identifiers WHERE entity_id=? ORDER BY first_observed", (eid,))],
            "profiles": [dict(r) for r in self.db.execute("SELECT * FROM profile_snapshots WHERE entity_id=? ORDER BY observed_at", (eid,))],
            "memberships": [dict(r) for r in self.db.execute("SELECT m.*,c.telegram_id AS chat_telegram_id,c.username AS chat_username,c.title AS chat_title,c.chat_type FROM memberships m JOIN chats c ON c.id=m.chat_id WHERE m.entity_id=? ORDER BY m.observed_at", (eid,))],
            "messages": [dict(r) for r in self.db.execute("SELECT m.*,c.telegram_id AS chat_telegram_id,c.username AS chat_username,c.title AS chat_title,c.chat_type FROM messages m JOIN chats c ON c.id=m.chat_id WHERE m.author_entity_id=? ORDER BY COALESCE(m.message_date,m.observed_at)", (eid,))],
            "reactions": [dict(r) for r in self.db.execute("SELECT r.*,m.telegram_message_id,c.telegram_id AS chat_telegram_id,c.username AS chat_username,c.title AS chat_title FROM reactions r JOIN messages m ON m.id=r.message_id JOIN chats c ON c.id=m.chat_id WHERE m.author_entity_id=? ORDER BY r.observed_at", (eid,))],
            "relationships": [dict(r) for r in self.db.execute("SELECT e.*,s.telegram_id AS source_telegram_id,t.telegram_id AS target_telegram_id,t.username AS target_username FROM edges e LEFT JOIN entities s ON s.id=e.source_entity_id LEFT JOIN entities t ON t.id=e.target_entity_id WHERE e.source_entity_id=? OR e.target_entity_id=? ORDER BY e.observed_at", (eid,eid))],
        }

    def close(self):
        self.db.close()
