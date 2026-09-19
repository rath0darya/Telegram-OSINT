import tempfile
import unittest

from tg_osint.core import Evidence, sha256_text
from tg_osint.intel_db import IntelligenceDB


class IntelligenceDBTests(unittest.TestCase):
    def test_username_history_stays_on_same_telegram_id(self):
        with tempfile.TemporaryDirectory() as d:
            db = IntelligenceDB(f"{d}/intel.db")
            for username, ts in (("old_name", "2026-09-18T00:00:00+00:00"), ("new_name", "2026-09-19T00:00:00+00:00")):
                ev = Evidence("telegram_api_public_entity", f"https://t.me/{username}", ts, username, username, sha256_text(username + ts), {"entity": {"id": 123, "username": username, "first_name": "Test"}})
                db.ingest([ev])
            rows = db.search("123")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["telegram_id"], 123)
            history = db.entity_history(123)
            self.assertEqual([x["value"] for x in history["identifiers"] if x["identifier_type"] == "telegram_username"], ["old_name", "new_name"])
            self.assertEqual(len(history["profiles"]), 2)
            db.close()

    def test_message_author_and_mention_relationship(self):
        with tempfile.TemporaryDirectory() as d:
            db = IntelligenceDB(f"{d}/intel.db")
            ev = Evidence("telegram_public_message", "https://t.me/example/42", "2026-09-19T00:00:00+00:00", "Public message 42", "hello @target", sha256_text("message"), {
                "message_id": 42,
                "date": "2026-09-19T00:00:00+00:00",
                "chat": {"id": 900, "username": "example", "title": "Example", "type": "channel"},
                "author": {"id": 111, "username": "author", "first_name": "Author"},
                "mentions": [{"id": 222, "username": "target", "first_name": "Target"}],
            })
            db.ingest([ev])
            history = db.entity_history(111)
            self.assertEqual(len(history["messages"]), 1)
            self.assertEqual(history["messages"][0]["telegram_message_id"], 42)
            self.assertTrue(any(x["edge_type"] == "mentioned" for x in history["relationships"]))
            db.close()

    def test_legacy_edges_schema_is_migrated(self):
        with tempfile.TemporaryDirectory() as d:
            import sqlite3
            path = f"{d}/intel.db"
            conn = sqlite3.connect(path)
            conn.execute("""CREATE TABLE edges (
                id INTEGER PRIMARY KEY,
                source_entity_id INTEGER,
                target_entity_id INTEGER,
                source_chat_id INTEGER,
                edge_type TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                source_url TEXT,
                evidence_sha256 TEXT NOT NULL
            )""")
            conn.commit()
            conn.close()
            db = IntelligenceDB(path)
            cols = {r["name"] for r in db.db.execute("PRAGMA table_info(edges)")}
            self.assertIn("message_id", cols)
            self.assertIn("metadata_json", cols)
            db.close()

    def test_reaction_metadata_is_persisted(self):
        with tempfile.TemporaryDirectory() as d:
            db = IntelligenceDB(f"{d}/intel.db")
            ev = Evidence("telegram_public_message", "https://t.me/example/43", "2026-09-19T00:00:00+00:00", "Public message 43", "hello", sha256_text("reaction-message"), {
                "message_id": 43,
                "date": "2026-09-19T00:00:00+00:00",
                "chat": {"id": 900, "username": "example", "title": "Example", "type": "channel"},
                "author": {"id": 111, "username": "author", "first_name": "Author"},
                "reaction_summary": [{"reaction": "👍", "count": 7}],
            })
            db.ingest([ev])
            history = db.entity_history(111)
            self.assertEqual(len(history["reactions"]), 1)
            self.assertEqual(history["reactions"][0]["count"], 7)
            db.close()


if __name__ == "__main__":
    unittest.main()
