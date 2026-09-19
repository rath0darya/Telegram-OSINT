import tempfile
import unittest

from tg_osint.core import Evidence, sha256_text
from tg_osint.intel_db import IntelligenceDB

class IntelligenceDBTests(unittest.TestCase):
    def test_historical_ingest_and_search(self):
        with tempfile.TemporaryDirectory() as d:
            db = IntelligenceDB(f"{d}/intel.db")
            ev = Evidence("telegram_api_public_entity", "https://t.me/example",
                "2026-09-19T00:00:00+00:00", "Example", "entity", sha256_text("entity"),
                {"entity": {"id": 123, "username": "example", "title": "Example"}})
            db.ingest([ev])
            rows = db.search("example")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["username"], "example")
            db.close()

if __name__ == "__main__":
    unittest.main()
