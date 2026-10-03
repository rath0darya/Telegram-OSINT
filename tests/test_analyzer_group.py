import unittest

from tg_osint.analyzer import analyze_evidence
from tg_osint.core import Evidence, sha256_text


class GroupAnalyzerTests(unittest.TestCase):
    def test_group_messages_are_analysis_scope_not_target_authorship(self):
        ev = Evidence(
            "telegram_public_message",
            "https://t.me/example/1",
            "2026-10-03T00:00:00+00:00",
            "Group message",
            "hello https://example.com #test",
            sha256_text("group"),
            {
                "message_id": 1,
                "date": "2026-10-03T00:00:00+00:00",
                "public_group_context": True,
                "chat": {"id": -1001, "username": "example", "title": "Example", "type": "supergroup"},
                "author": {"id": 123, "username": "author"},
            },
        )
        result = analyze_evidence([ev], None)
        self.assertEqual(result["message_count"], 1)
        self.assertEqual(result["authored_message_count"], 0)
        self.assertEqual(result["iocs"]["urls"], ["https://example.com"])
        self.assertEqual(result["hashtags"][0]["value"], "test")


if __name__ == "__main__":
    unittest.main()
