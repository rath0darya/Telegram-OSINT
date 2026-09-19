import tempfile
import unittest
from pathlib import Path

from tg_osint.report import build_report, write_html


class ReportTests(unittest.TestCase):
    def test_manual_relationships_are_report_only(self):
        manual = [{
            "observed": "01.09.2026",
            "relation": "reaction_given",
            "person": "Example",
            "telegram_id": 123,
            "username": "@example",
            "reaction": "❤",
            "source": "https://t.me/example/1",
        }]
        report = build_report(
            {"handle": "@target", "username": "target", "target_type": "username", "url": "https://t.me/target"},
            1,
            [],
            [],
            analysis={},
            manual_relationships=manual,
        )
        self.assertEqual(report["manual_relationships"], manual)
        self.assertEqual(report["history"], {})

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "report.html"
            write_html(report, path)
            text = path.read_text(encoding="utf-8")
            self.assertIn("Manual relationship references", text)
            self.assertIn("Example", text)
            self.assertIn("https://t.me/example/1", text)

    def test_evidence_mapping_uses_exact_author_id(self):
        from tg_osint.core import Evidence

        evidence = [
            Evidence(
                "telegram_api_public_entity",
                "telegram://id/7030758596",
                "2026-09-19T00:00:00+00:00",
                "Teacher Sara",
                "entity",
                "entitysha",
                {"entity": {"id": 7030758596, "username": "Teachersara0", "display_name": "Teacher Sara"}},
            ),
            Evidence(
                "telegram_public_message",
                "https://t.me/example/1",
                "2026-09-19T00:00:00+00:00",
                "Unrelated",
                "unrelated https://other.example",
                "msgsha",
                {"message_id": 1, "chat": {"id": -1}, "author": {"id": 2229980862}},
            ),
        ]
        report = build_report(
            {"handle": "@Teachersara0", "username": "Teachersara0", "target_type": "username", "url": "https://t.me/Teachersara0"},
            2,
            evidence,
            [],
            analysis={},
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "report.html"
            write_html(report, path)
            text = path.read_text(encoding="utf-8")
            self.assertIn("NO — context only; different/unknown author ID", text)
            self.assertNotIn("resolved_target_id", text)


if __name__ == "__main__":
    unittest.main()
