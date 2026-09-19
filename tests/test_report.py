import tempfile
import unittest
from pathlib import Path

from tg_osint.report import build_report, write_html


class ReportTests(unittest.TestCase):
    def test_report_is_self_contained(self):
        from tg_osint.core import Evidence
        evidence = [Evidence(
            "telegram_api_public_entity",
            "telegram://id/123",
            "2026-09-19T00:00:00+00:00",
            "Target",
            "entity",
            "sha",
            {"entity": {"id": 123, "username": "target"}},
        )]
        report = build_report(
            {"handle": "@target", "username": "target", "target_type": "username", "url": "https://t.me/target"},
            1, evidence, [], analysis={},
        )
        self.assertNotIn("manual_relationships", report)
        self.assertEqual(report["evidence"], [{
            "source_type": "telegram_api_public_entity",
            "source_url": "telegram://id/123",
            "collected_at": "2026-09-19T00:00:00+00:00",
            "title": "Target",
            "text": "entity",
            "sha256": "sha",
            "metadata": {"entity": {"id": 123, "username": "target"}},
        }])

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
            self.assertNotIn("Manual relationship references", text)
            self.assertNotIn("external reference data", text)


if __name__ == "__main__":
    unittest.main()
