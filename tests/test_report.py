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


if __name__ == "__main__":
    unittest.main()
