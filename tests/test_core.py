import unittest

from tg_osint.core import Evidence, extract_iocs, normalize_target


class CoreTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_target("@telegram")["username"], "telegram")
        self.assertEqual(normalize_target("https://t.me/telegram")["handle"], "@telegram")
        self.assertEqual(normalize_target("123456789")["telegram_id"], 123456789)

    def test_iocs(self):
        x = extract_iocs("Visit https://example.com and email a@example.com. Contact @sample_user and 8.8.8.8")
        self.assertIn("https://example.com", x["urls"])
        self.assertIn("a@example.com", x["emails"])
        self.assertIn("@sample_user", x["usernames"])
        self.assertIn("8.8.8.8", x["ipv4"])


class AnalyzerTests(unittest.TestCase):
    def test_analysis(self):
        from tg_osint.analyzer import analyze_evidence
        e = Evidence("telegram_public_message", "https://t.me/x/1", "2026-01-01T00:00:00+00:00", "m", "hello #cti @sample_user https://example.com", "x", {"date": "2026-01-01T00:00:00+00:00", "views": 10, "forwards": 2})
        a = analyze_evidence([e])
        self.assertEqual(a["message_count"], 1)
        self.assertIn("@sample_user", a["mentions"])
        self.assertEqual(a["engagement"]["total_views"], 10)


if __name__ == "__main__":
    unittest.main()
