import unittest
from tg_osint.core import normalize_target, extract_iocs

class CoreTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_target('@telegram')['username'], 'telegram')
        self.assertEqual(normalize_target('https://t.me/telegram')['handle'], '@telegram')
    def test_iocs(self):
        x = extract_iocs('Visit https://example.com and email a@example.com. Contact @sample_user and 8.8.8.8')
        self.assertIn('https://example.com', x['urls'])
        self.assertIn('a@example.com', x['emails'])
        self.assertIn('@sample_user', x['usernames'])
        self.assertIn('8.8.8.8', x['ipv4'])

if __name__ == '__main__':
    unittest.main()