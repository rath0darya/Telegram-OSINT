import unittest

from tg_osint.telegram_api import _message_author_matches_target, _target_input_peer


class FakeInputPeerUser:
    def __init__(self, user_id, access_hash):
        self.user_id = user_id
        self.access_hash = access_hash


class FakeTypes:
    InputPeerUser = FakeInputPeerUser


class Entity:
    id = 7030758596
    access_hash = 99887766


class NoHashEntity:
    id = 7030758596
    access_hash = None
    input_entity = None


class Message:
    def __init__(self, sender_id):
        self.sender_id = sender_id


class TelegramApiTests(unittest.TestCase):
    def test_target_input_peer_uses_resolved_access_hash(self):
        peer = _target_input_peer(Entity(), 7030758596, FakeTypes)
        self.assertEqual(peer.user_id, 7030758596)
        self.assertEqual(peer.access_hash, 99887766)

    def test_target_input_peer_rejects_missing_access_hash(self):
        with self.assertRaisesRegex(RuntimeError, "usable user access_hash"):
            _target_input_peer(NoHashEntity(), 7030758596, FakeTypes)

    def test_authorship_requires_exact_numeric_id(self):
        self.assertTrue(
            _message_author_matches_target(Message(7030758596), 7030758596)
        )
        self.assertFalse(
            _message_author_matches_target(Message(123456789), 7030758596)
        )
        self.assertFalse(
            _message_author_matches_target(Message(None), 7030758596)
        )


if __name__ == "__main__":
    unittest.main()
