import unittest

from tg_osint.public_group import _message_url, _public_chat_type


class FakeChannel:
    username = "examplegroup"
    id = 123
    broadcast = False
    megagroup = True


class FakeBroadcast:
    username = "examplechannel"
    id = 456
    broadcast = True


class FakeChat:
    username = "smallgroup"
    id = 789


class PublicGroupTests(unittest.TestCase):
    def test_supergroup_type(self):
        self.assertEqual(_public_chat_type(FakeChannel()), "supergroup")

    def test_channel_type(self):
        self.assertEqual(_public_chat_type(FakeBroadcast()), "channel")

    def test_group_type(self):
        self.assertEqual(_public_chat_type(FakeChat()), "group")

    def test_public_message_url(self):
        self.assertEqual(_message_url(FakeChannel(), 42), "https://t.me/examplegroup/42")


if __name__ == "__main__":
    unittest.main()
