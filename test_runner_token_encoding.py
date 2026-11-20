import unittest

from security_gateway.trust import is_trusted_runner


class RunnerTokenEncodingTests(unittest.TestCase):
    def test_only_matching_ascii_tokens_are_trusted(self):
        for received, configured, trusted in (
            ("sample", "sample", True),
            ("other", "sample", False),
            ("café", "sample", False),
            ("sample", "café", False),
            ("café", "café", False),
        ):
            with self.subTest(received=received, configured=configured):
                self.assertEqual(is_trusted_runner(received, configured), trusted)
