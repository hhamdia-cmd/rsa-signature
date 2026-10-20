"""Behavior checks for valid signatures, forgery attempts, and replay."""

import unittest

from rsa_signature import generate_private_key, sign_message, verify_signature


class SignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = generate_private_key()
        cls.public_key = cls.private_key.public_key()
        cls.message = b"Transfer $1000 to Mark"
        cls.signature = sign_message(cls.private_key, cls.message)

    def test_original_message_is_accepted(self):
        self.assertTrue(verify_signature(self.public_key, self.message, self.signature))

    def test_changed_recipient_is_rejected(self):
        self.assertFalse(verify_signature(
            self.public_key, b"Transfer $1000 to Oscar", self.signature
        ))

    def test_changed_signature_is_rejected(self):
        changed = self.signature[:-1] + bytes([self.signature[-1] ^ 1])
        self.assertFalse(verify_signature(self.public_key, self.message, changed))

    def test_other_signer_is_rejected(self):
        other_key = generate_private_key().public_key()
        self.assertFalse(verify_signature(other_key, self.message, self.signature))

    def test_missing_signature_is_rejected(self):
        self.assertFalse(verify_signature(self.public_key, self.message, b""))

    def test_unicode_message_is_supported(self):
        message = "Software Security - أمن البرمجيات".encode("utf-8")
        signature = sign_message(self.private_key, message)
        self.assertTrue(verify_signature(self.public_key, message, signature))

    def test_replay_still_verifies_without_freshness_state(self):
        for _ in range(3):
            self.assertTrue(verify_signature(self.public_key, self.message, self.signature))


if __name__ == "__main__":
    unittest.main(verbosity=2)
