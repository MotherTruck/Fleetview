import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from app.security import password_hash, secure_equal, token_hash, verify_password


class AuthTests(unittest.TestCase):
    def test_hash_is_repeatable_and_not_plaintext(self):
        token = "a-secret-token"
        self.assertEqual(token_hash(token), token_hash(token))
        self.assertNotEqual(token_hash(token), token)
        self.assertEqual(len(token_hash(token)), 64)

    def test_secure_comparison(self):
        self.assertTrue(secure_equal("same", "same"))
        self.assertFalse(secure_equal("same", "different"))

    def test_uninstall_code_hash(self):
        encoded = password_hash("4829")
        self.assertTrue(verify_password("4829", encoded))
        self.assertFalse(verify_password("wrong", encoded))
        self.assertNotIn("4829", encoded)


if __name__ == "__main__":
    unittest.main()
