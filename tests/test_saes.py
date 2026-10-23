import unittest
from saes import (encrypt_block, decrypt_block, expand_key, double_encrypt,
                  double_decrypt, triple_encrypt, triple_decrypt, mitm_attack,
                  encrypt_ascii, decrypt_ascii, cbc_encrypt, cbc_decrypt)


class SAESTests(unittest.TestCase):
    def test_textbook_vector_and_key_schedule(self):
        self.assertEqual(expand_key(0x2D55), (0x2D55, 0xBCE9, 0xA34A))
        self.assertEqual(encrypt_block(0xD728, 0x4AF5), 0x24EC)
        self.assertEqual(decrypt_block(0x24EC, 0x4AF5), 0xD728)

    def test_block_roundtrips(self):
        for key in (0, 0x4AF5, 0xFFFF):
            for block in range(0, 65536, 257):
                self.assertEqual(decrypt_block(encrypt_block(block, key), key), block)

    def test_multiple_encryption(self):
        self.assertEqual(double_decrypt(double_encrypt(0xD728, 0x4AF52D55), 0x4AF52D55), 0xD728)
        self.assertEqual(triple_decrypt(triple_encrypt(0xD728, 0x4AF52D551234), 0x4AF52D551234), 0xD728)

    def test_ascii_padding(self):
        for text in ("", "A", "HELLO", "ABCDEF", "A\x00"):
            self.assertEqual(decrypt_ascii(encrypt_ascii(text, 0x4AF5), 0x4AF5), text)
        with self.assertRaises(UnicodeEncodeError):
            encrypt_ascii("汉字", 0x4AF5)

    def test_cbc_and_tamper(self):
        plaintext = b"ABCDEF"
        iv, ciphertext = cbc_encrypt(plaintext, 0x4AF5, 0x1234)
        self.assertEqual(cbc_decrypt(ciphertext, 0x4AF5, iv), plaintext)
        changed = bytearray(ciphertext)
        changed[0] ^= 1
        tampered = cbc_decrypt(bytes(changed), 0x4AF5, iv)
        self.assertNotEqual(tampered, plaintext)
        self.assertEqual(tampered[2], plaintext[2] ^ 1)

    def test_mitm_true_key_is_candidate(self):
        key = 0x4AF52D55
        pairs = [(plain, double_encrypt(plain, key)) for plain in (0xD728, 0x1234, 0xABCD)]
        self.assertIn(key, mitm_attack(pairs))


if __name__ == "__main__":
    unittest.main()
