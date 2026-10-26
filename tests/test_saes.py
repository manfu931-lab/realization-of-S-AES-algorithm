import unittest
from saes import (encrypt_block, decrypt_block, expand_key, trace_encrypt, double_encrypt,
                  double_decrypt, triple_encrypt, triple_decrypt, mitm_attack,
                  encrypt_ascii, decrypt_ascii, cbc_encrypt, cbc_decrypt)
from saes.core import SBOX, INV_SBOX, gf_multiply, _shift_rows, _mix_columns


class SAESTests(unittest.TestCase):
    def test_appendix_parameters_and_reference_vector(self):
        self.assertEqual(expand_key(0x2D55), (0x2D55, 0xBCE9, 0xA34A))
        self.assertEqual(encrypt_block(0xD728, 0x4AF5), 0x24EC)
        self.assertEqual(decrypt_block(0x24EC, 0x4AF5), 0xD728)

    def test_component_trace(self):
        expected = {
            "K0": 0x2D55, "K1": 0xBCE9, "K2": 0xA34A,
            "AddKey0": 0x3F61, "SubNib1": 0xB784,
            "ShiftRow1": 0xB487, "MixColumn1": 0x8E71,
            "AddKey1": 0x3298, "SubNib2": 0xBA26,
            "ShiftRow2": 0xB62A, "Ciphertext": 0x1560,
        }
        self.assertEqual(trace_encrypt(0x1234, 0x2D55), expected)
        self.assertEqual(decrypt_block(expected["Ciphertext"], 0x2D55), 0x1234)

    def test_appendix_component_examples(self):
        self.assertEqual(SBOX[0xA], 0)
        self.assertEqual(INV_SBOX[0], 0xA)
        self.assertEqual(gf_multiply(4, 0xC), 5)
        self.assertEqual(_shift_rows(0xB784), 0xB487)
        self.assertEqual(_mix_columns(0x6C40), 0x3743)
        self.assertEqual(_mix_columns(0x3743, inverse=True), 0x6C40)

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
