"""Multiple encryption, ASCII byte pairs, CBC, and meet-in-the-middle analysis."""
from collections import defaultdict
from secrets import randbits
from .core import encrypt_block, decrypt_block


def double_encrypt(block: int, key: int) -> int:
    if not 0 <= key <= 0xFFFFFFFF:
        raise ValueError("双重密钥必须为 32 位")
    return encrypt_block(encrypt_block(block, key >> 16), key & 0xFFFF)


def double_decrypt(block: int, key: int) -> int:
    return decrypt_block(decrypt_block(block, key & 0xFFFF), key >> 16)


def triple_encrypt(block: int, key: int) -> int:
    """48-bit EEE: K1 || K2 || K3."""
    if not 0 <= key <= 0xFFFFFFFFFFFF:
        raise ValueError("三重密钥必须为 48 位")
    return encrypt_block(encrypt_block(encrypt_block(block, key >> 32),
                                       (key >> 16) & 0xFFFF), key & 0xFFFF)


def triple_decrypt(block: int, key: int) -> int:
    return decrypt_block(decrypt_block(decrypt_block(block, key & 0xFFFF),
                                       (key >> 16) & 0xFFFF), key >> 32)


def mitm_attack(pairs: list[tuple[int, int]], limit: int | None = None) -> list[int]:
    """Return all K1||K2 candidates consistent with every known pair."""
    if not pairs:
        raise ValueError("至少提供一组明密文")
    forward = defaultdict(list)
    first_plaintext, first_ciphertext = pairs[0]
    for first_key in range(65536):
        forward[encrypt_block(first_plaintext, first_key)].append(first_key)
    candidates = []
    for second_key in range(65536):
        middle = decrypt_block(first_ciphertext, second_key)
        for first_key in forward.get(middle, ()):
            full_key = first_key << 16 | second_key
            if all(double_encrypt(plain, full_key) == cipher for plain, cipher in pairs[1:]):
                candidates.append(full_key)
                if limit is not None and len(candidates) >= limit:
                    return candidates
    return candidates


def encrypt_ascii(text: str, key: int) -> str:
    """2-byte ECB demonstration with reversible PKCS#7 padding."""
    data = text.encode("ascii")
    padding = 2 - len(data) % 2
    data += bytes([padding]) * padding
    return b"".join(encrypt_block(int.from_bytes(data[i:i+2], "big"), key).to_bytes(2, "big")
                    for i in range(0, len(data), 2)).hex().upper()


def decrypt_ascii(cipher_hex: str, key: int) -> str:
    data = bytes.fromhex(cipher_hex)
    if not data or len(data) % 2:
        raise ValueError("密文长度必须是完整的 16 位分组")
    plain = b"".join(decrypt_block(int.from_bytes(data[i:i+2], "big"), key).to_bytes(2, "big")
                     for i in range(0, len(data), 2))
    padding = plain[-1]
    if padding not in (1, 2) or plain[-padding:] != bytes([padding]) * padding:
        raise ValueError("填充校验失败")
    return plain[:-padding].decode("ascii")


def cbc_encrypt(data: bytes, key: int, iv: int | None = None) -> tuple[int, bytes]:
    """CBC with PKCS#7 padding for 2-byte blocks; random IV unless supplied."""
    if iv is None:
        iv = randbits(16)
    if not 0 <= iv <= 0xFFFF:
        raise ValueError("IV 必须是 16 位")
    padding = 2 - len(data) % 2
    data += bytes([padding]) * padding
    previous = iv
    output = bytearray()
    for index in range(0, len(data), 2):
        previous = encrypt_block(int.from_bytes(data[index:index+2], "big") ^ previous, key)
        output.extend(previous.to_bytes(2, "big"))
    return iv, bytes(output)


def cbc_decrypt(ciphertext: bytes, key: int, iv: int) -> bytes:
    if not 0 <= iv <= 0xFFFF or not ciphertext or len(ciphertext) % 2:
        raise ValueError("IV 或密文长度无效")
    previous = iv
    result = bytearray()
    for index in range(0, len(ciphertext), 2):
        current = int.from_bytes(ciphertext[index:index+2], "big")
        result.extend((decrypt_block(current, key) ^ previous).to_bytes(2, "big"))
        previous = current
    padding = result[-1]
    if padding not in (1, 2) or result[-padding:] != bytes([padding]) * padding:
        raise ValueError("填充校验失败；密钥、IV 或密文可能错误")
    return bytes(result[:-padding])
