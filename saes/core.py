"""Stallings Appendix D simplified AES. All block and key values are 16-bit integers."""

SBOX = (0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7)
INV_SBOX = tuple(SBOX.index(value) for value in range(16))


def _check_word(value: int) -> None:
    if not isinstance(value, int) or not 0 <= value <= 0xFFFF:
        raise ValueError("数据和单个密钥必须是 0..65535 的整数")


def gf_multiply(left: int, right: int) -> int:
    """GF(2^4), reduction polynomial x^4+x+1 (0b10011)."""
    result = 0
    for _ in range(4):
        if right & 1:
            result ^= left
        left <<= 1
        if left & 0x10:
            left ^= 0x13
        right >>= 1
    return result & 0xF


def _sub_byte(value: int) -> int:
    return (SBOX[value >> 4] << 4) | SBOX[value & 0xF]


def expand_key(key: int) -> tuple[int, int, int]:
    _check_word(key)
    words = [key >> 8, key & 0xFF]
    for constant in (0x80, 0x30):
        rotated = ((words[-1] << 4) | (words[-1] >> 4)) & 0xFF
        first = words[-2] ^ constant ^ _sub_byte(rotated)
        second = first ^ words[-1]
        words.extend((first, second))
    return tuple((words[index] << 8) | words[index + 1] for index in (0, 2, 4))


def _sub_nibbles(state: int, box: tuple[int, ...]) -> int:
    return sum(box[(state >> shift) & 0xF] << shift for shift in (0, 4, 8, 12))


def _shift_rows(state: int) -> int:
    # Column-major nibbles: [n0,n1] is the first column.
    return (state & 0xF0F0) | ((state & 0xF) << 8) | ((state >> 8) & 0xF)


def _mix_columns(state: int, inverse: bool = False) -> int:
    high, low, other_high, other_low = ((state >> shift) & 0xF for shift in (12, 8, 4, 0))
    diagonal, off_diagonal = (9, 2) if inverse else (1, 4)
    return ((gf_multiply(diagonal, high) ^ gf_multiply(off_diagonal, low)) << 12
            | (gf_multiply(off_diagonal, high) ^ gf_multiply(diagonal, low)) << 8
            | (gf_multiply(diagonal, other_high) ^ gf_multiply(off_diagonal, other_low)) << 4
            | gf_multiply(off_diagonal, other_high) ^ gf_multiply(diagonal, other_low))


def encrypt_block(plaintext: int, key: int) -> int:
    _check_word(plaintext)
    round_zero, round_one, round_two = expand_key(key)
    state = plaintext ^ round_zero
    state = _mix_columns(_shift_rows(_sub_nibbles(state, SBOX))) ^ round_one
    return _shift_rows(_sub_nibbles(state, SBOX)) ^ round_two


def trace_encrypt(plaintext: int, key: int) -> dict[str, int]:
    """Return each encryption stage for component-level interoperability checks."""
    _check_word(plaintext)
    round_zero, round_one, round_two = expand_key(key)
    trace = {"K0": round_zero, "K1": round_one, "K2": round_two}
    state = plaintext ^ round_zero
    trace["AddKey0"] = state
    state = _sub_nibbles(state, SBOX)
    trace["SubNib1"] = state
    state = _shift_rows(state)
    trace["ShiftRow1"] = state
    state = _mix_columns(state)
    trace["MixColumn1"] = state
    state ^= round_one
    trace["AddKey1"] = state
    state = _sub_nibbles(state, SBOX)
    trace["SubNib2"] = state
    state = _shift_rows(state)
    trace["ShiftRow2"] = state
    trace["Ciphertext"] = state ^ round_two
    return trace


def decrypt_block(ciphertext: int, key: int) -> int:
    _check_word(ciphertext)
    round_zero, round_one, round_two = expand_key(key)
    state = ciphertext ^ round_two
    state = _sub_nibbles(_shift_rows(state), INV_SBOX) ^ round_one
    state = _sub_nibbles(_shift_rows(_mix_columns(state, inverse=True)), INV_SBOX)
    return state ^ round_zero
