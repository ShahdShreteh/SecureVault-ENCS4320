S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

INV_S_BOX = [0] * 256

for index, value in enumerate(S_BOX):
    INV_S_BOX[value] = index


RCON = (
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36,
)


AES_BLOCK_SIZE = 16
AES_256_KEY_SIZE = 32
AES_256_ROUNDS = 14


class AESError(ValueError):
    pass


def _gmul(
    a: int,
    b: int,
) -> int:

    result = 0

    for _ in range(8):

        if b & 1:
            result ^= a

        high_bit = a & 0x80

        a = (a << 1) & 0xFF

        if high_bit:
            a ^= 0x1B

        b >>= 1

    return result


def _add_round_key(
    state: list[int],
    round_key: list[int],
) -> list[int]:

    return [
        value ^ key_byte
        for value, key_byte in zip(
            state,
            round_key,
        )
    ]


def _sub_bytes(
    state: list[int],
) -> list[int]:

    return [
        S_BOX[value]
        for value in state
    ]


def _inv_sub_bytes(
    state: list[int],
) -> list[int]:

    return [
        INV_S_BOX[value]
        for value in state
    ]


def _shift_rows(
    state: list[int],
) -> list[int]:

    result = [0] * 16

    for row in range(4):

        for column in range(4):

            result[
                row + 4 * column
            ] = state[
                row
                + 4
                * ((column + row) % 4)
            ]

    return result


def _inv_shift_rows(
    state: list[int],
) -> list[int]:

    result = [0] * 16

    for row in range(4):

        for column in range(4):

            result[
                row + 4 * column
            ] = state[
                row
                + 4
                * ((column - row) % 4)
            ]

    return result


def _mix_columns(
    state: list[int],
) -> list[int]:

    result = [0] * 16

    for column in range(4):

        index = column * 4

        a0, a1, a2, a3 = (
            state[index:index + 4]
        )

        result[index] = (
            _gmul(a0, 2)
            ^ _gmul(a1, 3)
            ^ a2
            ^ a3
        )

        result[index + 1] = (
            a0
            ^ _gmul(a1, 2)
            ^ _gmul(a2, 3)
            ^ a3
        )

        result[index + 2] = (
            a0
            ^ a1
            ^ _gmul(a2, 2)
            ^ _gmul(a3, 3)
        )

        result[index + 3] = (
            _gmul(a0, 3)
            ^ a1
            ^ a2
            ^ _gmul(a3, 2)
        )

    return result


def _inv_mix_columns(
    state: list[int],
) -> list[int]:

    result = [0] * 16

    for column in range(4):

        index = column * 4

        a0, a1, a2, a3 = (
            state[index:index + 4]
        )

        result[index] = (
            _gmul(a0, 14)
            ^ _gmul(a1, 11)
            ^ _gmul(a2, 13)
            ^ _gmul(a3, 9)
        )

        result[index + 1] = (
            _gmul(a0, 9)
            ^ _gmul(a1, 14)
            ^ _gmul(a2, 11)
            ^ _gmul(a3, 13)
        )

        result[index + 2] = (
            _gmul(a0, 13)
            ^ _gmul(a1, 9)
            ^ _gmul(a2, 14)
            ^ _gmul(a3, 11)
        )

        result[index + 3] = (
            _gmul(a0, 11)
            ^ _gmul(a1, 13)
            ^ _gmul(a2, 9)
            ^ _gmul(a3, 14)
        )

    return result


def _rot_word(
    word: list[int],
) -> list[int]:

    return (
        word[1:]
        + word[:1]
    )


def _sub_word(
    word: list[int],
) -> list[int]:

    return [
        S_BOX[value]
        for value in word
    ]


def _expand_key(
    key: bytes,
) -> list[list[int]]:

    if not isinstance(key, bytes):
        raise TypeError(
            "key must be bytes"
        )

    if len(key) != AES_256_KEY_SIZE:
        raise AESError(
            "AES-256 key must be exactly 32 bytes."
        )

    words = [
        list(key[index:index + 4])
        for index in range(
            0,
            AES_256_KEY_SIZE,
            4,
        )
    ]

    total_words = (
        4
        * (AES_256_ROUNDS + 1)
    )

    for index in range(
        8,
        total_words,
    ):

        temp = words[
            index - 1
        ].copy()

        if index % 8 == 0:

            temp = _rot_word(
                temp
            )

            temp = _sub_word(
                temp
            )

            temp[0] ^= RCON[
                index // 8
            ]

        elif index % 8 == 4:

            temp = _sub_word(
                temp
            )

        new_word = [
            words[index - 8][position]
            ^ temp[position]
            for position in range(4)
        ]

        words.append(
            new_word
        )

    round_keys = []

    for round_number in range(
        AES_256_ROUNDS + 1
    ):

        round_key = []

        start = (
            round_number * 4
        )

        for word in words[
            start:start + 4
        ]:

            round_key.extend(
                word
            )

        round_keys.append(
            round_key
        )

    return round_keys


def encrypt_block(
    plaintext_block: bytes,
    key: bytes,
) -> bytes:

    if not isinstance(
        plaintext_block,
        bytes,
    ):
        raise TypeError(
            "plaintext_block must be bytes"
        )

    if len(
        plaintext_block
    ) != AES_BLOCK_SIZE:

        raise AESError(
            "AES block must be exactly 16 bytes."
        )

    round_keys = _expand_key(
        key
    )

    state = list(
        plaintext_block
    )

    state = _add_round_key(
        state,
        round_keys[0],
    )

    for round_number in range(
        1,
        AES_256_ROUNDS,
    ):

        state = _sub_bytes(
            state
        )

        state = _shift_rows(
            state
        )

        state = _mix_columns(
            state
        )

        state = _add_round_key(
            state,
            round_keys[
                round_number
            ],
        )

    state = _sub_bytes(
        state
    )

    state = _shift_rows(
        state
    )

    state = _add_round_key(
        state,
        round_keys[
            AES_256_ROUNDS
        ],
    )

    return bytes(
        state
    )


def decrypt_block(
    ciphertext_block: bytes,
    key: bytes,
) -> bytes:

    if not isinstance(
        ciphertext_block,
        bytes,
    ):
        raise TypeError(
            "ciphertext_block must be bytes"
        )

    if len(
        ciphertext_block
    ) != AES_BLOCK_SIZE:

        raise AESError(
            "AES block must be exactly 16 bytes."
        )

    round_keys = _expand_key(
        key
    )

    state = list(
        ciphertext_block
    )

    state = _add_round_key(
        state,
        round_keys[
            AES_256_ROUNDS
        ],
    )

    for round_number in range(
        AES_256_ROUNDS - 1,
        0,
        -1,
    ):

        state = _inv_shift_rows(
            state
        )

        state = _inv_sub_bytes(
            state
        )

        state = _add_round_key(
            state,
            round_keys[
                round_number
            ],
        )

        state = _inv_mix_columns(
            state
        )

    state = _inv_shift_rows(
        state
    )

    state = _inv_sub_bytes(
        state
    )

    state = _add_round_key(
        state,
        round_keys[0],
    )

    return bytes(
        state
    )