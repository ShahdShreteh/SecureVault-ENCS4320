import secrets

from .aes import (
    AES_BLOCK_SIZE,
    AES_256_KEY_SIZE,
    AESError,
    decrypt_block,
    encrypt_block,
)
from .padding import pkcs7_pad, pkcs7_unpad


class CBCError(ValueError):
    pass


def generate_iv() -> bytes:
    return secrets.token_bytes(AES_BLOCK_SIZE)


def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")

    if len(key) != AES_256_KEY_SIZE:
        raise CBCError(
            "AES-256 key must be exactly 32 bytes."
        )


def _validate_iv(iv: bytes) -> None:
    if not isinstance(iv, bytes):
        raise TypeError("iv must be bytes")

    if len(iv) != AES_BLOCK_SIZE:
        raise CBCError(
            "CBC IV must be exactly 16 bytes."
        )


def _xor_blocks(
    first: bytes,
    second: bytes,
) -> bytes:
    if len(first) != AES_BLOCK_SIZE:
        raise CBCError(
            "CBC block must be exactly 16 bytes."
        )

    if len(second) != AES_BLOCK_SIZE:
        raise CBCError(
            "CBC block must be exactly 16 bytes."
        )

    return bytes(
        a ^ b
        for a, b in zip(first, second)
    )


def cbc_encrypt_blocks(
    plaintext: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    if not isinstance(plaintext, bytes):
        raise TypeError(
            "plaintext must be bytes"
        )

    _validate_key(key)
    _validate_iv(iv)

    if len(plaintext) % AES_BLOCK_SIZE != 0:
        raise CBCError(
            "Plaintext length must be a multiple of 16 bytes."
        )

    ciphertext = bytearray()
    previous = iv

    for offset in range(
        0,
        len(plaintext),
        AES_BLOCK_SIZE,
    ):
        block = plaintext[
            offset:offset + AES_BLOCK_SIZE
        ]

        mixed = _xor_blocks(
            block,
            previous,
        )

        encrypted = encrypt_block(
            mixed,
            key,
        )

        ciphertext.extend(
            encrypted
        )

        previous = encrypted

    return bytes(ciphertext)


def cbc_decrypt_blocks(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    if not isinstance(ciphertext, bytes):
        raise TypeError(
            "ciphertext must be bytes"
        )

    _validate_key(key)
    _validate_iv(iv)

    if len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise CBCError(
            "Ciphertext length must be a multiple of 16 bytes."
        )

    plaintext = bytearray()
    previous = iv

    for offset in range(
        0,
        len(ciphertext),
        AES_BLOCK_SIZE,
    ):
        block = ciphertext[
            offset:offset + AES_BLOCK_SIZE
        ]

        decrypted = decrypt_block(
            block,
            key,
        )

        plaintext_block = _xor_blocks(
            decrypted,
            previous,
        )

        plaintext.extend(
            plaintext_block
        )

        previous = block

    return bytes(plaintext)


def cbc_encrypt(
    plaintext: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    if not isinstance(plaintext, bytes):
        raise TypeError(
            "plaintext must be bytes"
        )

    padded = pkcs7_pad(
        plaintext,
        AES_BLOCK_SIZE,
    )

    return cbc_encrypt_blocks(
        padded,
        key,
        iv,
    )


def cbc_decrypt(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    if not isinstance(ciphertext, bytes):
        raise TypeError(
            "ciphertext must be bytes"
        )

    if len(ciphertext) == 0:
        raise CBCError(
            "Ciphertext cannot be empty."
        )

    decrypted = cbc_decrypt_blocks(
        ciphertext,
        key,
        iv,
    )

    return pkcs7_unpad(
        decrypted,
        AES_BLOCK_SIZE,
    )