import pytest

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)

from src.crypto.aes import (
    AESError,
    decrypt_block,
    encrypt_block,
)


KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d7781"
    "1f352c073b6108d72d9810a30914dff4"
)

PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
)

EXPECTED_CIPHERTEXT = bytes.fromhex(
    "f3eed1bdb5d2a03c064b5a7e3db181f8"
)


def test_aes256_known_vector_encrypt():

    ciphertext = encrypt_block(
        PLAINTEXT,
        KEY,
    )

    assert (
        ciphertext
        == EXPECTED_CIPHERTEXT
    )


def test_aes256_known_vector_decrypt():

    plaintext = decrypt_block(
        EXPECTED_CIPHERTEXT,
        KEY,
    )

    assert plaintext == PLAINTEXT


def test_encrypt_then_decrypt_round_trip():

    key = bytes(range(32))

    plaintext = bytes(
        range(16)
    )

    ciphertext = encrypt_block(
        plaintext,
        key,
    )

    recovered = decrypt_block(
        ciphertext,
        key,
    )

    assert recovered == plaintext


def test_ciphertext_differs_from_plaintext():

    key = bytes(range(32))

    plaintext = b"A" * 16

    ciphertext = encrypt_block(
        plaintext,
        key,
    )

    assert ciphertext != plaintext


def test_reference_library_matches():

    cipher = Cipher(
        algorithms.AES(KEY),
        modes.ECB(),
    )

    encryptor = cipher.encryptor()

    expected = (
        encryptor.update(
            PLAINTEXT
        )
        + encryptor.finalize()
    )

    actual = encrypt_block(
        PLAINTEXT,
        KEY,
    )

    assert actual == expected


def test_wrong_key_length_is_rejected():

    with pytest.raises(
        AESError
    ):
        encrypt_block(
            PLAINTEXT,
            b"k" * 16,
        )


def test_wrong_plaintext_block_size_is_rejected():

    with pytest.raises(
        AESError
    ):
        encrypt_block(
            b"short",
            KEY,
        )


def test_wrong_ciphertext_block_size_is_rejected():

    with pytest.raises(
        AESError
    ):
        decrypt_block(
            b"short",
            KEY,
        )


def test_key_must_be_bytes():

    with pytest.raises(
        TypeError
    ):
        encrypt_block(
            PLAINTEXT,
            "not-bytes",
        )