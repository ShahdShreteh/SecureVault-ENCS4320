import pytest

from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)

from src.crypto.cbc import (
    CBCError,
    cbc_decrypt,
    cbc_decrypt_blocks,
    cbc_encrypt,
    cbc_encrypt_blocks,
    generate_iv,
)


KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d7781"
    "1f352c073b6108d72d9810a30914dff4"
)

IV = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
)

PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)

EXPECTED_CIPHERTEXT = bytes.fromhex(
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
    "9cfc4e967edb808d679f777bc6702c7d"
    "39f23369a9d9bacfa530e26304231461"
    "b2eb05e2c39be9fcda6c19078c6a9d1b"
)


def test_cbc_known_vector_encrypt():

    ciphertext = cbc_encrypt_blocks(
        PLAINTEXT,
        KEY,
        IV,
    )

    assert (
        ciphertext
        == EXPECTED_CIPHERTEXT
    )


def test_cbc_known_vector_decrypt():

    plaintext = cbc_decrypt_blocks(
        EXPECTED_CIPHERTEXT,
        KEY,
        IV,
    )

    assert plaintext == PLAINTEXT


def test_cbc_reference_library_matches():

    cipher = Cipher(
        algorithms.AES(KEY),
        modes.CBC(IV),
    )

    encryptor = cipher.encryptor()

    expected = (
        encryptor.update(
            PLAINTEXT
        )
        + encryptor.finalize()
    )

    actual = cbc_encrypt_blocks(
        PLAINTEXT,
        KEY,
        IV,
    )

    assert actual == expected


def test_padded_round_trip():

    plaintext = (
        b"SecureVault encrypted document."
    )

    ciphertext = cbc_encrypt(
        plaintext,
        KEY,
        IV,
    )

    recovered = cbc_decrypt(
        ciphertext,
        KEY,
        IV,
    )

    assert recovered == plaintext


def test_empty_plaintext_round_trip():

    ciphertext = cbc_encrypt(
        b"",
        KEY,
        IV,
    )

    assert len(ciphertext) == 16

    recovered = cbc_decrypt(
        ciphertext,
        KEY,
        IV,
    )

    assert recovered == b""


def test_ciphertext_is_block_aligned():

    plaintext = b"Hello SecureVault"

    ciphertext = cbc_encrypt(
        plaintext,
        KEY,
        IV,
    )

    assert len(ciphertext) % 16 == 0


def test_fresh_iv_generation():

    first = generate_iv()
    second = generate_iv()

    assert len(first) == 16
    assert len(second) == 16
    assert first != second


def test_different_ivs_change_ciphertext():

    plaintext = b"A" * 32

    first_iv = generate_iv()
    second_iv = generate_iv()

    first = cbc_encrypt(
        plaintext,
        KEY,
        first_iv,
    )

    second = cbc_encrypt(
        plaintext,
        KEY,
        second_iv,
    )

    assert first != second


def test_invalid_iv_length_is_rejected():

    with pytest.raises(
        CBCError
    ):
        cbc_encrypt(
            b"hello",
            KEY,
            b"short",
        )


def test_invalid_key_length_is_rejected():

    with pytest.raises(
        CBCError
    ):
        cbc_encrypt(
            b"hello",
            b"k" * 16,
            IV,
        )


def test_raw_plaintext_must_be_block_aligned():

    with pytest.raises(
        CBCError
    ):
        cbc_encrypt_blocks(
            b"not-aligned",
            KEY,
            IV,
        )


def test_raw_ciphertext_must_be_block_aligned():

    with pytest.raises(
        CBCError
    ):
        cbc_decrypt_blocks(
            b"not-aligned",
            KEY,
            IV,
        )


def test_empty_ciphertext_is_rejected():

    with pytest.raises(
        CBCError
    ):
        cbc_decrypt(
            b"",
            KEY,
            IV,
        )