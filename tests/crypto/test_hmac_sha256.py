import hashlib
import hmac

import pytest

from src.crypto.hmac_sha256 import (
    SHA256_DIGEST_SIZE,
    hmac_sha256,
    verify_hmac_sha256,
)


def test_rfc4231_case_1():

    key = bytes.fromhex(
        "0b" * 20
    )

    message = b"Hi There"

    expected = bytes.fromhex(
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7"
    )

    actual = hmac_sha256(
        key,
        message,
    )

    assert actual == expected


def test_rfc4231_case_2():

    key = b"Jefe"

    message = (
        b"what do ya want for nothing?"
    )

    expected = bytes.fromhex(
        "5bdcc146bf60754e6a042426089575c7"
        "5a003f089d2739839dec58b964ec3843"
    )

    actual = hmac_sha256(
        key,
        message,
    )

    assert actual == expected


def test_reference_library_matches():

    key = (
        b"SecureVault-HMAC-Key"
    )

    message = (
        b"Encrypted document data"
    )

    expected = hmac.new(
        key,
        message,
        hashlib.sha256,
    ).digest()

    actual = hmac_sha256(
        key,
        message,
    )

    assert actual == expected


def test_long_key_matches_reference():

    key = b"K" * 100

    message = (
        b"SecureVault long key test"
    )

    expected = hmac.new(
        key,
        message,
        hashlib.sha256,
    ).digest()

    actual = hmac_sha256(
        key,
        message,
    )

    assert actual == expected


def test_empty_message():

    key = b"key"

    message = b""

    expected = hmac.new(
        key,
        message,
        hashlib.sha256,
    ).digest()

    actual = hmac_sha256(
        key,
        message,
    )

    assert actual == expected


def test_empty_key():

    key = b""

    message = b"SecureVault"

    expected = hmac.new(
        key,
        message,
        hashlib.sha256,
    ).digest()

    actual = hmac_sha256(
        key,
        message,
    )

    assert actual == expected


def test_tag_length():

    tag = hmac_sha256(
        b"key",
        b"message",
    )

    assert len(tag) == (
        SHA256_DIGEST_SIZE
    )


def test_verify_correct_tag():

    key = b"key"

    message = b"message"

    tag = hmac_sha256(
        key,
        message,
    )

    assert verify_hmac_sha256(
        key,
        message,
        tag,
    )


def test_verify_modified_message_fails():

    key = b"key"

    tag = hmac_sha256(
        key,
        b"original",
    )

    assert not verify_hmac_sha256(
        key,
        b"modified",
        tag,
    )


def test_verify_modified_tag_fails():

    key = b"key"

    message = b"message"

    tag = bytearray(
        hmac_sha256(
            key,
            message,
        )
    )

    tag[0] ^= 1

    assert not verify_hmac_sha256(
        key,
        message,
        bytes(tag),
    )


def test_invalid_tag_length_fails():

    assert not verify_hmac_sha256(
        b"key",
        b"message",
        b"short",
    )


def test_key_must_be_bytes():

    with pytest.raises(
        TypeError
    ):
        hmac_sha256(
            "key",
            b"message",
        )


def test_message_must_be_bytes():

    with pytest.raises(
        TypeError
    ):
        hmac_sha256(
            b"key",
            "message",
        )


def test_tag_must_be_bytes():

    with pytest.raises(
        TypeError
    ):
        verify_hmac_sha256(
            b"key",
            b"message",
            "tag",
        )