"""PKCS#7 padding helpers for SecureVault."""

from __future__ import annotations


AES_BLOCK_SIZE = 16


class PaddingError(ValueError):
    pass

def pkcs7_pad(
    data: bytes,
    block_size: int = AES_BLOCK_SIZE,
) -> bytes:

    if not isinstance(data, bytes):
        raise TypeError(
            "data must be bytes"
        )

    if not isinstance(block_size, int):
        raise TypeError(
            "block_size must be an integer"
        )

    if block_size < 1 or block_size > 255:
        raise ValueError(
            "block_size must be between 1 and 255 bytes"
        )

    padding_length = (
        block_size
        - (len(data) % block_size)
    )

    padding = (
        bytes([padding_length])
        * padding_length
    )

    return data + padding


def pkcs7_unpad(
    padded_data: bytes,
    block_size: int = AES_BLOCK_SIZE,
) -> bytes:
    """
    Validate and remove PKCS#7 padding.
    """

    if not isinstance(padded_data, bytes):
        raise TypeError(
            "padded_data must be bytes"
        )

    if not isinstance(block_size, int):
        raise TypeError(
            "block_size must be an integer"
        )

    if block_size < 1 or block_size > 255:
        raise ValueError(
            "block_size must be between 1 and 255 bytes"
        )

    if len(padded_data) == 0:
        raise PaddingError(
            "Invalid PKCS#7 padding."
        )

    if len(padded_data) % block_size != 0:
        raise PaddingError(
            "Invalid PKCS#7 padded length."
        )

    padding_length = padded_data[-1]

    if (
        padding_length < 1
        or padding_length > block_size
    ):
        raise PaddingError(
            "Invalid PKCS#7 padding."
        )

    expected_padding = (
        bytes([padding_length])
        * padding_length
    )

    actual_padding = padded_data[
        -padding_length:
    ]

    if actual_padding != expected_padding:
        raise PaddingError(
            "Invalid PKCS#7 padding."
        )

    return padded_data[
        :-padding_length
    ]