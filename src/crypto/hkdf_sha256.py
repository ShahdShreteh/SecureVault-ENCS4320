from .hmac_sha256 import (
    SHA256_DIGEST_SIZE,
    hmac_sha256,
)


class HKDFError(ValueError):
    pass


def _validate_bytes(
    value: bytes,
    name: str,
) -> None:
    if not isinstance(value, bytes):
        raise TypeError(
            f"{name} must be bytes"
        )


def hkdf_extract(
    salt: bytes,
    input_key_material: bytes,
) -> bytes:
    _validate_bytes(
        salt,
        "salt",
    )

    _validate_bytes(
        input_key_material,
        "input_key_material",
    )

    if len(salt) == 0:
        salt = (
            b"\x00"
            * SHA256_DIGEST_SIZE
        )

    return hmac_sha256(
        salt,
        input_key_material,
    )


def hkdf_expand(
    pseudorandom_key: bytes,
    info: bytes,
    length: int,
) -> bytes:
    _validate_bytes(
        pseudorandom_key,
        "pseudorandom_key",
    )

    _validate_bytes(
        info,
        "info",
    )

    if not isinstance(length, int):
        raise TypeError(
            "length must be an integer"
        )

    if length < 0:
        raise HKDFError(
            "length cannot be negative"
        )

    maximum_length = (
        255 * SHA256_DIGEST_SIZE
    )

    if length > maximum_length:
        raise HKDFError(
            "Requested HKDF output is too long."
        )

    if length == 0:
        return b""

    output = bytearray()
    previous = b""

    block_number = 1

    while len(output) < length:

        previous = hmac_sha256(
            pseudorandom_key,
            previous
            + info
            + bytes([block_number]),
        )

        output.extend(
            previous
        )

        block_number += 1

    return bytes(
        output[:length]
    )


def hkdf_sha256(
    input_key_material: bytes,
    salt: bytes = b"",
    info: bytes = b"",
    length: int = 32,
) -> bytes:
    _validate_bytes(
        input_key_material,
        "input_key_material",
    )

    _validate_bytes(
        salt,
        "salt",
    )

    _validate_bytes(
        info,
        "info",
    )

    pseudorandom_key = hkdf_extract(
        salt,
        input_key_material,
    )

    return hkdf_expand(
        pseudorandom_key,
        info,
        length,
    )