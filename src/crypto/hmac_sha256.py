import hashlib
import secrets


SHA256_BLOCK_SIZE = 64
SHA256_DIGEST_SIZE = 32


class HMACError(ValueError):
    pass


def _validate_bytes(
    value: bytes,
    name: str,
) -> None:
    if not isinstance(value, bytes):
        raise TypeError(
            f"{name} must be bytes"
        )


def _normalize_key(
    key: bytes,
) -> bytes:
    _validate_bytes(
        key,
        "key",
    )

    if len(key) > SHA256_BLOCK_SIZE:
        key = hashlib.sha256(
            key
        ).digest()

    if len(key) < SHA256_BLOCK_SIZE:
        key = (
            key
            + b"\x00"
            * (
                SHA256_BLOCK_SIZE
                - len(key)
            )
        )

    return key


def hmac_sha256(
    key: bytes,
    message: bytes,
) -> bytes:
    _validate_bytes(
        message,
        "message",
    )

    normalized_key = _normalize_key(
        key
    )

    inner_pad = bytes(
        byte ^ 0x36
        for byte in normalized_key
    )

    outer_pad = bytes(
        byte ^ 0x5C
        for byte in normalized_key
    )

    inner_hash = hashlib.sha256(
        inner_pad + message
    ).digest()

    return hashlib.sha256(
        outer_pad + inner_hash
    ).digest()


def verify_hmac_sha256(
    key: bytes,
    message: bytes,
    tag: bytes,
) -> bool:
    _validate_bytes(
        key,
        "key",
    )

    _validate_bytes(
        message,
        "message",
    )

    _validate_bytes(
        tag,
        "tag",
    )

    if len(tag) != SHA256_DIGEST_SIZE:
        return False

    expected = hmac_sha256(
        key,
        message,
    )

    return secrets.compare_digest(
        expected,
        tag,
    )