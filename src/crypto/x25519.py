import secrets


FIELD_PRIME = 2**255 - 19
A24 = 121665
KEY_SIZE = 32
BASE_POINT = bytes([9]) + b"\x00" * 31


class X25519Error(ValueError):
    pass


def _validate_key(
    value: bytes,
    name: str,
) -> None:
    if not isinstance(value, bytes):
        raise TypeError(
            f"{name} must be bytes"
        )

    if len(value) != KEY_SIZE:
        raise X25519Error(
            f"{name} must be exactly 32 bytes."
        )


def clamp_scalar(
    scalar: bytes,
) -> bytes:
    _validate_key(
        scalar,
        "scalar",
    )

    value = bytearray(
        scalar
    )

    value[0] &= 248
    value[31] &= 127
    value[31] |= 64

    return bytes(value)


def _decode_scalar(
    scalar: bytes,
) -> int:
    clamped = clamp_scalar(
        scalar
    )

    return int.from_bytes(
        clamped,
        "little",
    )


def _decode_u_coordinate(
    coordinate: bytes,
) -> int:
    _validate_key(
        coordinate,
        "u_coordinate",
    )

    value = bytearray(
        coordinate
    )

    value[31] &= 127

    return int.from_bytes(
        value,
        "little",
    )


def _encode_u_coordinate(
    coordinate: int,
) -> bytes:
    return (
        coordinate % FIELD_PRIME
    ).to_bytes(
        KEY_SIZE,
        "little",
    )


def _conditional_swap(
    swap: int,
    first: int,
    second: int,
) -> tuple[int, int]:
    mask = -swap

    temporary = (
        mask
        & (first ^ second)
    )

    first ^= temporary
    second ^= temporary

    return first, second


def x25519(
    private_key: bytes,
    peer_public_key: bytes,
) -> bytes:
    _validate_key(
        private_key,
        "private_key",
    )

    _validate_key(
        peer_public_key,
        "peer_public_key",
    )

    scalar = _decode_scalar(
        private_key
    )

    x1 = _decode_u_coordinate(
        peer_public_key
    )

    x2 = 1
    z2 = 0
    x3 = x1
    z3 = 1
    swap = 0

    for bit_index in range(
        254,
        -1,
        -1,
    ):
        bit = (
            scalar >> bit_index
        ) & 1

        swap ^= bit

        x2, x3 = _conditional_swap(
            swap,
            x2,
            x3,
        )

        z2, z3 = _conditional_swap(
            swap,
            z2,
            z3,
        )

        swap = bit

        a = (
            x2 + z2
        ) % FIELD_PRIME

        aa = (
            a * a
        ) % FIELD_PRIME

        b = (
            x2 - z2
        ) % FIELD_PRIME

        bb = (
            b * b
        ) % FIELD_PRIME

        e = (
            aa - bb
        ) % FIELD_PRIME

        c = (
            x3 + z3
        ) % FIELD_PRIME

        d = (
            x3 - z3
        ) % FIELD_PRIME

        da = (
            d * a
        ) % FIELD_PRIME

        cb = (
            c * b
        ) % FIELD_PRIME

        x3 = (
            (da + cb)
            * (da + cb)
        ) % FIELD_PRIME

        z3 = (
            x1
            * (da - cb)
            * (da - cb)
        ) % FIELD_PRIME

        x2 = (
            aa * bb
        ) % FIELD_PRIME

        z2 = (
            e
            * (
                aa
                + A24 * e
            )
        ) % FIELD_PRIME

    x2, x3 = _conditional_swap(
        swap,
        x2,
        x3,
    )

    z2, z3 = _conditional_swap(
        swap,
        z2,
        z3,
    )

    inverse_z2 = pow(
        z2,
        FIELD_PRIME - 2,
        FIELD_PRIME,
    )

    result = (
        x2 * inverse_z2
    ) % FIELD_PRIME

    return _encode_u_coordinate(
        result
    )


def generate_private_key() -> bytes:
    return secrets.token_bytes(
        KEY_SIZE
    )


def derive_public_key(
    private_key: bytes,
) -> bytes:
    return x25519(
        private_key,
        BASE_POINT,
    )


def generate_keypair() -> tuple[
    bytes,
    bytes,
]:
    private_key = generate_private_key()

    public_key = derive_public_key(
        private_key
    )

    return (
        private_key,
        public_key,
    )


def compute_shared_secret(
    private_key: bytes,
    peer_public_key: bytes,
) -> bytes:
    shared_secret = x25519(
        private_key,
        peer_public_key,
    )

    if shared_secret == (
        b"\x00" * KEY_SIZE
    ):
        raise X25519Error(
            "Invalid peer public key."
        )

    return shared_secret