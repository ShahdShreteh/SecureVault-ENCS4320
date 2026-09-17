
from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from . import config
from .errors import ValidationError


# Allows us to replace the library HMAC later with the team's
# from-scratch HMAC-SHA256 implementation.
MacFunction = Callable[[bytes, bytes], bytes]


def _standard_library_hmac(key: bytes, message: bytes) -> bytes:
    """
    Temporary HMAC-SHA256 adapter.

    Replace this function later with the team's from-scratch
    HMAC-SHA256 implementation.
    """
    return hmac.new(
        key,
        message,
        hashlib.sha256,
    ).digest()


def derive_login_private_key_bytes(
    password_secret: bytes,
    make_mac: MacFunction = _standard_library_hmac,
) -> bytes:
    """
    Derive the deterministic 32-byte login X25519 private-key material
    from the Argon2id password secret.

    password_secret must be the output produced locally by Argon2id.

    This value must NEVER be sent to or stored by the server.
    """
    if not isinstance(password_secret, bytes):
        raise ValidationError("Password secret must be bytes.")

    if len(password_secret) < 16:
        raise ValidationError("Password secret is too short.")

    derived = make_mac(
        password_secret,
        config.LOGIN_KEY_LABEL,
    )

    if len(derived) < 32:
        raise ValidationError(
            "Login-key derivation must produce at least 32 bytes."
        )

    return derived[:32]


def login_private_key_from_secret(
    password_secret: bytes,
    make_mac: MacFunction = _standard_library_hmac,
) -> X25519PrivateKey:
    """
    Create the client's deterministic login X25519 private key.

    The cryptography X25519 implementation internally performs the
    required scalar clamping.
    """
    private_bytes = derive_login_private_key_bytes(
        password_secret,
        make_mac,
    )

    try:
        return X25519PrivateKey.from_private_bytes(private_bytes)
    except ValueError as error:
        raise ValidationError(
            "Could not construct login private key."
        ) from error


def login_public_key_from_private(
    private_key: X25519PrivateKey,
) -> bytes:
    """
    Return the raw 32-byte X25519 public key corresponding to a
    login private key.
    """
    if not isinstance(private_key, X25519PrivateKey):
        raise ValidationError("Invalid X25519 private key.")

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def derive_login_public_key(
    password_secret: bytes,
    make_mac: MacFunction = _standard_library_hmac,
) -> bytes:
    """
    Convenience function used during sign-up.

    Argon2 password secret
        → login private key
        → 32-byte login public key

    Only the returned public key is sent to the server.
    """
    private_key = login_private_key_from_secret(
        password_secret,
        make_mac,
    )

    return login_public_key_from_private(private_key)


def generate_ephemeral_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    """
    Generate a fresh X25519 key pair.

    Used by the server for each login challenge.

    Returns:
        (
            private_key_object,
            raw_32_byte_public_key
        )
    """
    private_key = X25519PrivateKey.generate()

    public_key = login_public_key_from_private(private_key)

    return private_key, public_key


def compute_shared_secret(
    private_key: X25519PrivateKey,
    peer_public_key_bytes: bytes,
) -> bytes:
    """
    Compute an X25519 shared secret.

    Client side:
        login private key
        +
        server ephemeral public key

    Server side:
        server ephemeral private key
        +
        stored client login public key

    Both sides obtain the same 32-byte shared secret.
    """
    if not isinstance(private_key, X25519PrivateKey):
        raise ValidationError("Invalid X25519 private key.")

    if not isinstance(peer_public_key_bytes, bytes):
        raise ValidationError("Peer public key must be bytes.")

    if len(peer_public_key_bytes) != 32:
        raise ValidationError(
            "X25519 public key must contain exactly 32 bytes."
        )

    try:
        peer_public_key = X25519PublicKey.from_public_bytes(
            peer_public_key_bytes
        )

        shared_secret = private_key.exchange(peer_public_key)

    except (ValueError, TypeError) as error:
        raise ValidationError(
            "Invalid peer X25519 public key."
        ) from error

    # Defensive check.
    #
    # X25519 implementations normally reject invalid low-order inputs,
    # but we also refuse an all-zero shared secret explicitly.
    if shared_secret == b"\x00" * 32:
        raise ValidationError(
            "Invalid X25519 shared secret."
        )

    return shared_secret