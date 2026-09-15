"""One-time login proof. Replace make_mac with the team's HMAC implementation."""

import hashlib
import hmac
from collections.abc import Callable

from .models import LoginChallenge

MacFunction = Callable[[bytes, bytes], bytes]


def standard_library_hmac(key: bytes, message: bytes) -> bytes:
    """Standalone adapter; replace by person 2's from-scratch HMAC-SHA256."""
    return hmac.new(key, message, hashlib.sha256).digest()


def proof_message(challenge: LoginChallenge) -> bytes:
    username = challenge.username.encode("utf-8")
    return (
        b"SecureVault-Login-v1"
        + len(username).to_bytes(2, "big")
        + username
        + len(challenge.nonce).to_bytes(2, "big")
        + challenge.nonce
        + challenge.challenge_id.encode("ascii")
    )


def create_login_proof(
    derived_password: bytes,
    challenge: LoginChallenge,
    make_mac: MacFunction = standard_library_hmac,
) -> bytes:
    return make_mac(derived_password, proof_message(challenge))
