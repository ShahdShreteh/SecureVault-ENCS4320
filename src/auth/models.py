"""Data containers used by the authentication component."""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class PasswordRecord:
    algorithm: str
    salt: bytes
    memory_cost: int
    time_cost: int
    parallelism: int
    hash_length: int
    version: int


@dataclass(frozen=True)
class UserRecord:
    user_id: Optional[int]
    username: str
    password_record: PasswordRecord
    login_public_key: bytes
    x25519_public_key: bytes
    ed25519_public_key: bytes
    encrypted_private_key_bundle: bytes
    created_at: str


@dataclass(frozen=True)
class PreparedSignup:
    """Safe-to-send registration data prepared on the client."""

    username: str
    password_record: PasswordRecord
    login_public_key: bytes
    x25519_public_key: bytes
    ed25519_public_key: bytes
    encrypted_private_key_bundle: bytes


@dataclass(frozen=True)
class LoginChallenge:
    challenge_id: str
    username: str
    nonce: bytes
    salt: bytes
    server_ephemeral_public_key: bytes
    memory_cost: int
    time_cost: int
    parallelism: int
    hash_length: int
    version: int


@dataclass(frozen=True)
class AuthResult:
    success: bool
    error_code: Optional[str] = None
    message: str = ""
    username: Optional[str] = None
    session_token: Optional[str] = None
