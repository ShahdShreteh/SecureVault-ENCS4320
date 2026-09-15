"""Client preparation and server storage for registration."""

import re
from datetime import datetime, timezone

from . import config
from .errors import DuplicateUsernameError, ValidationError
from .models import PreparedSignup, UserRecord
from .password import create_password_record
from .user_store import UserStore


def validate_username(username: str) -> str:
    if not isinstance(username, str):
        raise ValidationError("Username must be text.")
    candidate = username.strip()
    if not config.MIN_USERNAME_LENGTH <= len(candidate) <= config.MAX_USERNAME_LENGTH:
        raise ValidationError(
            f"Username must contain {config.MIN_USERNAME_LENGTH} to "
            f"{config.MAX_USERNAME_LENGTH} characters."
        )
    if re.fullmatch(config.USERNAME_PATTERN, candidate) is None:
        raise ValidationError("Username may contain letters, numbers, and underscore only.")
    return candidate


def prepare_signup(
    username: str,
    password: str,
    x25519_public_key: bytes,
    ed25519_public_key: bytes,
    encrypted_private_key_bundle: bytes,
) -> PreparedSignup:
    """Run on the client so the plaintext password never leaves the client."""
    candidate = validate_username(username)
    if len(x25519_public_key) != 32 or len(ed25519_public_key) != 32:
        raise ValidationError("X25519 and Ed25519 public keys must each be 32 bytes.")
    if not encrypted_private_key_bundle:
        raise ValidationError("Encrypted private-key bundle is required.")
    return PreparedSignup(
        username=candidate,
        password_record=create_password_record(password),
        x25519_public_key=x25519_public_key,
        ed25519_public_key=ed25519_public_key,
        encrypted_private_key_bundle=encrypted_private_key_bundle,
    )


def register_prepared(store: UserStore, prepared: PreparedSignup) -> UserRecord:
    """Run on the server; receives no plaintext password or plaintext private key."""
    if store.username_exists(prepared.username):
        raise DuplicateUsernameError("Username already exists.")
    user = UserRecord(
        user_id=None,
        username=prepared.username,
        password_record=prepared.password_record,
        x25519_public_key=prepared.x25519_public_key,
        ed25519_public_key=prepared.ed25519_public_key,
        encrypted_private_key_bundle=prepared.encrypted_private_key_bundle,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    return store.create_user(user)
