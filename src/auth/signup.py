"""Client preparation and server storage for registration."""

import re
from datetime import datetime, timezone

from . import config
from .errors import DuplicateUsernameError, ValidationError
from .login_key import derive_login_public_key
from .models import PreparedSignup, UserRecord
from .password import create_password_record, derive_password_secret
from .user_store import UserStore


def validate_username(username: str) -> str:
 
    if not isinstance(username, str):
        raise ValidationError("Username must be text.")

    candidate = username.strip()

    if not (
        config.MIN_USERNAME_LENGTH
        <= len(candidate)
        <= config.MAX_USERNAME_LENGTH
    ):
        raise ValidationError(
            f"Username must contain {config.MIN_USERNAME_LENGTH} to "
            f"{config.MAX_USERNAME_LENGTH} characters."
        )

    if re.fullmatch(config.USERNAME_PATTERN, candidate) is None:
        raise ValidationError(
            "Username may contain letters, numbers, and underscore only."
        )

    return candidate


def _validate_public_keys(
    x25519_public_key: bytes,
    ed25519_public_key: bytes,
) -> None:
   
    if not isinstance(x25519_public_key, bytes):
        raise ValidationError(
            "X25519 public key must be bytes."
        )

    if not isinstance(ed25519_public_key, bytes):
        raise ValidationError(
            "Ed25519 public key must be bytes."
        )

    if len(x25519_public_key) != 32:
        raise ValidationError(
            "X25519 public key must be exactly 32 bytes."
        )

    if len(ed25519_public_key) != 32:
        raise ValidationError(
            "Ed25519 public key must be exactly 32 bytes."
        )


def prepare_signup(
    username: str,
    password: str,
    x25519_public_key: bytes,
    ed25519_public_key: bytes,
    encrypted_private_key_bundle: bytes,
) -> PreparedSignup:
    
    candidate = validate_username(username)

    _validate_public_keys(
        x25519_public_key,
        ed25519_public_key,
    )

    if not isinstance(encrypted_private_key_bundle, bytes):
        raise ValidationError(
            "Encrypted private-key bundle must be bytes."
        )

    if not encrypted_private_key_bundle:
        raise ValidationError(
            "Encrypted private-key bundle is required."
        )

    password_record = create_password_record(password)

    password_secret = derive_password_secret(
        password,
        password_record,
    )

    login_public_key = derive_login_public_key(
        password_secret
    )

    if len(login_public_key) != 32:
        raise ValidationError(
            "Derived login public key must be exactly 32 bytes."
        )

    return PreparedSignup(
        username=candidate,
        password_record=password_record,
        login_public_key=login_public_key,
        x25519_public_key=x25519_public_key,
        ed25519_public_key=ed25519_public_key,
        encrypted_private_key_bundle=encrypted_private_key_bundle,
    )


def register_prepared(
    store: UserStore,
    prepared: PreparedSignup,
) -> UserRecord:

    if not isinstance(prepared, PreparedSignup):
        raise ValidationError(
            "Invalid prepared signup data."
        )

    if store.username_exists(prepared.username):
        raise DuplicateUsernameError(
            "Username already exists."
        )

    if len(prepared.login_public_key) != 32:
        raise ValidationError(
            "Login public key must be exactly 32 bytes."
        )

    user = UserRecord(
        user_id=None,
        username=prepared.username,
        password_record=prepared.password_record,
        login_public_key=prepared.login_public_key,
        x25519_public_key=prepared.x25519_public_key,
        ed25519_public_key=prepared.ed25519_public_key,
        encrypted_private_key_bundle=(
            prepared.encrypted_private_key_bundle
        ),
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    return store.create_user(user)