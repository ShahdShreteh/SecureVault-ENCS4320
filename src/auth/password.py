"""Argon2id password-record creation and verification."""

import hmac
import secrets

from argon2.low_level import Type, hash_secret_raw

from . import config
from .errors import ValidationError
from .models import LoginChallenge, PasswordRecord


def validate_password(password: str) -> None:
    if not isinstance(password, str):
        raise ValidationError("Password must be text.")
    if not config.MIN_PASSWORD_LENGTH <= len(password) <= config.MAX_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must contain {config.MIN_PASSWORD_LENGTH} to "
            f"{config.MAX_PASSWORD_LENGTH} characters."
        )


def _derive(password: str, record: PasswordRecord) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=record.salt,
        time_cost=record.time_cost,
        memory_cost=record.memory_cost,
        parallelism=record.parallelism,
        hash_len=record.hash_length,
        type=Type.ID,
        version=record.version,
    )


def create_password_record(password: str, salt: bytes | None = None) -> PasswordRecord:
    validate_password(password)
    selected_salt = salt if salt is not None else secrets.token_bytes(config.ARGON2_SALT_LENGTH)
    if len(selected_salt) < 16:
        raise ValidationError("Argon2 salt must be at least 16 bytes.")
    template = PasswordRecord(
        algorithm=config.ARGON2_ALGORITHM,
        salt=selected_salt,
        password_hash=b"",
        memory_cost=config.ARGON2_MEMORY_COST,
        time_cost=config.ARGON2_TIME_COST,
        parallelism=config.ARGON2_PARALLELISM,
        hash_length=config.ARGON2_HASH_LENGTH,
        version=config.ARGON2_VERSION,
    )
    return PasswordRecord(**{**template.__dict__, "password_hash": _derive(password, template)})


def derive_for_challenge(password: str, challenge: LoginChallenge) -> bytes:
    validate_password(password)
    template = PasswordRecord(
        algorithm=config.ARGON2_ALGORITHM,
        salt=challenge.salt,
        password_hash=b"",
        memory_cost=challenge.memory_cost,
        time_cost=challenge.time_cost,
        parallelism=challenge.parallelism,
        hash_length=challenge.hash_length,
        version=challenge.version,
    )
    return _derive(password, template)


def verify_password(password: str, record: PasswordRecord) -> bool:
    try:
        candidate = _derive(password, record)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, record.password_hash)
