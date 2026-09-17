"""Tests for the SecureVault SQLite user store."""

from datetime import datetime, timezone

import pytest

from src.auth.errors import DuplicateUsernameError
from src.auth.login_key import derive_login_public_key
from src.auth.models import UserRecord
from src.auth.password import (
    create_password_record,
    derive_password_secret,
)
from src.auth.user_store import UserStore


TEST_PASSWORD = "Correct-Horse-2026"


def make_user(
    username: str = "Layla",
) -> UserRecord:

    password_record = create_password_record(
        TEST_PASSWORD
    )

    password_secret = derive_password_secret(
        TEST_PASSWORD,
        password_record,
    )

    login_public_key = derive_login_public_key(
        password_secret
    )

    return UserRecord(
        user_id=None,

        username=username,

        password_record=password_record,

        login_public_key=login_public_key,

        x25519_public_key=b"x" * 32,

        ed25519_public_key=b"e" * 32,

        encrypted_private_key_bundle=(
            b"encrypted-private-key-bundle"
        ),

        created_at=datetime.now(
            timezone.utc
        ).isoformat(),
    )


def test_store_and_reload_user(
    tmp_path,
):

    store = UserStore(
        tmp_path / "users.db"
    )

    original = make_user()

    saved = store.create_user(
        original
    )

    assert saved.user_id is not None

    assert saved.username == original.username

    loaded = store.get_user(
        original.username
    )

    assert loaded is not None

    assert loaded.user_id == saved.user_id

    assert loaded.username == original.username

    assert loaded.created_at == original.created_at

    assert (
        loaded.password_record.algorithm
        == original.password_record.algorithm
    )

    assert (
        loaded.password_record.salt
        == original.password_record.salt
    )

    assert (
        loaded.password_record.memory_cost
        == original.password_record.memory_cost
    )

    assert (
        loaded.password_record.time_cost
        == original.password_record.time_cost
    )

    assert (
        loaded.password_record.parallelism
        == original.password_record.parallelism
    )

    assert (
        loaded.password_record.hash_length
        == original.password_record.hash_length
    )

    assert (
        loaded.password_record.version
        == original.password_record.version
    )

    assert not hasattr(
        loaded.password_record,
        "password_hash",
    )

    assert (
        loaded.login_public_key
        == original.login_public_key
    )

    assert len(
        loaded.login_public_key
    ) == 32

    assert (
        loaded.x25519_public_key
        == original.x25519_public_key
    )

    assert (
        loaded.ed25519_public_key
        == original.ed25519_public_key
    )

    assert (
        loaded.encrypted_private_key_bundle
        == original.encrypted_private_key_bundle
    )


def test_username_exists(
    tmp_path,
):

    store = UserStore(
        tmp_path / "users.db"
    )

    assert not store.username_exists(
        "Layla"
    )

    store.create_user(
        make_user("Layla")
    )

    assert store.username_exists(
        "Layla"
    )

    assert not store.username_exists(
        "Nobody"
    )


def test_get_public_keys(
    tmp_path,
):

    store = UserStore(
        tmp_path / "users.db"
    )

    user = make_user(
        "Layla"
    )

    store.create_user(
        user
    )

    keys = store.get_public_keys(
        "Layla"
    )

    assert keys is not None

    x25519_key, ed25519_key = keys

    assert (
        x25519_key
        == user.x25519_public_key
    )

    assert (
        ed25519_key
        == user.ed25519_public_key
    )


def test_get_login_public_key(
    tmp_path,
):
    
    store = UserStore(
        tmp_path / "users.db"
    )

    user = make_user(
        "Layla"
    )

    store.create_user(
        user
    )

    login_key = store.get_login_public_key(
        "Layla"
    )

    assert (
        login_key
        == user.login_public_key
    )

    assert len(
        login_key
    ) == 32


def test_unknown_user_returns_none(
    tmp_path,
):

    store = UserStore(
        tmp_path / "users.db"
    )

    assert (
        store.get_user("Nobody")
        is None
    )

    assert (
        store.get_public_keys("Nobody")
        is None
    )

    assert (
        store.get_login_public_key("Nobody")
        is None
    )


def test_duplicate_username_is_rejected(
    tmp_path,
):

    store = UserStore(
        tmp_path / "users.db"
    )

    first = make_user(
        "Layla"
    )

    second = make_user(
        "Layla"
    )

    store.create_user(
        first
    )

    with pytest.raises(
        DuplicateUsernameError
    ):
        store.create_user(
            second
        )