from datetime import datetime, timezone

import pytest

from src.auth.errors import DuplicateUsernameError
from src.auth.models import UserRecord
from src.auth.password import create_password_record
from src.auth.user_store import UserStore


def make_user(username="Layla"):
    return UserRecord(
        user_id=None,
        username=username,
        password_record=create_password_record("Correct-Horse-2026"),
        x25519_public_key=b"x" * 32,
        ed25519_public_key=b"e" * 32,
        encrypted_private_key_bundle=b"encrypted-private-key-bundle",
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def test_store_and_reload_user(tmp_path):
    store = UserStore(tmp_path / "users.db")
    saved = store.create_user(make_user())
    loaded = store.get_user("Layla")
    assert saved.user_id is not None
    assert loaded is not None
    assert loaded.username == "Layla"
    assert loaded.password_record.password_hash == saved.password_record.password_hash


def test_duplicate_username_is_rejected(tmp_path):
    store = UserStore(tmp_path / "users.db")
    store.create_user(make_user())
    with pytest.raises(DuplicateUsernameError):
        store.create_user(make_user())
