"""SQLite credential storage. Passwords and plaintext private keys are never stored."""

import sqlite3
from pathlib import Path
from typing import Optional

from .errors import DuplicateUsernameError
from .models import PasswordRecord, UserRecord


class UserStore:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._create_table()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _create_table(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    algorithm TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    memory_cost INTEGER NOT NULL,
                    time_cost INTEGER NOT NULL,
                    parallelism INTEGER NOT NULL,
                    hash_length INTEGER NOT NULL,
                    version INTEGER NOT NULL,
                    x25519_public_key BLOB NOT NULL,
                    ed25519_public_key BLOB NOT NULL,
                    encrypted_private_key_bundle BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    def create_user(self, user: UserRecord) -> UserRecord:
        password = user.password_record
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO users (
                        username, algorithm, salt, password_hash,
                        memory_cost, time_cost, parallelism, hash_length, version,
                        x25519_public_key, ed25519_public_key,
                        encrypted_private_key_bundle, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user.username,
                        password.algorithm,
                        password.salt,
                        password.password_hash,
                        password.memory_cost,
                        password.time_cost,
                        password.parallelism,
                        password.hash_length,
                        password.version,
                        user.x25519_public_key,
                        user.ed25519_public_key,
                        user.encrypted_private_key_bundle,
                        user.created_at,
                    ),
                )
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError as error:
            raise DuplicateUsernameError("Username already exists.") from error
        return UserRecord(**{**user.__dict__, "user_id": user_id})

    def get_user(self, username: str) -> Optional[UserRecord]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        if row is None:
            return None
        password = PasswordRecord(
            algorithm=row["algorithm"],
            salt=bytes(row["salt"]),
            password_hash=bytes(row["password_hash"]),
            memory_cost=row["memory_cost"],
            time_cost=row["time_cost"],
            parallelism=row["parallelism"],
            hash_length=row["hash_length"],
            version=row["version"],
        )
        return UserRecord(
            user_id=row["user_id"],
            username=row["username"],
            password_record=password,
            x25519_public_key=bytes(row["x25519_public_key"]),
            ed25519_public_key=bytes(row["ed25519_public_key"]),
            encrypted_private_key_bundle=bytes(row["encrypted_private_key_bundle"]),
            created_at=row["created_at"],
        )

    def username_exists(self, username: str) -> bool:
        return self.get_user(username) is not None

    def get_public_keys(self, username: str) -> Optional[tuple[bytes, bytes]]:
        user = self.get_user(username)
        if user is None:
            return None
        return user.x25519_public_key, user.ed25519_public_key
