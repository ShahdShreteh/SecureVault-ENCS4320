import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


KEY_SIZE = 32
FINGERPRINT_DOMAIN = b"SecureVault-TOFU-v1"


class TrustError(ValueError):
    pass


class KeyChangeDetected(TrustError):
    pass


@dataclass(frozen=True)
class TrustedPeer:
    username: str
    x25519_public_key: bytes
    ed25519_public_key: bytes
    fingerprint: str
    manually_verified: bool
    first_seen: str


def _validate_username(
    username: str,
) -> None:
    if not isinstance(username, str):
        raise TypeError(
            "username must be a string"
        )

    if not username.strip():
        raise TrustError(
            "username cannot be empty."
        )


def _validate_key(
    key: bytes,
    name: str,
) -> None:
    if not isinstance(key, bytes):
        raise TypeError(
            f"{name} must be bytes"
        )

    if len(key) != KEY_SIZE:
        raise TrustError(
            f"{name} must be exactly 32 bytes."
        )


def compute_fingerprint(
    username: str,
    x25519_public_key: bytes,
    ed25519_public_key: bytes,
) -> str:
    _validate_username(
        username
    )

    _validate_key(
        x25519_public_key,
        "x25519_public_key",
    )

    _validate_key(
        ed25519_public_key,
        "ed25519_public_key",
    )

    username_bytes = username.encode(
        "utf-8"
    )

    message = (
        FINGERPRINT_DOMAIN
        + len(username_bytes).to_bytes(
            4,
            "big",
        )
        + username_bytes
        + x25519_public_key
        + ed25519_public_key
    )

    digest = hashlib.sha256(
        message
    ).hexdigest().upper()

    return ":".join(
        digest[index:index + 4]
        for index in range(
            0,
            len(digest),
            4,
        )
    )


def verification_code(
    username: str,
    x25519_public_key: bytes,
    ed25519_public_key: bytes,
) -> str:
    fingerprint = compute_fingerprint(
        username,
        x25519_public_key,
        ed25519_public_key,
    )

    compact = fingerprint.replace(
        ":",
        "",
    )

    return " ".join(
        compact[index:index + 4]
        for index in range(
            0,
            24,
            4,
        )
    )


class TofuTrustStore:

    def __init__(
        self,
        database_path: str | Path,
    ) -> None:
        self.database_path = Path(
            database_path
        )

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._create_table()

    def _connect(
        self,
    ) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path
        )

        connection.row_factory = (
            sqlite3.Row
        )

        return connection

    def _create_table(
        self,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS trusted_peers (
                    username TEXT PRIMARY KEY,
                    x25519_public_key BLOB NOT NULL,
                    ed25519_public_key BLOB NOT NULL,
                    fingerprint TEXT NOT NULL,
                    manually_verified INTEGER NOT NULL DEFAULT 0,
                    first_seen TEXT NOT NULL
                )
                """
            )

    def get_peer(
        self,
        username: str,
    ) -> TrustedPeer | None:
        _validate_username(
            username
        )

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM trusted_peers
                WHERE username = ?
                """,
                (username,),
            ).fetchone()

        if row is None:
            return None

        return TrustedPeer(
            username=row["username"],
            x25519_public_key=bytes(
                row["x25519_public_key"]
            ),
            ed25519_public_key=bytes(
                row["ed25519_public_key"]
            ),
            fingerprint=row[
                "fingerprint"
            ],
            manually_verified=bool(
                row["manually_verified"]
            ),
            first_seen=row[
                "first_seen"
            ],
        )

    def observe_peer(
        self,
        username: str,
        x25519_public_key: bytes,
        ed25519_public_key: bytes,
    ) -> TrustedPeer:
        _validate_username(
            username
        )

        _validate_key(
            x25519_public_key,
            "x25519_public_key",
        )

        _validate_key(
            ed25519_public_key,
            "ed25519_public_key",
        )

        existing = self.get_peer(
            username
        )

        if existing is not None:
            if (
                existing.x25519_public_key
                != x25519_public_key
                or existing.ed25519_public_key
                != ed25519_public_key
            ):
                raise KeyChangeDetected(
                    f"Public key change detected for {username}."
                )

            return existing

        fingerprint = compute_fingerprint(
            username,
            x25519_public_key,
            ed25519_public_key,
        )

        first_seen = datetime.now(
            timezone.utc
        ).isoformat()

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO trusted_peers (
                    username,
                    x25519_public_key,
                    ed25519_public_key,
                    fingerprint,
                    manually_verified,
                    first_seen
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    x25519_public_key,
                    ed25519_public_key,
                    fingerprint,
                    0,
                    first_seen,
                ),
            )

        return self.get_peer(
            username
        )

    def mark_verified(
        self,
        username: str,
    ) -> TrustedPeer:
        peer = self.get_peer(
            username
        )

        if peer is None:
            raise TrustError(
                "Peer is not trusted yet."
            )

        with self._connect() as connection:
            connection.execute(
                """
                UPDATE trusted_peers
                SET manually_verified = 1
                WHERE username = ?
                """,
                (username,),
            )

        return self.get_peer(
            username
        )

    def verify_code(
        self,
        username: str,
        code: str,
    ) -> bool:
        if not isinstance(code, str):
            raise TypeError(
                "code must be a string"
            )

        peer = self.get_peer(
            username
        )

        if peer is None:
            return False

        expected = verification_code(
            peer.username,
            peer.x25519_public_key,
            peer.ed25519_public_key,
        )

        normalized_expected = (
            expected
            .replace(" ", "")
            .upper()
        )

        normalized_received = (
            code
            .replace(" ", "")
            .replace("-", "")
            .upper()
        )

        return (
            normalized_expected
            == normalized_received
        )