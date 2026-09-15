"""Challenge-response login with identical public failures."""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from . import config
from .models import AuthResult, LoginChallenge, PasswordRecord
from .password import derive_for_challenge
from .proof import MacFunction, create_login_proof, standard_library_hmac
from .session import SessionManager
from .user_store import UserStore


@dataclass
class _PendingLogin:
    challenge: LoginChallenge
    expected_verifier: bytes
    account_exists: bool
    expires_at: datetime


class LoginManager:
    def __init__(
        self,
        store: UserStore,
        sessions: SessionManager,
        make_mac: MacFunction = standard_library_hmac,
    ) -> None:
        self.store = store
        self.sessions = sessions
        self.make_mac = make_mac
        self._pending: dict[str, _PendingLogin] = {}
        # Produces stable-looking fake records for unknown usernames during this
        # server run, without storing a list of nonexistent accounts.
        self._dummy_secret = secrets.token_bytes(32)

    def _fake_record(self, username: str) -> PasswordRecord:
        encoded = username.encode("utf-8", errors="replace")
        salt = hmac.new(
            self._dummy_secret, b"fake-salt:" + encoded, hashlib.sha256
        ).digest()[: config.ARGON2_SALT_LENGTH]
        verifier = hmac.new(
            self._dummy_secret, b"fake-verifier:" + encoded, hashlib.sha256
        ).digest()[: config.ARGON2_HASH_LENGTH]
        return PasswordRecord(
            algorithm=config.ARGON2_ALGORITHM,
            salt=salt,
            password_hash=verifier,
            memory_cost=config.ARGON2_MEMORY_COST,
            time_cost=config.ARGON2_TIME_COST,
            parallelism=config.ARGON2_PARALLELISM,
            hash_length=config.ARGON2_HASH_LENGTH,
            version=config.ARGON2_VERSION,
        )

    def begin(self, username: str) -> LoginChallenge:
        user = self.store.get_user(username)
        record = user.password_record if user else self._fake_record(username)
        challenge_id = secrets.token_hex(16)
        challenge = LoginChallenge(
            challenge_id=challenge_id,
            username=username,
            nonce=secrets.token_bytes(config.LOGIN_CHALLENGE_LENGTH),
            salt=record.salt,
            memory_cost=record.memory_cost,
            time_cost=record.time_cost,
            parallelism=record.parallelism,
            hash_length=record.hash_length,
            version=record.version,
        )
        self._pending[challenge_id] = _PendingLogin(
            challenge=challenge,
            expected_verifier=record.password_hash,
            account_exists=user is not None,
            expires_at=datetime.now(timezone.utc)
            + timedelta(seconds=config.LOGIN_CHALLENGE_LIFETIME_SECONDS),
        )
        return challenge

    def finish(self, challenge_id: str, proof: bytes) -> AuthResult:
        pending = self._pending.pop(challenge_id, None)
        failure = AuthResult(
            success=False,
            error_code="AUTHENTICATION_FAILED",
            message="Authentication failed.",
        )
        if pending is None or datetime.now(timezone.utc) >= pending.expires_at:
            return failure
        expected = create_login_proof(
            pending.expected_verifier, pending.challenge, self.make_mac
        )
        if not pending.account_exists or not hmac.compare_digest(expected, proof):
            return failure
        token = self.sessions.create(pending.challenge.username)
        return AuthResult(
            success=True,
            message="Login successful.",
            username=pending.challenge.username,
            session_token=token,
        )


def client_create_proof(
    password: str,
    challenge: LoginChallenge,
    make_mac: MacFunction = standard_library_hmac,
) -> bytes:
    derived = derive_for_challenge(password, challenge)
    return create_login_proof(derived, challenge, make_mac)
