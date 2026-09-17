"""Challenge-response login with identical public failures."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from . import config
from .errors import ValidationError
from .login_key import (
    compute_shared_secret,
    generate_ephemeral_x25519_keypair,
    login_private_key_from_secret,
    login_public_key_from_private,
)
from .models import (
    AuthResult,
    LoginChallenge,
    PasswordRecord,
)
from .password import derive_for_challenge
from .proof import (
    MacFunction,
    create_login_proof,
    standard_library_hmac,
)
from .session import SessionManager
from .user_store import UserStore


@dataclass
class _PendingLogin:

    challenge: LoginChallenge

    login_public_key: bytes

    server_ephemeral_private_key: X25519PrivateKey

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
        self._dummy_secret = self._load_or_create_dummy_secret()

    def _load_or_create_dummy_secret(self) -> bytes:

        path = Path(config.DUMMY_SECRET_PATH)

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if path.exists():

            secret = path.read_bytes()

            if len(secret) != 32:
                raise RuntimeError(
                    "Invalid dummy login secret file."
                )

            return secret

        secret = secrets.token_bytes(32)

        try:
           
            with path.open("xb") as file:
                file.write(secret)

            return secret

        except FileExistsError:

            stored_secret = path.read_bytes()

            if len(stored_secret) != 32:
                raise RuntimeError(
                    "Invalid dummy login secret file."
                )

            return stored_secret

    def _fake_record(
        self,
        username: str,
    ) -> PasswordRecord:

        encoded_username = username.encode(
            "utf-8",
            errors="replace",
        )

        salt = hmac.new(
            self._dummy_secret,
            b"SecureVault-Fake-Salt:"
            + encoded_username,
            hashlib.sha256,
        ).digest()[: config.ARGON2_SALT_LENGTH]

        return PasswordRecord(
            algorithm=config.ARGON2_ALGORITHM,
            salt=salt,
            memory_cost=config.ARGON2_MEMORY_COST,
            time_cost=config.ARGON2_TIME_COST,
            parallelism=config.ARGON2_PARALLELISM,
            hash_length=config.ARGON2_HASH_LENGTH,
            version=config.ARGON2_VERSION,
        )

    def _fake_login_public_key(
        self,
        username: str,
    ) -> bytes:

        encoded_username = username.encode(
            "utf-8",
            errors="replace",
        )

        fake_private_bytes = hmac.new(
            self._dummy_secret,
            b"SecureVault-Fake-Login-Key:"
            + encoded_username,
            hashlib.sha256,
        ).digest()

        fake_private_key = (
            X25519PrivateKey.from_private_bytes(
                fake_private_bytes
            )
        )

        return login_public_key_from_private(
            fake_private_key
        )

    def begin(
        self,
        username: str,
    ) -> LoginChallenge:
        
        user = self.store.get_user(username)

        if user is not None:

            password_record = user.password_record

            login_public_key = (
                user.login_public_key
            )

            account_exists = True

        else:

            password_record = self._fake_record(
                username
            )

            login_public_key = (
                self._fake_login_public_key(
                    username
                )
            )

            account_exists = False


        (
            server_private_key,
            server_public_key,
        ) = generate_ephemeral_x25519_keypair()

        challenge_id = secrets.token_hex(16)

        nonce = secrets.token_bytes(
            config.LOGIN_CHALLENGE_LENGTH
        )

        challenge = LoginChallenge(
            challenge_id=challenge_id,
            username=username,
            nonce=nonce,
            salt=password_record.salt,
            memory_cost=(
                password_record.memory_cost
            ),
            time_cost=(
                password_record.time_cost
            ),
            parallelism=(
                password_record.parallelism
            ),
            hash_length=(
                password_record.hash_length
            ),
            version=password_record.version,
            server_ephemeral_public_key=(
                server_public_key
            ),
        )

        self._pending[challenge_id] = (
            _PendingLogin(
                challenge=challenge,
                login_public_key=(
                    login_public_key
                ),
                server_ephemeral_private_key=(
                    server_private_key
                ),
                account_exists=(
                    account_exists
                ),
                expires_at=(
                    datetime.now(
                        timezone.utc
                    )
                    + timedelta(
                        seconds=(
                            config
                            .LOGIN_CHALLENGE_LIFETIME_SECONDS
                        )
                    )
                ),
            )
        )

        return challenge


    def finish(
        self,
        challenge_id: str,
        proof: bytes,
    ) -> AuthResult:

        pending = self._pending.pop(
            challenge_id,
            None,
        )

        failure = AuthResult(
            success=False,
            error_code="AUTHENTICATION_FAILED",
            message="Authentication failed.",
        )

        if pending is None:
            return failure

        if (
            datetime.now(timezone.utc)
            >= pending.expires_at
        ):
            return failure
        
        if not isinstance(proof, bytes):
            return failure

        try:
            shared_secret = compute_shared_secret(
                pending.server_ephemeral_private_key,
                pending.login_public_key,
            )

            expected_proof = (
                create_login_proof(
                    shared_secret,
                    pending.challenge,
                    self.make_mac,
                )
            )

        except (
            ValidationError,
            ValueError,
            TypeError,
        ):

            return failure


        proof_matches = hmac.compare_digest(
            expected_proof,
            proof,
        )

        if not proof_matches:
            return failure

        if not pending.account_exists:
            return failure

        token = self.sessions.create(
            pending.challenge.username
        )

        return AuthResult(
            success=True,
            message="Login successful.",
            username=(
                pending.challenge.username
            ),
            session_token=token,
        )

def client_create_proof(
    password: str,
    challenge: LoginChallenge,
    make_mac: MacFunction = standard_library_hmac,
) -> bytes:

    password_secret = derive_for_challenge(
        password,
        challenge,
    )

    login_private_key = (
        login_private_key_from_secret(
            password_secret
        )
    )

    shared_secret = compute_shared_secret(
        login_private_key,
        challenge.server_ephemeral_public_key,
    )

    return create_login_proof(
        shared_secret,
        challenge,
        make_mac,
    )