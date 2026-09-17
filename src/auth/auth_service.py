"""Simple facade used by the server and demo."""

from pathlib import Path

from . import config
from .errors import DuplicateUsernameError, ValidationError
from .login import LoginManager
from .models import AuthResult, LoginChallenge, PreparedSignup, UserRecord
from .session import SessionManager
from .signup import register_prepared
from .user_store import UserStore


class AuthService:
    def __init__(self, database_path: str | Path = config.DATABASE_PATH) -> None:
        self.store = UserStore(database_path)
        self.sessions = SessionManager()
        self.login_manager = LoginManager(self.store, self.sessions)

    def signup(self, prepared: PreparedSignup) -> AuthResult:
        try:
            user = register_prepared(self.store, prepared)
        except DuplicateUsernameError:
            return AuthResult(False, "USERNAME_TAKEN", "Username is already registered.")
        except ValidationError as error:
            return AuthResult(False, "INVALID_SIGNUP", str(error))
        return AuthResult(True, message="Registration successful.", username=user.username)

    def begin_login(self, username: str) -> LoginChallenge:
        return self.login_manager.begin(username)

    def finish_login(self, challenge_id: str, proof: bytes) -> AuthResult:
        return self.login_manager.finish(challenge_id, proof)

    def validate_session(self, token: str) -> str | None:
        return self.sessions.validate(token)

    def logout(self, token: str) -> bool:
        return self.sessions.logout(token)

    def get_user(self, username: str) -> UserRecord | None:
        return self.store.get_user(username)
