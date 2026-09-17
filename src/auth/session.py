"""Short-lived, in-memory login sessions."""

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from . import config


@dataclass
class _Session:
    username: str
    expires_at: datetime


class SessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, _Session] = {}

    def create(self, username: str) -> str:
        token = secrets.token_urlsafe(config.SESSION_TOKEN_LENGTH)
        expires = datetime.now(timezone.utc) + timedelta(
            seconds=config.SESSION_LIFETIME_SECONDS
        )
        self._sessions[token] = _Session(username=username, expires_at=expires)
        return token

    def validate(self, token: str) -> str | None:
        session = self._sessions.get(token)
        if session is None:
            return None
        if datetime.now(timezone.utc) >= session.expires_at:
            self._sessions.pop(token, None)
            return None
        return session.username

    def logout(self, token: str) -> bool:
        return self._sessions.pop(token, None) is not None
