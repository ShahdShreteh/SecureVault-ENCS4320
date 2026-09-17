"""Authentication exceptions and public error codes."""

INVALID_USERNAME = "INVALID_USERNAME"
WEAK_PASSWORD = "WEAK_PASSWORD"
USERNAME_TAKEN = "USERNAME_TAKEN"
AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
INVALID_CHALLENGE = "INVALID_CHALLENGE"
INVALID_SESSION = "INVALID_SESSION"


class AuthenticationError(Exception):
    """Base error for the authentication component."""


class ValidationError(AuthenticationError):
    """Input does not satisfy the local validation rules."""


class DuplicateUsernameError(AuthenticationError):
    """The requested username already exists."""
