from src.auth.session import SessionManager


def test_create_validate_and_logout():
    sessions = SessionManager()
    token = sessions.create("Layla")
    assert sessions.validate(token) == "Layla"
    assert sessions.logout(token)
    assert sessions.validate(token) is None


def test_random_token_is_rejected():
    sessions = SessionManager()
    assert sessions.validate("not-a-real-token") is None
