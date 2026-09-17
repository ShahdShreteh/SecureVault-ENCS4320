from src.auth.signup import prepare_signup


def prepared(username, password="Correct-Horse-2026"):
    return prepare_signup(
        username,
        password,
        b"x" * 32,
        b"e" * 32,
        b"encrypted-private-key-bundle",
    )


def test_signup_succeeds(service):
    result = service.signup(prepared("Layla"))
    assert result.success
    assert service.get_user("Layla") is not None


def test_duplicate_signup_fails(service):
    assert service.signup(prepared("Layla")).success
    result = service.signup(prepared("Layla"))
    assert not result.success
    assert result.error_code == "USERNAME_TAKEN"
