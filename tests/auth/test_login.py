from src.auth.login import client_create_proof
from src.auth.signup import prepare_signup


def add_layla(service):
    prepared = prepare_signup(
        "Layla",
        "Correct-Horse-2026",
        b"x" * 32,
        b"e" * 32,
        b"encrypted-private-key-bundle",
    )
    assert service.signup(prepared).success


def test_correct_login_creates_session(service):
    add_layla(service)
    challenge = service.begin_login("Layla")
    proof = client_create_proof("Correct-Horse-2026", challenge)
    result = service.finish_login(challenge.challenge_id, proof)
    assert result.success
    assert result.session_token is not None
    assert service.validate_session(result.session_token) == "Layla"


def test_wrong_password_and_unknown_user_have_same_public_error(service):
    add_layla(service)
    wrong = service.begin_login("Layla")
    wrong_result = service.finish_login(
        wrong.challenge_id, client_create_proof("Wrong-Password-2026", wrong)
    )
    unknown = service.begin_login("Nobody")
    unknown_result = service.finish_login(
        unknown.challenge_id, client_create_proof("Wrong-Password-2026", unknown)
    )
    assert not wrong_result.success
    assert not unknown_result.success
    assert wrong_result.error_code == unknown_result.error_code
    assert wrong_result.message == unknown_result.message


def test_challenge_cannot_be_replayed(service):
    add_layla(service)
    challenge = service.begin_login("Layla")
    proof = client_create_proof("Correct-Horse-2026", challenge)
    assert service.finish_login(challenge.challenge_id, proof).success
    assert not service.finish_login(challenge.challenge_id, proof).success


def test_unknown_username_gets_stable_fake_salt_during_server_run(service):
    first = service.begin_login("Nobody")
    second = service.begin_login("Nobody")
    assert first.salt == second.salt
