"""Tests for the SecureVault challenge-response login protocol."""

from src.auth import config
from src.auth.auth_service import AuthService
from src.auth.login import client_create_proof
from src.auth.proof import create_login_proof
from src.auth.signup import prepare_signup


TEST_USERNAME = "Layla"
TEST_PASSWORD = "Correct-Horse-2026"
WRONG_PASSWORD = "Wrong-Password-2026"


def add_layla(service):

    prepared = prepare_signup(
        TEST_USERNAME,
        TEST_PASSWORD,
        b"x" * 32,
        b"e" * 32,
        b"encrypted-private-key-bundle",
    )

    result = service.signup(prepared)

    assert result.success

    return result


def test_correct_login_creates_session(service):

    add_layla(service)

    challenge = service.begin_login(
        TEST_USERNAME
    )

    proof = client_create_proof(
        TEST_PASSWORD,
        challenge,
    )

    result = service.finish_login(
        challenge.challenge_id,
        proof,
    )

    assert result.success

    assert result.error_code is None

    assert result.username == TEST_USERNAME

    assert result.session_token is not None

    assert (
        service.validate_session(
            result.session_token
        )
        == TEST_USERNAME
    )


def test_wrong_password_is_rejected(service):

    add_layla(service)

    challenge = service.begin_login(
        TEST_USERNAME
    )

    proof = client_create_proof(
        WRONG_PASSWORD,
        challenge,
    )

    result = service.finish_login(
        challenge.challenge_id,
        proof,
    )

    assert not result.success

    assert (
        result.error_code
        == "AUTHENTICATION_FAILED"
    )

    assert (
        result.message
        == "Authentication failed."
    )

    assert result.session_token is None


def test_unknown_username_is_rejected(service):

    challenge = service.begin_login(
        "Nobody"
    )

    proof = client_create_proof(
        WRONG_PASSWORD,
        challenge,
    )

    result = service.finish_login(
        challenge.challenge_id,
        proof,
    )

    assert not result.success

    assert (
        result.error_code
        == "AUTHENTICATION_FAILED"
    )

    assert (
        result.message
        == "Authentication failed."
    )

    assert result.session_token is None


def test_wrong_password_and_unknown_user_have_same_public_error(
    service,
):

    add_layla(service)

    wrong_challenge = service.begin_login(
        TEST_USERNAME
    )

    wrong_proof = client_create_proof(
        WRONG_PASSWORD,
        wrong_challenge,
    )

    wrong_result = service.finish_login(
        wrong_challenge.challenge_id,
        wrong_proof,
    )

    unknown_challenge = service.begin_login(
        "Nobody"
    )

    unknown_proof = client_create_proof(
        WRONG_PASSWORD,
        unknown_challenge,
    )

    unknown_result = service.finish_login(
        unknown_challenge.challenge_id,
        unknown_proof,
    )

    assert not wrong_result.success
    assert not unknown_result.success

    assert (
        wrong_result.error_code
        == unknown_result.error_code
    )

    assert (
        wrong_result.message
        == unknown_result.message
    )

    assert wrong_result.session_token is None
    assert unknown_result.session_token is None


def test_challenge_cannot_be_replayed(service):

    add_layla(service)

    challenge = service.begin_login(
        TEST_USERNAME
    )

    proof = client_create_proof(
        TEST_PASSWORD,
        challenge,
    )

    first_result = service.finish_login(
        challenge.challenge_id,
        proof,
    )

    assert first_result.success

    replay_result = service.finish_login(
        challenge.challenge_id,
        proof,
    )

    assert not replay_result.success

    assert (
        replay_result.error_code
        == "AUTHENTICATION_FAILED"
    )

    assert (
        replay_result.message
        == "Authentication failed."
    )


def test_each_login_uses_fresh_challenge_nonce(service):

    add_layla(service)

    first = service.begin_login(
        TEST_USERNAME
    )

    second = service.begin_login(
        TEST_USERNAME
    )

    assert first.challenge_id != second.challenge_id

    assert first.nonce != second.nonce

    assert (
        len(first.nonce)
        == config.LOGIN_CHALLENGE_LENGTH
    )

    assert (
        len(second.nonce)
        == config.LOGIN_CHALLENGE_LENGTH
    )


def test_each_login_uses_fresh_server_ephemeral_key(service):

    add_layla(service)

    first = service.begin_login(
        TEST_USERNAME
    )

    second = service.begin_login(
        TEST_USERNAME
    )

    assert (
        first.server_ephemeral_public_key
        != second.server_ephemeral_public_key
    )

    assert (
        len(first.server_ephemeral_public_key)
        == 32
    )

    assert (
        len(second.server_ephemeral_public_key)
        == 32
    )


def test_unknown_username_gets_stable_fake_salt_during_server_run(
    service,
):

    first = service.begin_login(
        "Nobody"
    )

    second = service.begin_login(
        "Nobody"
    )

    assert first.salt == second.salt

    assert (
        len(first.salt)
        == config.ARGON2_SALT_LENGTH
    )


def test_unknown_username_fake_salt_survives_server_restart(
    tmp_path,
    monkeypatch,
):

    database_path = (
        tmp_path
        / "users.db"
    )

    dummy_secret_path = (
        tmp_path
        / "dummy_login_secret.bin"
    )

    monkeypatch.setattr(
        config,
        "DUMMY_SECRET_PATH",
        dummy_secret_path,
    )

    first_service = AuthService(
        database_path
    )

    first_challenge = (
        first_service.begin_login(
            "Nobody"
        )
    )

    first_salt = first_challenge.salt

    second_service = AuthService(
        database_path
    )

    second_challenge = (
        second_service.begin_login(
            "Nobody"
        )
    )

    second_salt = second_challenge.salt

    assert first_salt == second_salt


def test_stolen_database_record_cannot_be_used_as_login_secret(
    service,
):
    
    add_layla(service)

    stored_user = service.get_user(
        TEST_USERNAME
    )

    assert stored_user is not None

    assert not hasattr(
        stored_user.password_record,
        "password_hash",
    )

    # The database contains only the public login key.
    assert isinstance(
        stored_user.login_public_key,
        bytes,
    )

    assert (
        len(stored_user.login_public_key)
        == 32
    )

    challenge = service.begin_login(
        TEST_USERNAME
    )

    forged_proof = create_login_proof(
        stored_user.login_public_key,
        challenge,
    )

    result = service.finish_login(
        challenge.challenge_id,
        forged_proof,
    )

    assert not result.success

    assert (
        result.error_code
        == "AUTHENTICATION_FAILED"
    )

    assert (
        result.message
        == "Authentication failed."
    )

    assert result.session_token is None


def test_new_challenge_after_success_can_login_again(service):

    add_layla(service)

    first_challenge = service.begin_login(
        TEST_USERNAME
    )

    first_proof = client_create_proof(
        TEST_PASSWORD,
        first_challenge,
    )

    first_result = service.finish_login(
        first_challenge.challenge_id,
        first_proof,
    )

    assert first_result.success

    second_challenge = service.begin_login(
        TEST_USERNAME
    )

    second_proof = client_create_proof(
        TEST_PASSWORD,
        second_challenge,
    )

    second_result = service.finish_login(
        second_challenge.challenge_id,
        second_proof,
    )

    assert second_result.success

    assert (
        second_result.session_token
        is not None
    )

    assert (
        first_result.session_token
        != second_result.session_token
    )