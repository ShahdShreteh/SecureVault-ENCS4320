"""Tests for SecureVault Argon2id password processing."""

import pytest

from src.auth import config
from src.auth.errors import ValidationError
from src.auth.models import LoginChallenge
from src.auth.password import (
    create_password_record,
    derive_for_challenge,
    derive_password_secret,
)

TEST_PASSWORD = "SecureVault-Test-Password-2026!"

WRONG_PASSWORD = "SecureVault-Wrong-Password-2026!"


def test_create_password_record_uses_argon2id():

    record = create_password_record(TEST_PASSWORD)

    assert record.algorithm == config.ARGON2_ALGORITHM

    assert record.memory_cost == config.ARGON2_MEMORY_COST
    assert record.time_cost == config.ARGON2_TIME_COST
    assert record.parallelism == config.ARGON2_PARALLELISM
    assert record.hash_length == config.ARGON2_HASH_LENGTH
    assert record.version == config.ARGON2_VERSION


def test_create_password_record_generates_random_salt():

    first = create_password_record(TEST_PASSWORD)
    second = create_password_record(TEST_PASSWORD)

    assert first.salt != second.salt

    assert len(first.salt) == config.ARGON2_SALT_LENGTH
    assert len(second.salt) == config.ARGON2_SALT_LENGTH


def test_same_password_and_same_salt_produce_same_secret():

    salt = b"\x01" * config.ARGON2_SALT_LENGTH

    first_record = create_password_record(
        TEST_PASSWORD,
        salt=salt,
    )

    second_record = create_password_record(
        TEST_PASSWORD,
        salt=salt,
    )

    first_secret = derive_password_secret(
        TEST_PASSWORD,
        first_record,
    )

    second_secret = derive_password_secret(
        TEST_PASSWORD,
        second_record,
    )

    assert first_secret == second_secret


def test_different_passwords_produce_different_secrets():

    salt = b"\x02" * config.ARGON2_SALT_LENGTH

    record = create_password_record(
        TEST_PASSWORD,
        salt=salt,
    )

    correct_secret = derive_password_secret(
        TEST_PASSWORD,
        record,
    )

    wrong_secret = derive_password_secret(
        WRONG_PASSWORD,
        record,
    )

    assert correct_secret != wrong_secret


def test_different_salts_produce_different_secrets():

    first_record = create_password_record(
        TEST_PASSWORD,
        salt=b"\x03" * config.ARGON2_SALT_LENGTH,
    )

    second_record = create_password_record(
        TEST_PASSWORD,
        salt=b"\x04" * config.ARGON2_SALT_LENGTH,
    )

    first_secret = derive_password_secret(
        TEST_PASSWORD,
        first_record,
    )

    second_secret = derive_password_secret(
        TEST_PASSWORD,
        second_record,
    )

    assert first_secret != second_secret


def test_derived_secret_has_expected_length():

    record = create_password_record(TEST_PASSWORD)

    secret = derive_password_secret(
        TEST_PASSWORD,
        record,
    )

    assert isinstance(secret, bytes)

    assert len(secret) == config.ARGON2_HASH_LENGTH


def test_password_record_does_not_store_password_hash():

    record = create_password_record(TEST_PASSWORD)

    assert not hasattr(record, "password_hash")


def test_explicit_valid_salt_is_preserved():

    salt = b"\x05" * config.ARGON2_SALT_LENGTH

    record = create_password_record(
        TEST_PASSWORD,
        salt=salt,
    )

    assert record.salt == salt


def test_too_short_salt_is_rejected():

    short_salt = b"12345678"

    with pytest.raises(ValidationError):
        create_password_record(
            TEST_PASSWORD,
            salt=short_salt,
        )


def test_derive_for_challenge_matches_password_record_derivation():

    record = create_password_record(TEST_PASSWORD)

    challenge = LoginChallenge(
        challenge_id="test-challenge-001",
        username="layla",
        nonce=b"\x10" * config.LOGIN_CHALLENGE_LENGTH,

        salt=record.salt,

        memory_cost=record.memory_cost,
        time_cost=record.time_cost,
        parallelism=record.parallelism,
        hash_length=record.hash_length,
        version=record.version,

        server_ephemeral_public_key=b"\x20" * 32,
    )

    expected = derive_password_secret(
        TEST_PASSWORD,
        record,
    )

    actual = derive_for_challenge(
        TEST_PASSWORD,
        challenge,
    )

    assert actual == expected


def test_wrong_password_for_challenge_produces_different_secret():

    record = create_password_record(TEST_PASSWORD)

    challenge = LoginChallenge(
        challenge_id="test-challenge-002",
        username="layla",
        nonce=b"\x11" * config.LOGIN_CHALLENGE_LENGTH,

        salt=record.salt,

        memory_cost=record.memory_cost,
        time_cost=record.time_cost,
        parallelism=record.parallelism,
        hash_length=record.hash_length,
        version=record.version,

        server_ephemeral_public_key=b"\x21" * 32,
    )

    correct_secret = derive_for_challenge(
        TEST_PASSWORD,
        challenge,
    )

    wrong_secret = derive_for_challenge(
        WRONG_PASSWORD,
        challenge,
    )

    assert correct_secret != wrong_secret