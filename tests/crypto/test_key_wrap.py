from dataclasses import replace

import pytest

from src.crypto.key_wrap import (
    DocumentKeys,
    KeyWrapError,
    KeyWrapIntegrityError,
    generate_document_keys,
    unwrap_document_keys,
    wrap_document_keys,
)
from src.crypto.x25519 import (
    generate_keypair,
)


def make_users():

    alice_private, alice_public = (
        generate_keypair()
    )

    bob_private, bob_public = (
        generate_keypair()
    )

    return (
        alice_private,
        alice_public,
        bob_private,
        bob_public,
    )


def test_generate_document_keys():

    keys = generate_document_keys()

    assert len(
        keys.encryption_key
    ) == 32

    assert len(
        keys.mac_key
    ) == 32

    assert (
        keys.encryption_key
        != keys.mac_key
    )


def test_generated_document_keys_are_fresh():

    first = generate_document_keys()

    second = generate_document_keys()

    assert (
        first.encryption_key
        != second.encryption_key
    )

    assert (
        first.mac_key
        != second.mac_key
    )


def test_wrap_and_unwrap_round_trip():

    (
        alice_private,
        alice_public,
        bob_private,
        bob_public,
    ) = make_users()

    original = (
        generate_document_keys()
    )

    wrapped = wrap_document_keys(
        original,
        alice_private,
        bob_public,
        "Alice",
        "Bob",
        "doc-001",
    )

    recovered = (
        unwrap_document_keys(
            wrapped,
            bob_private,
            alice_public,
            "Alice",
            "Bob",
            "doc-001",
        )
    )

    assert (
        recovered
        == original
    )


def test_wrap_uses_fresh_salt():

    (
        alice_private,
        _,
        _,
        bob_public,
    ) = make_users()

    keys = generate_document_keys()

    first = wrap_document_keys(
        keys,
        alice_private,
        bob_public,
        "Alice",
        "Bob",
        "doc-001",
    )

    second = wrap_document_keys(
        keys,
        alice_private,
        bob_public,
        "Alice",
        "Bob",
        "doc-001",
    )

    assert (
        first.kdf_salt
        != second.kdf_salt
    )

    assert (
        first.iv
        != second.iv
    )

    assert (
        first.ciphertext
        != second.ciphertext
    )


def test_wrong_recipient_private_key_fails():

    (
        alice_private,
        alice_public,
        _,
        bob_public,
    ) = make_users()

    mallory_private, _ = (
        generate_keypair()
    )

    keys = generate_document_keys()

    wrapped = wrap_document_keys(
        keys,
        alice_private,
        bob_public,
        "Alice",
        "Bob",
        "doc-001",
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        unwrap_document_keys(
            wrapped,
            mallory_private,
            alice_public,
            "Alice",
            "Bob",
            "doc-001",
        )


def test_wrong_sender_public_key_fails():

    (
        alice_private,
        _,
        bob_private,
        bob_public,
    ) = make_users()

    _, mallory_public = (
        generate_keypair()
    )

    keys = generate_document_keys()

    wrapped = wrap_document_keys(
        keys,
        alice_private,
        bob_public,
        "Alice",
        "Bob",
        "doc-001",
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        unwrap_document_keys(
            wrapped,
            bob_private,
            mallory_public,
            "Alice",
            "Bob",
            "doc-001",
        )


def test_wrong_sender_username_fails():

    (
        alice_private,
        alice_public,
        bob_private,
        bob_public,
    ) = make_users()

    keys = generate_document_keys()

    wrapped = wrap_document_keys(
        keys,
        alice_private,
        bob_public,
        "Alice",
        "Bob",
        "doc-001",
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        unwrap_document_keys(
            wrapped,
            bob_private,
            alice_public,
            "Mallory",
            "Bob",
            "doc-001",
        )


def test_wrong_recipient_username_fails():

    (
        alice_private,
        alice_public,
        bob_private,
        bob_public,
    ) = make_users()

    keys = generate_document_keys()

    wrapped = wrap_document_keys(
        keys,
        alice_private,
        bob_public,
        "Alice",
        "Bob",
        "doc-001",
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        unwrap_document_keys(
            wrapped,
            bob_private,
            alice_public,
            "Alice",
            "Mallory",
            "doc-001",
        )


def test_wrong_document_id_fails():

    (
        alice_private,
        alice_public,
        bob_private,
        bob_public,
    ) = make_users()

    keys = generate_document_keys()

    wrapped = wrap_document_keys(
        keys,
        alice_private,
        bob_public,
        "Alice",
        "Bob",
        "doc-001",
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        unwrap_document_keys(
            wrapped,
            bob_private,
            alice_public,
            "Alice",
            "Bob",
            "doc-999",
        )


def test_ciphertext_tampering_fails():

    (
        alice_private,
        alice_public,
        bob_private,
        bob_public,
    ) = make_users()

    keys = generate_document_keys()

    wrapped = wrap_document_keys(
        keys,
        alice_private,
        bob_public,
        "Alice",
        "Bob",
        "doc-001",
    )

    modified = bytearray(
        wrapped.ciphertext
    )

    modified[0] ^= 1

    tampered = replace(
        wrapped,
        ciphertext=bytes(
            modified
        ),
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        unwrap_document_keys(
            tampered,
            bob_private,
            alice_public,
            "Alice",
            "Bob",
            "doc-001",
        )


def test_metadata_tampering_fails():

    (
        alice_private,
        alice_public,
        bob_private,
        bob_public,
    ) = make_users()

    keys = generate_document_keys()

    wrapped = wrap_document_keys(
        keys,
        alice_private,
        bob_public,
        "Alice",
        "Bob",
        "doc-001",
    )

    tampered = replace(
        wrapped,
        metadata=b"{}",
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        unwrap_document_keys(
            tampered,
            bob_private,
            alice_public,
            "Alice",
            "Bob",
            "doc-001",
        )


def test_tag_tampering_fails():

    (
        alice_private,
        alice_public,
        bob_private,
        bob_public,
    ) = make_users()

    keys = generate_document_keys()

    wrapped = wrap_document_keys(
        keys,
        alice_private,
        bob_public,
        "Alice",
        "Bob",
        "doc-001",
    )

    modified = bytearray(
        wrapped.tag
    )

    modified[0] ^= 1

    tampered = replace(
        wrapped,
        tag=bytes(modified),
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        unwrap_document_keys(
            tampered,
            bob_private,
            alice_public,
            "Alice",
            "Bob",
            "doc-001",
        )


def test_salt_tampering_fails():

    (
        alice_private,
        alice_public,
        bob_private,
        bob_public,
    ) = make_users()

    keys = generate_document_keys()

    wrapped = wrap_document_keys(
        keys,
        alice_private,
        bob_public,
        "Alice",
        "Bob",
        "doc-001",
    )

    modified = bytearray(
        wrapped.kdf_salt
    )

    modified[0] ^= 1

    tampered = replace(
        wrapped,
        kdf_salt=bytes(modified),
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        unwrap_document_keys(
            tampered,
            bob_private,
            alice_public,
            "Alice",
            "Bob",
            "doc-001",
        )


def test_invalid_document_key_length():

    (
        alice_private,
        _,
        _,
        bob_public,
    ) = make_users()

    keys = DocumentKeys(
        encryption_key=b"K" * 16,
        mac_key=b"M" * 32,
    )

    with pytest.raises(
        KeyWrapError
    ):
        wrap_document_keys(
            keys,
            alice_private,
            bob_public,
            "Alice",
            "Bob",
            "doc-001",
        )


def test_empty_document_id_rejected():

    (
        alice_private,
        _,
        _,
        bob_public,
    ) = make_users()

    keys = generate_document_keys()

    with pytest.raises(
        KeyWrapError
    ):
        wrap_document_keys(
            keys,
            alice_private,
            bob_public,
            "Alice",
            "Bob",
            "",
        )