from dataclasses import replace

import pytest

from src.crypto.sharing import (
    MetadataBindingError,
    ProducerVerificationError,
    SharedDocumentError,
    create_shared_document,
    open_shared_document,
)
from src.crypto.signatures import (
    generate_ed25519_keypair,
)
from src.crypto.x25519 import (
    generate_keypair,
)
from src.crypto.key_wrap import (
    KeyWrapIntegrityError,
)
from src.crypto.document_crypto import (
    IntegrityError,
)


def make_users():

    alice_x_private, alice_x_public = (
        generate_keypair()
    )

    bob_x_private, bob_x_public = (
        generate_keypair()
    )

    (
        alice_ed_private,
        alice_ed_public,
    ) = generate_ed25519_keypair()

    (
        bob_ed_private,
        bob_ed_public,
    ) = generate_ed25519_keypair()

    return {
        "alice_x_private": alice_x_private,
        "alice_x_public": alice_x_public,
        "bob_x_private": bob_x_private,
        "bob_x_public": bob_x_public,
        "alice_ed_private": alice_ed_private,
        "alice_ed_public": alice_ed_public,
        "bob_ed_private": bob_ed_private,
        "bob_ed_public": bob_ed_public,
    }


def create_package(users):

    return create_shared_document(
        plaintext=(
            b"SecureVault confidential report."
        ),
        metadata={
            "filename": "report.pdf",
            "version": 1,
        },
        document_id="doc-001",
        sender_username="Alice",
        recipient_username="Bob",
        sender_x25519_private_key=(
            users["alice_x_private"]
        ),
        sender_ed25519_private_key=(
            users["alice_ed_private"]
        ),
        recipient_x25519_public_key=(
            users["bob_x_public"]
        ),
    )


def test_complete_share_round_trip():

    users = make_users()

    package = create_package(
        users
    )

    plaintext = (
        open_shared_document(
            package,
            "doc-001",
            "Alice",
            "Bob",
            users["bob_x_private"],
            users["alice_x_public"],
            users["alice_ed_public"],
        )
    )

    assert plaintext == (
        b"SecureVault confidential report."
    )


def test_plaintext_not_stored_in_ciphertext():

    users = make_users()

    plaintext = (
        b"SecureVault confidential report."
    )

    package = create_package(
        users
    )

    assert (
        plaintext
        not in package
        .encrypted_document
        .ciphertext
    )


def test_wrong_recipient_private_key_fails():

    users = make_users()

    package = create_package(
        users
    )

    mallory_private, _ = (
        generate_keypair()
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        open_shared_document(
            package,
            "doc-001",
            "Alice",
            "Bob",
            mallory_private,
            users["alice_x_public"],
            users["alice_ed_public"],
        )


def test_wrong_sender_x25519_key_fails():

    users = make_users()

    package = create_package(
        users
    )

    _, mallory_public = (
        generate_keypair()
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        open_shared_document(
            package,
            "doc-001",
            "Alice",
            "Bob",
            users["bob_x_private"],
            mallory_public,
            users["alice_ed_public"],
        )


def test_wrong_sender_ed25519_key_fails():

    users = make_users()

    package = create_package(
        users
    )

    _, mallory_public = (
        generate_ed25519_keypair()
    )

    with pytest.raises(
        ProducerVerificationError
    ):
        open_shared_document(
            package,
            "doc-001",
            "Alice",
            "Bob",
            users["bob_x_private"],
            users["alice_x_public"],
            mallory_public,
        )


def test_wrong_document_id_fails():

    users = make_users()

    package = create_package(
        users
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        open_shared_document(
            package,
            "doc-999",
            "Alice",
            "Bob",
            users["bob_x_private"],
            users["alice_x_public"],
            users["alice_ed_public"],
        )


def test_wrong_sender_username_fails():

    users = make_users()

    package = create_package(
        users
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        open_shared_document(
            package,
            "doc-001",
            "Mallory",
            "Bob",
            users["bob_x_private"],
            users["alice_x_public"],
            users["alice_ed_public"],
        )


def test_wrong_recipient_username_fails():

    users = make_users()

    package = create_package(
        users
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        open_shared_document(
            package,
            "doc-001",
            "Alice",
            "Mallory",
            users["bob_x_private"],
            users["alice_x_public"],
            users["alice_ed_public"],
        )


def test_ciphertext_tampering_fails():

    users = make_users()

    package = create_package(
        users
    )

    ciphertext = bytearray(
        package
        .encrypted_document
        .ciphertext
    )

    ciphertext[0] ^= 1

    tampered_document = replace(
        package.encrypted_document,
        ciphertext=bytes(
            ciphertext
        ),
    )

    tampered_package = replace(
        package,
        encrypted_document=(
            tampered_document
        ),
    )

    with pytest.raises(
        IntegrityError
    ):
        open_shared_document(
            tampered_package,
            "doc-001",
            "Alice",
            "Bob",
            users["bob_x_private"],
            users["alice_x_public"],
            users["alice_ed_public"],
        )


def test_encrypted_metadata_tampering_fails():

    users = make_users()

    package = create_package(
        users
    )

    tampered_document = replace(
        package.encrypted_document,
        metadata=b"{}",
    )

    tampered_package = replace(
        package,
        encrypted_document=(
            tampered_document
        ),
    )

    with pytest.raises(
        IntegrityError
    ):
        open_shared_document(
            tampered_package,
            "doc-001",
            "Alice",
            "Bob",
            users["bob_x_private"],
            users["alice_x_public"],
            users["alice_ed_public"],
        )


def test_signature_tampering_fails():

    users = make_users()

    package = create_package(
        users
    )

    signature = bytearray(
        package.signature.signature
    )

    signature[0] ^= 1

    tampered_signature = replace(
        package.signature,
        signature=bytes(
            signature
        ),
    )

    tampered_package = replace(
        package,
        signature=tampered_signature,
    )

    with pytest.raises(
        ProducerVerificationError
    ):
        open_shared_document(
            tampered_package,
            "doc-001",
            "Alice",
            "Bob",
            users["bob_x_private"],
            users["alice_x_public"],
            users["alice_ed_public"],
        )


def test_signed_metadata_tampering_fails():

    users = make_users()

    package = create_package(
        users
    )

    tampered_signature = replace(
        package.signature,
        metadata=b"{}",
    )

    tampered_package = replace(
        package,
        signature=tampered_signature,
    )

    with pytest.raises(
        MetadataBindingError
    ):
        open_shared_document(
            tampered_package,
            "doc-001",
            "Alice",
            "Bob",
            users["bob_x_private"],
            users["alice_x_public"],
            users["alice_ed_public"],
        )


def test_wrapped_keys_tampering_fails():

    users = make_users()

    package = create_package(
        users
    )

    ciphertext = bytearray(
        package
        .wrapped_keys
        .ciphertext
    )

    ciphertext[0] ^= 1

    tampered_wrapped = replace(
        package.wrapped_keys,
        ciphertext=bytes(
            ciphertext
        ),
    )

    tampered_package = replace(
        package,
        wrapped_keys=(
            tampered_wrapped
        ),
    )

    with pytest.raises(
        KeyWrapIntegrityError
    ):
        open_shared_document(
            tampered_package,
            "doc-001",
            "Alice",
            "Bob",
            users["bob_x_private"],
            users["alice_x_public"],
            users["alice_ed_public"],
        )


def test_two_encryptions_are_different():

    users = make_users()

    first = create_package(
        users
    )

    second = create_package(
        users
    )

    assert (
        first.encrypted_document.iv
        != second.encrypted_document.iv
    )

    assert (
        first
        .encrypted_document
        .ciphertext
        != second
        .encrypted_document
        .ciphertext
    )

    assert (
        first.wrapped_keys.kdf_salt
        != second.wrapped_keys.kdf_salt
    )


def test_signature_metadata_matches_encrypted_metadata():

    users = make_users()

    package = create_package(
        users
    )

    assert (
        package.signature.metadata
        == package
        .encrypted_document
        .metadata
    )


def test_reserved_metadata_field_rejected():

    users = make_users()

    with pytest.raises(
        SharedDocumentError
    ):
        create_shared_document(
            plaintext=b"document",
            metadata={
                "filename": "test.txt",
                "owner": "Mallory",
            },
            document_id="doc-001",
            sender_username="Alice",
            recipient_username="Bob",
            sender_x25519_private_key=(
                users["alice_x_private"]
            ),
            sender_ed25519_private_key=(
                users["alice_ed_private"]
            ),
            recipient_x25519_public_key=(
                users["bob_x_public"]
            ),
        )