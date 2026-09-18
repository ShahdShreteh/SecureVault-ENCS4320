from dataclasses import replace

import pytest

from src.crypto.signatures import (
    ED25519_PRIVATE_KEY_SIZE,
    ED25519_PUBLIC_KEY_SIZE,
    ED25519_SIGNATURE_SIZE,
    SignatureError,
    derive_ed25519_public_key,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
    sign_document,
    verify_document_signature,
)


METADATA = {
    "document_id": "doc-001",
    "filename": "report.pdf",
    "owner": "Alice",
    "version": 1,
}


def test_rfc8032_vector():

    private_key = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60"
    )

    expected_public_key = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a"
    )

    expected_signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    )

    public_key = (
        derive_ed25519_public_key(
            private_key
        )
    )

    signature = ed25519_sign(
        private_key,
        b"",
    )

    assert (
        public_key
        == expected_public_key
    )

    assert (
        signature
        == expected_signature
    )


def test_generated_key_sizes():

    private_key, public_key = (
        generate_ed25519_keypair()
    )

    assert len(
        private_key
    ) == ED25519_PRIVATE_KEY_SIZE

    assert len(
        public_key
    ) == ED25519_PUBLIC_KEY_SIZE


def test_generated_keypairs_are_different():

    first_private, first_public = (
        generate_ed25519_keypair()
    )

    second_private, second_public = (
        generate_ed25519_keypair()
    )

    assert (
        first_private
        != second_private
    )

    assert (
        first_public
        != second_public
    )


def test_sign_and_verify_message():

    private_key, public_key = (
        generate_ed25519_keypair()
    )

    message = (
        b"SecureVault message"
    )

    signature = ed25519_sign(
        private_key,
        message,
    )

    assert ed25519_verify(
        public_key,
        message,
        signature,
    )


def test_signature_size():

    private_key, _ = (
        generate_ed25519_keypair()
    )

    signature = ed25519_sign(
        private_key,
        b"message",
    )

    assert len(
        signature
    ) == ED25519_SIGNATURE_SIZE


def test_ed25519_is_deterministic():

    private_key, _ = (
        generate_ed25519_keypair()
    )

    message = b"same-message"

    first = ed25519_sign(
        private_key,
        message,
    )

    second = ed25519_sign(
        private_key,
        message,
    )

    assert first == second


def test_modified_message_fails():

    private_key, public_key = (
        generate_ed25519_keypair()
    )

    signature = ed25519_sign(
        private_key,
        b"original",
    )

    assert not ed25519_verify(
        public_key,
        b"modified",
        signature,
    )


def test_modified_signature_fails():

    private_key, public_key = (
        generate_ed25519_keypair()
    )

    signature = bytearray(
        ed25519_sign(
            private_key,
            b"message",
        )
    )

    signature[0] ^= 1

    assert not ed25519_verify(
        public_key,
        b"message",
        bytes(signature),
    )


def test_wrong_public_key_fails():

    alice_private, _ = (
        generate_ed25519_keypair()
    )

    _, bob_public = (
        generate_ed25519_keypair()
    )

    signature = ed25519_sign(
        alice_private,
        b"message",
    )

    assert not ed25519_verify(
        bob_public,
        b"message",
        signature,
    )


def test_document_signature_round_trip():

    private_key, public_key = (
        generate_ed25519_keypair()
    )

    plaintext = (
        b"SecureVault confidential document"
    )

    proof = sign_document(
        plaintext,
        METADATA,
        private_key,
    )

    assert verify_document_signature(
        plaintext,
        proof,
        public_key,
    )


def test_document_content_tampering_fails():

    private_key, public_key = (
        generate_ed25519_keypair()
    )

    proof = sign_document(
        b"original document",
        METADATA,
        private_key,
    )

    assert not verify_document_signature(
        b"modified document",
        proof,
        public_key,
    )


def test_document_metadata_tampering_fails():

    private_key, public_key = (
        generate_ed25519_keypair()
    )

    proof = sign_document(
        b"document",
        METADATA,
        private_key,
    )

    tampered = replace(
        proof,
        metadata=(
            b'{"owner":"Mallory"}'
        ),
    )

    assert not verify_document_signature(
        b"document",
        tampered,
        public_key,
    )


def test_document_hash_tampering_fails():

    private_key, public_key = (
        generate_ed25519_keypair()
    )

    proof = sign_document(
        b"document",
        METADATA,
        private_key,
    )

    modified_hash = bytearray(
        proof.content_hash
    )

    modified_hash[0] ^= 1

    tampered = replace(
        proof,
        content_hash=bytes(
            modified_hash
        ),
    )

    assert not verify_document_signature(
        b"document",
        tampered,
        public_key,
    )


def test_document_signature_tampering_fails():

    private_key, public_key = (
        generate_ed25519_keypair()
    )

    proof = sign_document(
        b"document",
        METADATA,
        private_key,
    )

    modified = bytearray(
        proof.signature
    )

    modified[-1] ^= 1

    tampered = replace(
        proof,
        signature=bytes(
            modified
        ),
    )

    assert not verify_document_signature(
        b"document",
        tampered,
        public_key,
    )


def test_metadata_order_produces_same_signature():

    private_key, _ = (
        generate_ed25519_keypair()
    )

    first_metadata = {
        "owner": "Alice",
        "filename": "report.pdf",
        "version": 1,
    }

    second_metadata = {
        "version": 1,
        "filename": "report.pdf",
        "owner": "Alice",
    }

    first = sign_document(
        b"document",
        first_metadata,
        private_key,
    )

    second = sign_document(
        b"document",
        second_metadata,
        private_key,
    )

    assert (
        first.metadata
        == second.metadata
    )

    assert (
        first.signature
        == second.signature
    )


def test_invalid_private_key_length():

    with pytest.raises(
        SignatureError
    ):
        ed25519_sign(
            b"short",
            b"message",
        )


def test_invalid_public_key_length():

    with pytest.raises(
        SignatureError
    ):
        ed25519_verify(
            b"short",
            b"message",
            b"x" * 64,
        )