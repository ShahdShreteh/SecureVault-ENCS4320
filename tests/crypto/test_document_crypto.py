from dataclasses import replace

import pytest

from src.crypto.document_crypto import (
    DocumentCryptoError,
    EncryptedDocument,
    IntegrityError,
    canonicalize_metadata,
    decrypt_document,
    encrypt_document,
    verify_document,
)


ENCRYPTION_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
    "102132435465768798a9bacbdcedfe0f"
)

MAC_KEY = bytes.fromhex(
    "ffeeddccbbaa99887766554433221100"
    "0ffedccbbaa998877665544332211001"
)

METADATA = {
    "document_id": "doc-001",
    "filename": "report.pdf",
    "owner": "Layla",
    "recipients": [
        "Omar",
        "Sara",
    ],
    "version": 1,
}


def test_encrypt_decrypt_round_trip():

    plaintext = (
        b"Confidential SecureVault document."
    )

    document = encrypt_document(
        plaintext,
        ENCRYPTION_KEY,
        MAC_KEY,
        METADATA,
    )

    recovered = decrypt_document(
        document,
        ENCRYPTION_KEY,
        MAC_KEY,
    )

    assert recovered == plaintext


def test_encryption_uses_fresh_iv():

    plaintext = b"same document"

    first = encrypt_document(
        plaintext,
        ENCRYPTION_KEY,
        MAC_KEY,
        METADATA,
    )

    second = encrypt_document(
        plaintext,
        ENCRYPTION_KEY,
        MAC_KEY,
        METADATA,
    )

    assert first.iv != second.iv

    assert (
        first.ciphertext
        != second.ciphertext
    )


def test_document_has_32_byte_tag():

    document = encrypt_document(
        b"hello",
        ENCRYPTION_KEY,
        MAC_KEY,
        METADATA,
    )

    assert len(document.tag) == 32


def test_valid_document_verifies():

    document = encrypt_document(
        b"hello",
        ENCRYPTION_KEY,
        MAC_KEY,
        METADATA,
    )

    assert verify_document(
        document,
        MAC_KEY,
    )


def test_ciphertext_tampering_is_rejected():

    document = encrypt_document(
        b"very secret document",
        ENCRYPTION_KEY,
        MAC_KEY,
        METADATA,
    )

    modified = bytearray(
        document.ciphertext
    )

    modified[0] ^= 1

    tampered = replace(
        document,
        ciphertext=bytes(modified),
    )

    with pytest.raises(
        IntegrityError
    ):
        decrypt_document(
            tampered,
            ENCRYPTION_KEY,
            MAC_KEY,
        )


def test_iv_tampering_is_rejected():

    document = encrypt_document(
        b"secret",
        ENCRYPTION_KEY,
        MAC_KEY,
        METADATA,
    )

    modified = bytearray(
        document.iv
    )

    modified[0] ^= 1

    tampered = replace(
        document,
        iv=bytes(modified),
    )

    with pytest.raises(
        IntegrityError
    ):
        decrypt_document(
            tampered,
            ENCRYPTION_KEY,
            MAC_KEY,
        )


def test_metadata_tampering_is_rejected():

    document = encrypt_document(
        b"secret",
        ENCRYPTION_KEY,
        MAC_KEY,
        METADATA,
    )

    tampered_metadata = (
        canonicalize_metadata(
            {
                "document_id": "doc-001",
                "filename": "evil.pdf",
                "owner": "Mallory",
                "recipients": [
                    "Mallory",
                ],
                "version": 1,
            }
        )
    )

    tampered = replace(
        document,
        metadata=tampered_metadata,
    )

    with pytest.raises(
        IntegrityError
    ):
        decrypt_document(
            tampered,
            ENCRYPTION_KEY,
            MAC_KEY,
        )


def test_tag_tampering_is_rejected():

    document = encrypt_document(
        b"secret",
        ENCRYPTION_KEY,
        MAC_KEY,
        METADATA,
    )

    modified = bytearray(
        document.tag
    )

    modified[-1] ^= 1

    tampered = replace(
        document,
        tag=bytes(modified),
    )

    with pytest.raises(
        IntegrityError
    ):
        decrypt_document(
            tampered,
            ENCRYPTION_KEY,
            MAC_KEY,
        )


def test_wrong_mac_key_is_rejected():

    document = encrypt_document(
        b"secret",
        ENCRYPTION_KEY,
        MAC_KEY,
        METADATA,
    )

    wrong_key = b"M" * 32

    with pytest.raises(
        IntegrityError
    ):
        decrypt_document(
            document,
            ENCRYPTION_KEY,
            wrong_key,
        )


def test_metadata_order_does_not_change_encoding():

    first = {
        "owner": "Layla",
        "filename": "report.pdf",
        "version": 1,
    }

    second = {
        "version": 1,
        "filename": "report.pdf",
        "owner": "Layla",
    }

    assert (
        canonicalize_metadata(first)
        == canonicalize_metadata(second)
    )


def test_metadata_change_changes_encoding():

    first = {
        "owner": "Layla",
        "filename": "report.pdf",
    }

    second = {
        "owner": "Layla",
        "filename": "other.pdf",
    }

    assert (
        canonicalize_metadata(first)
        != canonicalize_metadata(second)
    )


def test_invalid_encryption_key_is_rejected():

    with pytest.raises(
        DocumentCryptoError
    ):
        encrypt_document(
            b"secret",
            b"K" * 16,
            MAC_KEY,
            METADATA,
        )


def test_invalid_mac_key_is_rejected():

    with pytest.raises(
        DocumentCryptoError
    ):
        encrypt_document(
            b"secret",
            ENCRYPTION_KEY,
            b"M" * 16,
            METADATA,
        )


def test_non_bytes_plaintext_is_rejected():

    with pytest.raises(
        TypeError
    ):
        encrypt_document(
            "secret",
            ENCRYPTION_KEY,
            MAC_KEY,
            METADATA,
        )


def test_invalid_metadata_value_is_rejected():

    with pytest.raises(
        DocumentCryptoError
    ):
        encrypt_document(
            b"secret",
            ENCRYPTION_KEY,
            MAC_KEY,
            {
                "owner": object(),
            },
        )


def test_metadata_is_stored_canonically():

    document = encrypt_document(
        b"secret",
        ENCRYPTION_KEY,
        MAC_KEY,
        METADATA,
    )

    assert (
        document.metadata
        == canonicalize_metadata(
            METADATA
        )
    )


def test_encrypted_document_contains_no_plaintext():

    plaintext = (
        b"TOP-SECRET-DOCUMENT-CONTENT"
    )

    document = encrypt_document(
        plaintext,
        ENCRYPTION_KEY,
        MAC_KEY,
        METADATA,
    )

    assert (
        plaintext
        not in document.ciphertext
    )

    assert (
        document.ciphertext
        != plaintext
    )