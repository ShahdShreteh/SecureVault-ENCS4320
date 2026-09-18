import secrets
from dataclasses import dataclass

from .document_crypto import (
    EncryptedDocument,
    IntegrityError,
    canonicalize_metadata,
    decrypt_document,
    encrypt_document,
)
from .hkdf_sha256 import hkdf_sha256
from .x25519 import (
    KEY_SIZE,
    compute_shared_secret,
    derive_public_key,
)


DOCUMENT_ENCRYPTION_KEY_SIZE = 32
DOCUMENT_MAC_KEY_SIZE = 32
WRAP_SALT_SIZE = 32
WRAP_KEY_MATERIAL_SIZE = 64

WRAP_DOMAIN = (
    b"SecureVault-Document-Key-Wrap-v1"
)


class KeyWrapError(ValueError):
    pass


class KeyWrapIntegrityError(
    KeyWrapError
):
    pass


@dataclass(frozen=True)
class DocumentKeys:
    encryption_key: bytes
    mac_key: bytes


@dataclass(frozen=True)
class WrappedDocumentKeys:
    kdf_salt: bytes
    iv: bytes
    ciphertext: bytes
    metadata: bytes
    tag: bytes


def _validate_text(
    value: str,
    name: str,
) -> None:
    if not isinstance(value, str):
        raise TypeError(
            f"{name} must be a string"
        )

    if len(value.strip()) == 0:
        raise KeyWrapError(
            f"{name} cannot be empty."
        )


def _validate_public_key(
    key: bytes,
    name: str,
) -> None:
    if not isinstance(key, bytes):
        raise TypeError(
            f"{name} must be bytes"
        )

    if len(key) != KEY_SIZE:
        raise KeyWrapError(
            f"{name} must be exactly 32 bytes."
        )


def _validate_document_keys(
    keys: DocumentKeys,
) -> None:
    if not isinstance(
        keys,
        DocumentKeys,
    ):
        raise TypeError(
            "keys must be DocumentKeys"
        )

    if not isinstance(
        keys.encryption_key,
        bytes,
    ):
        raise TypeError(
            "encryption_key must be bytes"
        )

    if not isinstance(
        keys.mac_key,
        bytes,
    ):
        raise TypeError(
            "mac_key must be bytes"
        )

    if len(
        keys.encryption_key
    ) != DOCUMENT_ENCRYPTION_KEY_SIZE:
        raise KeyWrapError(
            "Document encryption key must be 32 bytes."
        )

    if len(
        keys.mac_key
    ) != DOCUMENT_MAC_KEY_SIZE:
        raise KeyWrapError(
            "Document MAC key must be 32 bytes."
        )


def _length_prefix(
    value: bytes,
) -> bytes:
    return len(value).to_bytes(
        4,
        "big",
    )


def _encode_field(
    value: bytes,
) -> bytes:
    return (
        _length_prefix(value)
        + value
    )


def _build_context(
    sender_username: str,
    recipient_username: str,
    document_id: str,
    sender_public_key: bytes,
    recipient_public_key: bytes,
) -> bytes:
    _validate_text(
        sender_username,
        "sender_username",
    )

    _validate_text(
        recipient_username,
        "recipient_username",
    )

    _validate_text(
        document_id,
        "document_id",
    )

    _validate_public_key(
        sender_public_key,
        "sender_public_key",
    )

    _validate_public_key(
        recipient_public_key,
        "recipient_public_key",
    )

    sender = sender_username.encode(
        "utf-8"
    )

    recipient = recipient_username.encode(
        "utf-8"
    )

    document = document_id.encode(
        "utf-8"
    )

    return (
        WRAP_DOMAIN
        + _encode_field(sender)
        + _encode_field(recipient)
        + _encode_field(document)
        + _encode_field(
            sender_public_key
        )
        + _encode_field(
            recipient_public_key
        )
    )


def _derive_wrapping_keys(
    shared_secret: bytes,
    salt: bytes,
    context: bytes,
) -> tuple[bytes, bytes]:
    if not isinstance(
        shared_secret,
        bytes,
    ):
        raise TypeError(
            "shared_secret must be bytes"
        )

    if not isinstance(
        salt,
        bytes,
    ):
        raise TypeError(
            "salt must be bytes"
        )

    if len(salt) != WRAP_SALT_SIZE:
        raise KeyWrapError(
            "KDF salt must be exactly 32 bytes."
        )

    material = hkdf_sha256(
        input_key_material=shared_secret,
        salt=salt,
        info=context,
        length=WRAP_KEY_MATERIAL_SIZE,
    )

    return (
        material[:32],
        material[32:],
    )


def _build_metadata(
    sender_username: str,
    recipient_username: str,
    document_id: str,
    sender_public_key: bytes,
    recipient_public_key: bytes,
    kdf_salt: bytes,
) -> dict:
    return {
        "purpose": (
            "SecureVault-Document-Key-Wrap-v1"
        ),
        "sender": sender_username,
        "recipient": recipient_username,
        "document_id": document_id,
        "sender_public_key": (
            sender_public_key.hex()
        ),
        "recipient_public_key": (
            recipient_public_key.hex()
        ),
        "kdf_salt": kdf_salt.hex(),
    }


def generate_document_keys() -> DocumentKeys:
    return DocumentKeys(
        encryption_key=(
            secrets.token_bytes(
                DOCUMENT_ENCRYPTION_KEY_SIZE
            )
        ),
        mac_key=(
            secrets.token_bytes(
                DOCUMENT_MAC_KEY_SIZE
            )
        ),
    )


def wrap_document_keys(
    keys: DocumentKeys,
    sender_private_key: bytes,
    recipient_public_key: bytes,
    sender_username: str,
    recipient_username: str,
    document_id: str,
) -> WrappedDocumentKeys:
    _validate_document_keys(
        keys
    )

    _validate_public_key(
        sender_private_key,
        "sender_private_key",
    )

    _validate_public_key(
        recipient_public_key,
        "recipient_public_key",
    )

    sender_public_key = (
        derive_public_key(
            sender_private_key
        )
    )

    shared_secret = (
        compute_shared_secret(
            sender_private_key,
            recipient_public_key,
        )
    )

    kdf_salt = (
        secrets.token_bytes(
            WRAP_SALT_SIZE
        )
    )

    context = _build_context(
        sender_username,
        recipient_username,
        document_id,
        sender_public_key,
        recipient_public_key,
    )

    wrapping_encryption_key, wrapping_mac_key = (
        _derive_wrapping_keys(
            shared_secret,
            kdf_salt,
            context,
        )
    )

    metadata = _build_metadata(
        sender_username,
        recipient_username,
        document_id,
        sender_public_key,
        recipient_public_key,
        kdf_salt,
    )

    payload = (
        keys.encryption_key
        + keys.mac_key
    )

    encrypted = encrypt_document(
        payload,
        wrapping_encryption_key,
        wrapping_mac_key,
        metadata,
    )

    return WrappedDocumentKeys(
        kdf_salt=kdf_salt,
        iv=encrypted.iv,
        ciphertext=encrypted.ciphertext,
        metadata=encrypted.metadata,
        tag=encrypted.tag,
    )


def unwrap_document_keys(
    wrapped: WrappedDocumentKeys,
    recipient_private_key: bytes,
    sender_public_key: bytes,
    sender_username: str,
    recipient_username: str,
    document_id: str,
) -> DocumentKeys:
    if not isinstance(
        wrapped,
        WrappedDocumentKeys,
    ):
        raise TypeError(
            "wrapped must be WrappedDocumentKeys"
        )

    _validate_public_key(
        recipient_private_key,
        "recipient_private_key",
    )

    _validate_public_key(
        sender_public_key,
        "sender_public_key",
    )

    if not isinstance(
        wrapped.kdf_salt,
        bytes,
    ):
        raise TypeError(
            "kdf_salt must be bytes"
        )

    if len(
        wrapped.kdf_salt
    ) != WRAP_SALT_SIZE:
        raise KeyWrapIntegrityError(
            "Invalid wrapped key package."
        )

    recipient_public_key = (
        derive_public_key(
            recipient_private_key
        )
    )

    shared_secret = (
        compute_shared_secret(
            recipient_private_key,
            sender_public_key,
        )
    )

    context = _build_context(
        sender_username,
        recipient_username,
        document_id,
        sender_public_key,
        recipient_public_key,
    )

    wrapping_encryption_key, wrapping_mac_key = (
        _derive_wrapping_keys(
            shared_secret,
            wrapped.kdf_salt,
            context,
        )
    )

    encrypted = EncryptedDocument(
        iv=wrapped.iv,
        ciphertext=wrapped.ciphertext,
        metadata=wrapped.metadata,
        tag=wrapped.tag,
    )

    try:
        payload = decrypt_document(
            encrypted,
            wrapping_encryption_key,
            wrapping_mac_key,
        )

    except IntegrityError as error:
        raise KeyWrapIntegrityError(
            "Wrapped document keys failed integrity verification."
        ) from error

    expected_metadata = (
        canonicalize_metadata(
            _build_metadata(
                sender_username,
                recipient_username,
                document_id,
                sender_public_key,
                recipient_public_key,
                wrapped.kdf_salt,
            )
        )
    )

    if (
        wrapped.metadata
        != expected_metadata
    ):
        raise KeyWrapIntegrityError(
            "Wrapped key metadata does not match the expected context."
        )

    if len(payload) != (
        DOCUMENT_ENCRYPTION_KEY_SIZE
        + DOCUMENT_MAC_KEY_SIZE
    ):
        raise KeyWrapIntegrityError(
            "Invalid wrapped key payload."
        )

    return DocumentKeys(
        encryption_key=(
            payload[
                :DOCUMENT_ENCRYPTION_KEY_SIZE
            ]
        ),
        mac_key=(
            payload[
                DOCUMENT_ENCRYPTION_KEY_SIZE:
            ]
        ),
    )