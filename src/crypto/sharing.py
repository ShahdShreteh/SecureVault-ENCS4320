import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass

from .document_crypto import (
    EncryptedDocument,
    decrypt_document,
    encrypt_document,
)
from .key_wrap import (
    WrappedDocumentKeys,
    generate_document_keys,
    unwrap_document_keys,
    wrap_document_keys,
)
from .signatures import (
    DocumentSignature,
    sign_document,
    verify_document_signature,
)


class SharedDocumentError(ValueError):
    pass


class MetadataBindingError(
    SharedDocumentError
):
    pass


class ProducerVerificationError(
    SharedDocumentError
):
    pass


@dataclass(frozen=True)
class SharedDocumentPackage:
    encrypted_document: EncryptedDocument
    wrapped_keys: WrappedDocumentKeys
    signature: DocumentSignature


def _validate_text(
    value: str,
    name: str,
) -> None:
    if not isinstance(value, str):
        raise TypeError(
            f"{name} must be a string"
        )

    if not value.strip():
        raise SharedDocumentError(
            f"{name} cannot be empty."
        )


def _build_bound_metadata(
    metadata: Mapping,
    document_id: str,
    sender_username: str,
    recipient_username: str,
) -> dict:
    if not isinstance(metadata, Mapping):
        raise TypeError(
            "metadata must be a mapping"
        )

    _validate_text(
        document_id,
        "document_id",
    )

    _validate_text(
        sender_username,
        "sender_username",
    )

    _validate_text(
        recipient_username,
        "recipient_username",
    )

    reserved = {
        "document_id",
        "owner",
        "recipient",
    }

    for key in reserved:
        if key in metadata:
            raise SharedDocumentError(
                f"Metadata field '{key}' is reserved."
            )

    result = dict(metadata)

    result["document_id"] = (
        document_id
    )

    result["owner"] = (
        sender_username
    )

    result["recipient"] = (
        recipient_username
    )

    return result


def _verify_bound_metadata(
    encoded_metadata: bytes,
    document_id: str,
    sender_username: str,
    recipient_username: str,
) -> None:
    if not isinstance(
        encoded_metadata,
        bytes,
    ):
        raise MetadataBindingError(
            "Invalid document metadata."
        )

    try:
        decoded = json.loads(
            encoded_metadata.decode(
                "utf-8"
            )
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise MetadataBindingError(
            "Invalid document metadata."
        ) from error

    if not isinstance(decoded, dict):
        raise MetadataBindingError(
            "Invalid document metadata."
        )

    if (
        decoded.get("document_id")
        != document_id
    ):
        raise MetadataBindingError(
            "Document ID does not match."
        )

    if (
        decoded.get("owner")
        != sender_username
    ):
        raise MetadataBindingError(
            "Document owner does not match."
        )

    if (
        decoded.get("recipient")
        != recipient_username
    ):
        raise MetadataBindingError(
            "Document recipient does not match."
        )


def create_shared_document(
    plaintext: bytes,
    metadata: Mapping,
    document_id: str,
    sender_username: str,
    recipient_username: str,
    sender_x25519_private_key: bytes,
    sender_ed25519_private_key: bytes,
    recipient_x25519_public_key: bytes,
) -> SharedDocumentPackage:
    if not isinstance(
        plaintext,
        bytes,
    ):
        raise TypeError(
            "plaintext must be bytes"
        )

    bound_metadata = (
        _build_bound_metadata(
            metadata,
            document_id,
            sender_username,
            recipient_username,
        )
    )

    document_keys = (
        generate_document_keys()
    )

    encrypted_document = (
        encrypt_document(
            plaintext,
            document_keys.encryption_key,
            document_keys.mac_key,
            bound_metadata,
        )
    )

    signature = sign_document(
        plaintext,
        bound_metadata,
        sender_ed25519_private_key,
    )

    wrapped_keys = (
        wrap_document_keys(
            document_keys,
            sender_x25519_private_key,
            recipient_x25519_public_key,
            sender_username,
            recipient_username,
            document_id,
        )
    )

    return SharedDocumentPackage(
        encrypted_document=(
            encrypted_document
        ),
        wrapped_keys=wrapped_keys,
        signature=signature,
    )


def open_shared_document(
    package: SharedDocumentPackage,
    document_id: str,
    sender_username: str,
    recipient_username: str,
    recipient_x25519_private_key: bytes,
    sender_x25519_public_key: bytes,
    sender_ed25519_public_key: bytes,
) -> bytes:
    if not isinstance(
        package,
        SharedDocumentPackage,
    ):
        raise TypeError(
            "package must be SharedDocumentPackage"
        )

    _validate_text(
        document_id,
        "document_id",
    )

    _validate_text(
        sender_username,
        "sender_username",
    )

    _validate_text(
        recipient_username,
        "recipient_username",
    )

    document_keys = (
        unwrap_document_keys(
            package.wrapped_keys,
            recipient_x25519_private_key,
            sender_x25519_public_key,
            sender_username,
            recipient_username,
            document_id,
        )
    )

    plaintext = decrypt_document(
        package.encrypted_document,
        document_keys.encryption_key,
        document_keys.mac_key,
    )

    if not secrets.compare_digest(
        package.encrypted_document.metadata,
        package.signature.metadata,
    ):
        raise MetadataBindingError(
            "Signed metadata does not match encrypted metadata."
        )

    _verify_bound_metadata(
        package.encrypted_document.metadata,
        document_id,
        sender_username,
        recipient_username,
    )

    valid_signature = (
        verify_document_signature(
            plaintext,
            package.signature,
            sender_ed25519_public_key,
        )
    )

    if not valid_signature:
        raise ProducerVerificationError(
            "Document producer verification failed."
        )

    return plaintext