import hashlib
import secrets
from collections.abc import Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .document_crypto import canonicalize_metadata


ED25519_PRIVATE_KEY_SIZE = 32
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
DOCUMENT_HASH_SIZE = 32

SIGNATURE_DOMAIN = (
    b"SecureVault-Document-Signature-v1"
)


class SignatureError(ValueError):
    pass


@dataclass(frozen=True)
class DocumentSignature:
    content_hash: bytes
    metadata: bytes
    signature: bytes


def _validate_private_key(
    private_key: bytes,
) -> None:
    if not isinstance(
        private_key,
        bytes,
    ):
        raise TypeError(
            "private_key must be bytes"
        )

    if len(
        private_key
    ) != ED25519_PRIVATE_KEY_SIZE:
        raise SignatureError(
            "Ed25519 private key must be exactly 32 bytes."
        )


def _validate_public_key(
    public_key: bytes,
) -> None:
    if not isinstance(
        public_key,
        bytes,
    ):
        raise TypeError(
            "public_key must be bytes"
        )

    if len(
        public_key
    ) != ED25519_PUBLIC_KEY_SIZE:
        raise SignatureError(
            "Ed25519 public key must be exactly 32 bytes."
        )


def _validate_message(
    message: bytes,
) -> None:
    if not isinstance(
        message,
        bytes,
    ):
        raise TypeError(
            "message must be bytes"
        )


def generate_ed25519_keypair() -> tuple[
    bytes,
    bytes,
]:
    private = (
        Ed25519PrivateKey.generate()
    )

    private_bytes = (
        private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=(
                serialization.NoEncryption()
            ),
        )
    )

    public_bytes = (
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )

    return (
        private_bytes,
        public_bytes,
    )


def derive_ed25519_public_key(
    private_key: bytes,
) -> bytes:
    _validate_private_key(
        private_key
    )

    private = (
        Ed25519PrivateKey
        .from_private_bytes(
            private_key
        )
    )

    return (
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def ed25519_sign(
    private_key: bytes,
    message: bytes,
) -> bytes:
    _validate_private_key(
        private_key
    )

    _validate_message(
        message
    )

    private = (
        Ed25519PrivateKey
        .from_private_bytes(
            private_key
        )
    )

    return private.sign(
        message
    )


def ed25519_verify(
    public_key: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    _validate_public_key(
        public_key
    )

    _validate_message(
        message
    )

    if not isinstance(
        signature,
        bytes,
    ):
        raise TypeError(
            "signature must be bytes"
        )

    if len(
        signature
    ) != ED25519_SIGNATURE_SIZE:
        return False

    public = (
        Ed25519PublicKey
        .from_public_bytes(
            public_key
        )
    )

    try:
        public.verify(
            signature,
            message,
        )

    except InvalidSignature:
        return False

    return True


def hash_document(
    plaintext: bytes,
) -> bytes:
    if not isinstance(
        plaintext,
        bytes,
    ):
        raise TypeError(
            "plaintext must be bytes"
        )

    return hashlib.sha256(
        plaintext
    ).digest()


def _length_prefix(
    value: bytes,
) -> bytes:
    return len(value).to_bytes(
        8,
        "big",
    )


def build_document_signature_message(
    content_hash: bytes,
    metadata: bytes,
) -> bytes:
    if not isinstance(
        content_hash,
        bytes,
    ):
        raise TypeError(
            "content_hash must be bytes"
        )

    if len(
        content_hash
    ) != DOCUMENT_HASH_SIZE:
        raise SignatureError(
            "Document hash must be exactly 32 bytes."
        )

    if not isinstance(
        metadata,
        bytes,
    ):
        raise TypeError(
            "metadata must be bytes"
        )

    return (
        SIGNATURE_DOMAIN
        + _length_prefix(
            content_hash
        )
        + content_hash
        + _length_prefix(
            metadata
        )
        + metadata
    )


def sign_document(
    plaintext: bytes,
    metadata: Mapping,
    private_key: bytes,
) -> DocumentSignature:
    if not isinstance(
        plaintext,
        bytes,
    ):
        raise TypeError(
            "plaintext must be bytes"
        )

    _validate_private_key(
        private_key
    )

    encoded_metadata = (
        canonicalize_metadata(
            metadata
        )
    )

    content_hash = (
        hash_document(
            plaintext
        )
    )

    message = (
        build_document_signature_message(
            content_hash,
            encoded_metadata,
        )
    )

    signature = ed25519_sign(
        private_key,
        message,
    )

    return DocumentSignature(
        content_hash=content_hash,
        metadata=encoded_metadata,
        signature=signature,
    )


def verify_document_signature(
    plaintext: bytes,
    proof: DocumentSignature,
    public_key: bytes,
) -> bool:
    if not isinstance(
        plaintext,
        bytes,
    ):
        raise TypeError(
            "plaintext must be bytes"
        )

    if not isinstance(
        proof,
        DocumentSignature,
    ):
        raise TypeError(
            "proof must be a DocumentSignature"
        )

    _validate_public_key(
        public_key
    )

    if len(
        proof.content_hash
    ) != DOCUMENT_HASH_SIZE:
        return False

    if not isinstance(
        proof.metadata,
        bytes,
    ):
        return False

    if not isinstance(
        proof.signature,
        bytes,
    ):
        return False

    calculated_hash = (
        hash_document(
            plaintext
        )
    )

    if not secrets.compare_digest(
        calculated_hash,
        proof.content_hash,
    ):
        return False

    message = (
        build_document_signature_message(
            proof.content_hash,
            proof.metadata,
        )
    )

    return ed25519_verify(
        public_key,
        message,
        proof.signature,
    )