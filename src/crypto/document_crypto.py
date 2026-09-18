import json
from collections.abc import Mapping
from dataclasses import dataclass

from .aes import AES_256_KEY_SIZE
from .cbc import (
    cbc_decrypt,
    cbc_encrypt,
    generate_iv,
)
from .hmac_sha256 import (
    SHA256_DIGEST_SIZE,
    hmac_sha256,
    verify_hmac_sha256,
)
from .padding import PaddingError


DOCUMENT_MAC_KEY_SIZE = 32
MAC_DOMAIN = b"SecureVault-Document-EtM-v1"


class DocumentCryptoError(ValueError):
    pass


class IntegrityError(DocumentCryptoError):
    pass


@dataclass(frozen=True)
class EncryptedDocument:
    iv: bytes
    ciphertext: bytes
    metadata: bytes
    tag: bytes


def _validate_encryption_key(
    key: bytes,
) -> None:
    if not isinstance(key, bytes):
        raise TypeError(
            "encryption_key must be bytes"
        )

    if len(key) != AES_256_KEY_SIZE:
        raise DocumentCryptoError(
            "Encryption key must be exactly 32 bytes."
        )


def _validate_mac_key(
    key: bytes,
) -> None:
    if not isinstance(key, bytes):
        raise TypeError(
            "mac_key must be bytes"
        )

    if len(key) != DOCUMENT_MAC_KEY_SIZE:
        raise DocumentCryptoError(
            "MAC key must be exactly 32 bytes."
        )


def _validate_json_value(
    value,
) -> None:
    if value is None:
        return

    if isinstance(
        value,
        (str, int, bool),
    ):
        return

    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return

    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise DocumentCryptoError(
                    "Metadata keys must be strings."
                )

            _validate_json_value(item)

        return

    raise DocumentCryptoError(
        "Metadata contains an unsupported value."
    )


def canonicalize_metadata(
    metadata: Mapping,
) -> bytes:
    if not isinstance(metadata, Mapping):
        raise TypeError(
            "metadata must be a mapping"
        )

    normalized = dict(metadata)

    for key, value in normalized.items():
        if not isinstance(key, str):
            raise DocumentCryptoError(
                "Metadata keys must be strings."
            )

        _validate_json_value(value)

    try:
        encoded = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (
        TypeError,
        ValueError,
    ) as error:
        raise DocumentCryptoError(
            "Invalid metadata."
        ) from error

    return encoded.encode(
        "utf-8"
    )


def _length_prefix(
    value: bytes,
) -> bytes:
    return len(value).to_bytes(
        8,
        "big",
    )


def build_authenticated_data(
    metadata: bytes,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    if not isinstance(metadata, bytes):
        raise TypeError(
            "metadata must be bytes"
        )

    if not isinstance(iv, bytes):
        raise TypeError(
            "iv must be bytes"
        )

    if not isinstance(ciphertext, bytes):
        raise TypeError(
            "ciphertext must be bytes"
        )

    return (
        MAC_DOMAIN
        + _length_prefix(metadata)
        + metadata
        + _length_prefix(iv)
        + iv
        + _length_prefix(ciphertext)
        + ciphertext
    )


def encrypt_document(
    plaintext: bytes,
    encryption_key: bytes,
    mac_key: bytes,
    metadata: Mapping,
) -> EncryptedDocument:
    if not isinstance(plaintext, bytes):
        raise TypeError(
            "plaintext must be bytes"
        )

    _validate_encryption_key(
        encryption_key
    )

    _validate_mac_key(
        mac_key
    )

    encoded_metadata = canonicalize_metadata(
        metadata
    )

    iv = generate_iv()

    ciphertext = cbc_encrypt(
        plaintext,
        encryption_key,
        iv,
    )

    authenticated_data = build_authenticated_data(
        encoded_metadata,
        iv,
        ciphertext,
    )

    tag = hmac_sha256(
        mac_key,
        authenticated_data,
    )

    return EncryptedDocument(
        iv=iv,
        ciphertext=ciphertext,
        metadata=encoded_metadata,
        tag=tag,
    )


def verify_document(
    document: EncryptedDocument,
    mac_key: bytes,
) -> bool:
    if not isinstance(
        document,
        EncryptedDocument,
    ):
        raise TypeError(
            "document must be an EncryptedDocument"
        )

    _validate_mac_key(
        mac_key
    )

    if len(document.tag) != SHA256_DIGEST_SIZE:
        return False

    authenticated_data = build_authenticated_data(
        document.metadata,
        document.iv,
        document.ciphertext,
    )

    return verify_hmac_sha256(
        mac_key,
        authenticated_data,
        document.tag,
    )


def decrypt_document(
    document: EncryptedDocument,
    encryption_key: bytes,
    mac_key: bytes,
) -> bytes:
    if not isinstance(
        document,
        EncryptedDocument,
    ):
        raise TypeError(
            "document must be an EncryptedDocument"
        )

    _validate_encryption_key(
        encryption_key
    )

    _validate_mac_key(
        mac_key
    )

    if not verify_document(
        document,
        mac_key,
    ):
        raise IntegrityError(
            "Document integrity verification failed."
        )

    try:
        return cbc_decrypt(
            document.ciphertext,
            encryption_key,
            document.iv,
        )

    except PaddingError as error:
        raise DocumentCryptoError(
            "Document decryption failed."
        ) from error