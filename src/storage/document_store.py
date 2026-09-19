import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from src.crypto.document_crypto import EncryptedDocument
from src.crypto.key_wrap import WrappedDocumentKeys
from src.crypto.signatures import DocumentSignature


class DocumentStoreError(ValueError):
    pass


class DuplicateDocumentError(DocumentStoreError):
    pass


class DuplicateShareError(DocumentStoreError):
    pass


class DocumentNotFoundError(DocumentStoreError):
    pass


class ShareNotFoundError(DocumentStoreError):
    pass


class DocumentOwnerError(DocumentStoreError):
    pass


@dataclass(frozen=True)
class StoredDocument:
    document_id: str
    owner_username: str
    encrypted_document: EncryptedDocument
    signature: DocumentSignature
    created_at: str


@dataclass(frozen=True)
class StoredShare:
    document_id: str
    owner_username: str
    recipient_username: str
    wrapped_keys: WrappedDocumentKeys
    created_at: str


def _validate_text(
    value: str,
    name: str,
) -> None:
    if not isinstance(value, str):
        raise TypeError(
            f"{name} must be a string"
        )

    if not value.strip():
        raise DocumentStoreError(
            f"{name} cannot be empty."
        )


class DocumentStore:

    def __init__(
        self,
        database_path: str | Path,
    ) -> None:
        self.database_path = Path(
            database_path
        )

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._create_tables()

    def _connect(
        self,
    ) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path
        )

        connection.row_factory = sqlite3.Row

        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        return connection

    def _create_tables(
        self,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    document_id TEXT PRIMARY KEY,
                    owner_username TEXT NOT NULL,
                    document_iv BLOB NOT NULL,
                    document_ciphertext BLOB NOT NULL,
                    document_metadata BLOB NOT NULL,
                    document_tag BLOB NOT NULL,
                    signature_content_hash BLOB NOT NULL,
                    signature_metadata BLOB NOT NULL,
                    signature BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS shares (
                    document_id TEXT NOT NULL,
                    owner_username TEXT NOT NULL,
                    recipient_username TEXT NOT NULL,
                    kdf_salt BLOB NOT NULL,
                    wrapped_iv BLOB NOT NULL,
                    wrapped_ciphertext BLOB NOT NULL,
                    wrapped_metadata BLOB NOT NULL,
                    wrapped_tag BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (
                        document_id,
                        recipient_username
                    ),
                    FOREIGN KEY (
                        document_id
                    )
                    REFERENCES documents (
                        document_id
                    )
                    ON DELETE CASCADE
                )
                """
            )

    def create_document(
        self,
        document_id: str,
        owner_username: str,
        encrypted_document: EncryptedDocument,
        signature: DocumentSignature,
    ) -> StoredDocument:
        _validate_text(
            document_id,
            "document_id",
        )

        _validate_text(
            owner_username,
            "owner_username",
        )

        if not isinstance(
            encrypted_document,
            EncryptedDocument,
        ):
            raise TypeError(
                "encrypted_document must be EncryptedDocument"
            )

        if not isinstance(
            signature,
            DocumentSignature,
        ):
            raise TypeError(
                "signature must be DocumentSignature"
            )

        created_at = datetime.now(
            timezone.utc
        ).isoformat()

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO documents (
                        document_id,
                        owner_username,
                        document_iv,
                        document_ciphertext,
                        document_metadata,
                        document_tag,
                        signature_content_hash,
                        signature_metadata,
                        signature,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        document_id,
                        owner_username,
                        encrypted_document.iv,
                        encrypted_document.ciphertext,
                        encrypted_document.metadata,
                        encrypted_document.tag,
                        signature.content_hash,
                        signature.metadata,
                        signature.signature,
                        created_at,
                    ),
                )

        except sqlite3.IntegrityError as error:
            raise DuplicateDocumentError(
                "Document already exists."
            ) from error

        return self.get_document(
            document_id
        )

    def get_document(
        self,
        document_id: str,
    ) -> StoredDocument:
        _validate_text(
            document_id,
            "document_id",
        )

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM documents
                WHERE document_id = ?
                """,
                (document_id,),
            ).fetchone()

        if row is None:
            raise DocumentNotFoundError(
                "Document not found."
            )

        encrypted_document = EncryptedDocument(
            iv=bytes(
                row["document_iv"]
            ),
            ciphertext=bytes(
                row["document_ciphertext"]
            ),
            metadata=bytes(
                row["document_metadata"]
            ),
            tag=bytes(
                row["document_tag"]
            ),
        )

        signature = DocumentSignature(
            content_hash=bytes(
                row["signature_content_hash"]
            ),
            metadata=bytes(
                row["signature_metadata"]
            ),
            signature=bytes(
                row["signature"]
            ),
        )

        return StoredDocument(
            document_id=row["document_id"],
            owner_username=row[
                "owner_username"
            ],
            encrypted_document=(
                encrypted_document
            ),
            signature=signature,
            created_at=row["created_at"],
        )

    def document_exists(
        self,
        document_id: str,
    ) -> bool:
        _validate_text(
            document_id,
            "document_id",
        )

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM documents
                WHERE document_id = ?
                LIMIT 1
                """,
                (document_id,),
            ).fetchone()

        return row is not None

    def create_share(
        self,
        document_id: str,
        owner_username: str,
        recipient_username: str,
        wrapped_keys: WrappedDocumentKeys,
    ) -> StoredShare:
        _validate_text(
            document_id,
            "document_id",
        )

        _validate_text(
            owner_username,
            "owner_username",
        )

        _validate_text(
            recipient_username,
            "recipient_username",
        )

        if not isinstance(
            wrapped_keys,
            WrappedDocumentKeys,
        ):
            raise TypeError(
                "wrapped_keys must be WrappedDocumentKeys"
            )

        document = self.get_document(
            document_id
        )

        if (
            document.owner_username
            != owner_username
        ):
            raise DocumentOwnerError(
                "Only the document owner can create a share."
            )

        created_at = datetime.now(
            timezone.utc
        ).isoformat()

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO shares (
                        document_id,
                        owner_username,
                        recipient_username,
                        kdf_salt,
                        wrapped_iv,
                        wrapped_ciphertext,
                        wrapped_metadata,
                        wrapped_tag,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        document_id,
                        owner_username,
                        recipient_username,
                        wrapped_keys.kdf_salt,
                        wrapped_keys.iv,
                        wrapped_keys.ciphertext,
                        wrapped_keys.metadata,
                        wrapped_keys.tag,
                        created_at,
                    ),
                )

        except sqlite3.IntegrityError as error:
            raise DuplicateShareError(
                "Document is already shared with this recipient."
            ) from error

        return self.get_share(
            document_id,
            recipient_username,
        )

    def get_share(
        self,
        document_id: str,
        recipient_username: str,
    ) -> StoredShare:
        _validate_text(
            document_id,
            "document_id",
        )

        _validate_text(
            recipient_username,
            "recipient_username",
        )

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM shares
                WHERE document_id = ?
                AND recipient_username = ?
                """,
                (
                    document_id,
                    recipient_username,
                ),
            ).fetchone()

        if row is None:
            raise ShareNotFoundError(
                "Document share not found."
            )

        wrapped_keys = WrappedDocumentKeys(
            kdf_salt=bytes(
                row["kdf_salt"]
            ),
            iv=bytes(
                row["wrapped_iv"]
            ),
            ciphertext=bytes(
                row["wrapped_ciphertext"]
            ),
            metadata=bytes(
                row["wrapped_metadata"]
            ),
            tag=bytes(
                row["wrapped_tag"]
            ),
        )

        return StoredShare(
            document_id=row["document_id"],
            owner_username=row[
                "owner_username"
            ],
            recipient_username=row[
                "recipient_username"
            ],
            wrapped_keys=wrapped_keys,
            created_at=row["created_at"],
        )

    def list_owned_documents(
        self,
        owner_username: str,
    ) -> list[str]:
        _validate_text(
            owner_username,
            "owner_username",
        )

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT document_id
                FROM documents
                WHERE owner_username = ?
                ORDER BY created_at ASC
                """,
                (owner_username,),
            ).fetchall()

        return [
            row["document_id"]
            for row in rows
        ]

    def list_shared_documents(
        self,
        recipient_username: str,
    ) -> list[str]:
        _validate_text(
            recipient_username,
            "recipient_username",
        )

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT document_id
                FROM shares
                WHERE recipient_username = ?
                ORDER BY created_at ASC
                """,
                (recipient_username,),
            ).fetchall()

        return [
            row["document_id"]
            for row in rows
        ]

    def retrieve_for_recipient(
        self,
        document_id: str,
        recipient_username: str,
    ) -> tuple[
        StoredDocument,
        StoredShare,
    ]:
        document = self.get_document(
            document_id
        )

        share = self.get_share(
            document_id,
            recipient_username,
        )

        return (
            document,
            share,
        )