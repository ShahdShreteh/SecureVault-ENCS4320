import pytest

from src.crypto.sharing import (
    create_shared_document,
)
from src.crypto.signatures import (
    generate_ed25519_keypair,
)
from src.crypto.x25519 import (
    generate_keypair,
)
from src.storage.document_store import (
    DocumentNotFoundError,
    DocumentOwnerError,
    DocumentStore,
    DuplicateDocumentError,
    DuplicateShareError,
    ShareNotFoundError,
)


def make_users():

    alice_x_private, alice_x_public = (
        generate_keypair()
    )

    bob_x_private, bob_x_public = (
        generate_keypair()
    )

    alice_ed_private, alice_ed_public = (
        generate_ed25519_keypair()
    )

    return {
        "alice_x_private": alice_x_private,
        "alice_x_public": alice_x_public,
        "bob_x_private": bob_x_private,
        "bob_x_public": bob_x_public,
        "alice_ed_private": alice_ed_private,
        "alice_ed_public": alice_ed_public,
    }


def make_package():

    users = make_users()

    package = create_shared_document(
        plaintext=b"SecureVault document",
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

    return users, package


def test_store_and_reload_document(
    tmp_path,
):

    store = DocumentStore(
        tmp_path / "documents.db"
    )

    _, package = make_package()

    saved = store.create_document(
        "doc-001",
        "Alice",
        package.encrypted_document,
        package.signature,
    )

    loaded = store.get_document(
        "doc-001"
    )

    assert (
        loaded.document_id
        == "doc-001"
    )

    assert (
        loaded.owner_username
        == "Alice"
    )

    assert (
        loaded.encrypted_document
        == package.encrypted_document
    )

    assert (
        loaded.signature
        == package.signature
    )

    assert saved == loaded


def test_document_exists(
    tmp_path,
):

    store = DocumentStore(
        tmp_path / "documents.db"
    )

    _, package = make_package()

    assert not store.document_exists(
        "doc-001"
    )

    store.create_document(
        "doc-001",
        "Alice",
        package.encrypted_document,
        package.signature,
    )

    assert store.document_exists(
        "doc-001"
    )


def test_duplicate_document_rejected(
    tmp_path,
):

    store = DocumentStore(
        tmp_path / "documents.db"
    )

    _, package = make_package()

    store.create_document(
        "doc-001",
        "Alice",
        package.encrypted_document,
        package.signature,
    )

    with pytest.raises(
        DuplicateDocumentError
    ):
        store.create_document(
            "doc-001",
            "Alice",
            package.encrypted_document,
            package.signature,
        )


def test_unknown_document_rejected(
    tmp_path,
):

    store = DocumentStore(
        tmp_path / "documents.db"
    )

    with pytest.raises(
        DocumentNotFoundError
    ):
        store.get_document(
            "missing"
        )


def test_store_and_reload_share(
    tmp_path,
):

    store = DocumentStore(
        tmp_path / "documents.db"
    )

    _, package = make_package()

    store.create_document(
        "doc-001",
        "Alice",
        package.encrypted_document,
        package.signature,
    )

    saved = store.create_share(
        "doc-001",
        "Alice",
        "Bob",
        package.wrapped_keys,
    )

    loaded = store.get_share(
        "doc-001",
        "Bob",
    )

    assert (
        loaded.document_id
        == "doc-001"
    )

    assert (
        loaded.owner_username
        == "Alice"
    )

    assert (
        loaded.recipient_username
        == "Bob"
    )

    assert (
        loaded.wrapped_keys
        == package.wrapped_keys
    )

    assert saved == loaded


def test_duplicate_share_rejected(
    tmp_path,
):

    store = DocumentStore(
        tmp_path / "documents.db"
    )

    _, package = make_package()

    store.create_document(
        "doc-001",
        "Alice",
        package.encrypted_document,
        package.signature,
    )

    store.create_share(
        "doc-001",
        "Alice",
        "Bob",
        package.wrapped_keys,
    )

    with pytest.raises(
        DuplicateShareError
    ):
        store.create_share(
            "doc-001",
            "Alice",
            "Bob",
            package.wrapped_keys,
        )


def test_wrong_owner_cannot_share(
    tmp_path,
):

    store = DocumentStore(
        tmp_path / "documents.db"
    )

    _, package = make_package()

    store.create_document(
        "doc-001",
        "Alice",
        package.encrypted_document,
        package.signature,
    )

    with pytest.raises(
        DocumentOwnerError
    ):
        store.create_share(
            "doc-001",
            "Mallory",
            "Bob",
            package.wrapped_keys,
        )


def test_share_for_unknown_document_fails(
    tmp_path,
):

    store = DocumentStore(
        tmp_path / "documents.db"
    )

    _, package = make_package()

    with pytest.raises(
        DocumentNotFoundError
    ):
        store.create_share(
            "missing",
            "Alice",
            "Bob",
            package.wrapped_keys,
        )


def test_unknown_share_rejected(
    tmp_path,
):

    store = DocumentStore(
        tmp_path / "documents.db"
    )

    with pytest.raises(
        ShareNotFoundError
    ):
        store.get_share(
            "doc-001",
            "Bob",
        )


def test_list_owned_documents(
    tmp_path,
):

    store = DocumentStore(
        tmp_path / "documents.db"
    )

    _, package = make_package()

    store.create_document(
        "doc-001",
        "Alice",
        package.encrypted_document,
        package.signature,
    )

    assert store.list_owned_documents(
        "Alice"
    ) == [
        "doc-001"
    ]

    assert store.list_owned_documents(
        "Bob"
    ) == []


def test_list_shared_documents(
    tmp_path,
):

    store = DocumentStore(
        tmp_path / "documents.db"
    )

    _, package = make_package()

    store.create_document(
        "doc-001",
        "Alice",
        package.encrypted_document,
        package.signature,
    )

    store.create_share(
        "doc-001",
        "Alice",
        "Bob",
        package.wrapped_keys,
    )

    assert store.list_shared_documents(
        "Bob"
    ) == [
        "doc-001"
    ]

    assert store.list_shared_documents(
        "Mallory"
    ) == []


def test_retrieve_for_recipient(
    tmp_path,
):

    store = DocumentStore(
        tmp_path / "documents.db"
    )

    _, package = make_package()

    store.create_document(
        "doc-001",
        "Alice",
        package.encrypted_document,
        package.signature,
    )

    store.create_share(
        "doc-001",
        "Alice",
        "Bob",
        package.wrapped_keys,
    )

    document, share = (
        store.retrieve_for_recipient(
            "doc-001",
            "Bob",
        )
    )

    assert (
        document.encrypted_document
        == package.encrypted_document
    )

    assert (
        document.signature
        == package.signature
    )

    assert (
        share.wrapped_keys
        == package.wrapped_keys
    )


def test_server_storage_does_not_store_plaintext(
    tmp_path,
):

    database = (
        tmp_path / "documents.db"
    )

    store = DocumentStore(
        database
    )

    plaintext = (
        b"VERY-SECRET-SERVER-SHOULD-NOT-SEE"
    )

    users = make_users()

    package = create_shared_document(
        plaintext=plaintext,
        metadata={
            "filename": "secret.txt",
        },
        document_id="doc-secret",
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

    store.create_document(
        "doc-secret",
        "Alice",
        package.encrypted_document,
        package.signature,
    )

    store.create_share(
        "doc-secret",
        "Alice",
        "Bob",
        package.wrapped_keys,
    )

    database_bytes = (
        database.read_bytes()
    )

    assert plaintext not in database_bytes