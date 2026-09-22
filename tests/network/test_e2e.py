import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.auth.auth_service import AuthService
from src.auth.signup import prepare_signup
from src.crypto.document_crypto import EncryptedDocument, IntegrityError
from src.crypto.sharing import (
    ProducerVerificationError,
    SharedDocumentPackage,
    create_shared_document,
    open_shared_document,
)
from src.crypto.signatures import DocumentSignature
from src.crypto.x25519 import derive_public_key
from src.network.client import SecureVaultClient
from src.network.protocol import create_request
from src.network.request_handler import RequestHandler
from src.network.tcp import SecureVaultTCPClient, SecureVaultTCPServer
from src.storage.document_store import DocumentStore
from src.trust.tofu import KeyChangeDetected, TofuTrustStore


def _identity():
    x_private = b"x" * 32
    ed_private = Ed25519PrivateKey.generate()
    return x_private, derive_public_key(x_private), ed_private


def _prepared(username, password, x_public, ed_private):
    return prepare_signup(username, password, x_public, ed_private.public_key().public_bytes_raw(), b"encrypted-private-bundle")


def test_tcp_e2e_tofu_replay_and_attacks(tmp_path):
    auth = AuthService(tmp_path / "users.db")
    docs = DocumentStore(tmp_path / "documents.db")
    handler = RequestHandler(auth, docs)
    server = SecureVaultTCPServer(handler)
    host, port = server.start()
    alice_x, alice_x_public, alice_ed = _identity()
    bob_x, bob_x_public, bob_ed = _identity()
    alice_tofu = TofuTrustStore(tmp_path / "alice-tofu.db")
    bob_tofu = TofuTrustStore(tmp_path / "bob-tofu.db")
    alice = SecureVaultClient(SecureVaultTCPClient(host, port), "Alice", alice_tofu)
    bob = SecureVaultClient(SecureVaultTCPClient(host, port), "Bob", bob_tofu)
    try:
        alice.signup(_prepared("Alice", "Alice-password-2026", alice_x_public, alice_ed))
        bob.signup(_prepared("Bob", "Bob-password-2026", bob_x_public, bob_ed))
        alice.login("Alice-password-2026")
        bob.login("Bob-password-2026")

        got_x, got_ed = alice.get_public_keys("Bob")
        assert (got_x, got_ed) == (bob_x_public, bob_ed.public_key().public_bytes_raw())
        assert alice_tofu.get_peer("Bob") is not None
        with pytest.raises(KeyChangeDetected):
            alice_tofu.observe_peer("Bob", b"z" * 32, got_ed)

        document_id = "alice-bob-001"
        package = create_shared_document(
            b"secret document contents", {"filename": "report.txt"}, document_id,
            "Alice", "Bob", alice_x, alice_ed.private_bytes_raw(), bob_x_public,
        )
        alice.upload_document(document_id, package)
        alice.share_document(document_id, "Bob", package)
        assert document_id in alice.list_documents()["owned"]
        assert document_id in bob.list_documents()["shared"]

        opened = bob.open_retrieved_document(document_id, bob_x)
        assert opened == b"secret document contents"
        assert bob_tofu.get_peer("Alice") is not None

        # A second request with the same ID returns the cached response and does not duplicate the write.
        replay = create_request("upload_document", {
            "document_id": document_id, "iv": package.encrypted_document.iv,
            "ciphertext": package.encrypted_document.ciphertext, "metadata": package.encrypted_document.metadata,
            "tag": package.encrypted_document.tag, "signature_content_hash": package.signature.content_hash,
            "signature_metadata": package.signature.metadata, "signature": package.signature.signature,
        }, alice.session_token, request_id="fixed-replay-id")
        first = alice.transport.request(replay)
        second = alice.transport.request(replay)
        assert first == second and first.success is False  # storage rejects first attempted duplicate

        tampered = SharedDocumentPackage(
            EncryptedDocument(package.encrypted_document.iv, bytes([package.encrypted_document.ciphertext[0] ^ 1]) + package.encrypted_document.ciphertext[1:], package.encrypted_document.metadata, package.encrypted_document.tag),
            package.wrapped_keys, package.signature,
        )
        with pytest.raises(IntegrityError):
            open_shared_document(tampered, document_id, "Alice", "Bob", bob_x, alice_x_public, alice_ed.public_key().public_bytes_raw())

        tampered_sig = SharedDocumentPackage(package.encrypted_document, package.wrapped_keys,
            DocumentSignature(package.signature.content_hash, package.signature.metadata, bytes([package.signature.signature[0] ^ 1]) + package.signature.signature[1:]))
        with pytest.raises(ProducerVerificationError):
            open_shared_document(tampered_sig, document_id, "Alice", "Bob", bob_x, alice_x_public, alice_ed.public_key().public_bytes_raw())

        raw = sqlite3.connect(tmp_path / "documents.db").iterdump().__str__()
        assert b"secret document contents" not in raw.encode()
    finally:
        alice.transport.close()
        bob.transport.close()
        server.close()
