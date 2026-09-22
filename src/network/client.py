"""High-level client integration: auth, TOFU, upload/share/retrieve."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from src.auth.login import client_create_proof
from src.auth.models import LoginChallenge, PreparedSignup
from src.crypto.sharing import SharedDocumentPackage, open_shared_document
from src.network.protocol import create_request
from src.trust.tofu import TofuTrustStore

from .tcp import SecureVaultTCPClient


class ClientRequestError(RuntimeError):
    pass


class SecureVaultClient:
    def __init__(self, transport: SecureVaultTCPClient, username: str | None = None,
                 trust_store: TofuTrustStore | None = None) -> None:
        self.transport = transport
        self.username = username
        self.session_token: str | None = None
        self.trust_store = trust_store

    def _call(self, operation: str, payload: dict | None = None, protected: bool = True,
              request_id: str | None = None) -> dict:
        token = self.session_token if protected else None
        response = self.transport.request(create_request(operation, payload or {}, token, request_id))
        if not response.success:
            raise ClientRequestError(f"{response.error_code}: {response.error_message}")
        return response.payload

    def signup(self, prepared: PreparedSignup) -> dict:
        return self._call("signup", asdict(prepared), protected=False)

    def login(self, password: str) -> str:
        if not self.username:
            raise ValueError("username is required")
        challenge_payload = self._call("login_begin", {"username": self.username}, protected=False)
        challenge = LoginChallenge(**challenge_payload)
        proof = client_create_proof(password, challenge)
        result = self._call("login_finish", {"challenge_id": challenge.challenge_id, "proof": proof}, protected=False)
        self.session_token = result["session_token"]
        return self.session_token

    def logout(self) -> None:
        self._call("logout")
        self.session_token = None

    def get_public_keys(self, username: str) -> tuple[bytes, bytes]:
        result = self._call("get_public_keys", {"username": username})
        x_key, ed_key = result["x25519_public_key"], result["ed25519_public_key"]
        if self.trust_store is not None:
            self.trust_store.observe_peer(username, x_key, ed_key)
        return x_key, ed_key

    def upload_document(self, document_id: str, package: SharedDocumentPackage) -> dict:
        return self._call("upload_document", {"document_id": document_id,
            "iv": package.encrypted_document.iv, "ciphertext": package.encrypted_document.ciphertext,
            "metadata": package.encrypted_document.metadata, "tag": package.encrypted_document.tag,
            "signature_content_hash": package.signature.content_hash,
            "signature_metadata": package.signature.metadata, "signature": package.signature.signature})

    def share_document(self, document_id: str, recipient_username: str, package: SharedDocumentPackage) -> dict:
        return self._call("share_document", {"document_id": document_id,
            "recipient_username": recipient_username, "kdf_salt": package.wrapped_keys.kdf_salt,
            "iv": package.wrapped_keys.iv, "ciphertext": package.wrapped_keys.ciphertext,
            "metadata": package.wrapped_keys.metadata, "tag": package.wrapped_keys.tag})

    def list_documents(self) -> dict:
        return self._call("list_documents")

    def retrieve_document(self, document_id: str) -> tuple[dict, SharedDocumentPackage]:
        result = self._call("retrieve_document", {"document_id": document_id})
        from src.crypto.document_crypto import EncryptedDocument
        from src.crypto.key_wrap import WrappedDocumentKeys
        from src.crypto.signatures import DocumentSignature
        package = SharedDocumentPackage(
            encrypted_document=EncryptedDocument(result["iv"], result["ciphertext"], result["metadata"], result["tag"]),
            wrapped_keys=WrappedDocumentKeys(result["kdf_salt"], result["wrapped_iv"], result["wrapped_ciphertext"], result["wrapped_metadata"], result["wrapped_tag"]),
            signature=DocumentSignature(result["signature_content_hash"], result["signature_metadata"], result["signature"]),
        )
        return result, package

    def open_retrieved_document(self, document_id: str, recipient_private_key: bytes) -> bytes:
        result, package = self.retrieve_document(document_id)
        owner = result["owner_username"]
        sender_x25519, sender_ed25519 = self.get_public_keys(owner)
        return open_shared_document(package, document_id, owner, self.username,
                                    recipient_private_key, sender_x25519, sender_ed25519)
