"""Application request handler for the SecureVault wire protocol.

The handler is deliberately transport-independent: TCP and tests can use the
same dispatch function. The server never receives plaintext or document keys.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import asdict
from typing import Any

from src.auth.auth_service import AuthService
from src.auth.login import client_create_proof
from src.auth.models import PreparedSignup
from src.auth.password import PasswordRecord
from src.crypto.document_crypto import EncryptedDocument
from src.crypto.key_wrap import WrappedDocumentKeys
from src.crypto.signatures import DocumentSignature
from src.network.protocol import ProtocolMessage, create_response
from src.storage.document_store import DocumentStore


PUBLIC_OPERATIONS = {"signup", "login_begin", "login_finish"}
PROTECTED_OPERATIONS = {
    "get_public_keys", "upload_document", "share_document",
    "list_documents", "retrieve_document", "logout",
}
ALL_OPERATIONS = PUBLIC_OPERATIONS | PROTECTED_OPERATIONS


class RequestHandler:
    """Validate and execute one protocol request.

    Request IDs are cached per authenticated principal (or ``anonymous``).
    A repeated ID gets the exact original response and cannot execute a write
    twice. Storage primary keys provide a second line of defence.
    """

    def __init__(self, auth: AuthService, documents: DocumentStore,
                 replay_limit: int = 4096, replay_ttl: float = 3600.0) -> None:
        self.auth = auth
        self.documents = documents
        self.replay_limit = replay_limit
        self.replay_ttl = replay_ttl
        self._replay: OrderedDict[tuple[str, str], tuple[float, ProtocolMessage]] = OrderedDict()
        self._lock = threading.RLock()

    @staticmethod
    def _required(payload: dict, *names: str) -> None:
        missing = [name for name in names if name not in payload]
        if missing:
            raise ValueError("Missing fields: " + ", ".join(missing))

    @staticmethod
    def _prepared(payload: dict) -> PreparedSignup:
        RequestHandler._required(payload, "username", "password_record", "login_public_key",
                                 "x25519_public_key", "ed25519_public_key", "encrypted_private_key_bundle")
        record = payload["password_record"]
        if not isinstance(record, dict):
            raise ValueError("password_record must be an object")
        password_record = PasswordRecord(**record)
        return PreparedSignup(username=payload["username"], password_record=password_record,
                              login_public_key=payload["login_public_key"],
                              x25519_public_key=payload["x25519_public_key"],
                              ed25519_public_key=payload["ed25519_public_key"],
                              encrypted_private_key_bundle=payload["encrypted_private_key_bundle"])

    @staticmethod
    def _challenge(challenge) -> dict:
        return asdict(challenge)

    def _principal(self, request: ProtocolMessage) -> str:
        if request.operation in PUBLIC_OPERATIONS:
            return "anonymous"
        if not request.session_token:
            raise PermissionError("A valid session_token is required")
        username = self.auth.validate_session(request.session_token)
        if username is None:
            raise PermissionError("Invalid or expired session_token")
        return username

    def _remember_get(self, key):
        now = time.monotonic()
        with self._lock:
            for old_key, (created, _) in list(self._replay.items()):
                if now - created > self.replay_ttl:
                    self._replay.pop(old_key, None)
            item = self._replay.get(key)
            if item:
                self._replay.move_to_end(key)
                return item[1]
        return None

    def _remember_put(self, key, response):
        with self._lock:
            self._replay[key] = (time.monotonic(), response)
            self._replay.move_to_end(key)
            while len(self._replay) > self.replay_limit:
                self._replay.popitem(last=False)

    def dispatch(self, request: ProtocolMessage) -> ProtocolMessage:
        if request.kind != "request":
            return create_response(request, False, error_code="INVALID_MESSAGE", error_message="Expected request")
        if request.operation not in ALL_OPERATIONS:
            return create_response(request, False, error_code="UNKNOWN_OPERATION", error_message="Unknown operation")
        try:
            principal = self._principal(request)
            key = (principal, request.request_id)
            cached = self._remember_get(key)
            if cached is not None:
                return cached
            response = self._execute(request, principal)
        except PermissionError as error:
            response = create_response(request, False, error_code="UNAUTHORIZED", error_message=str(error))
        except (ValueError, TypeError, KeyError) as error:
            response = create_response(request, False, error_code="INVALID_REQUEST", error_message=str(error))
        except Exception:
            response = create_response(request, False, error_code="INTERNAL_ERROR", error_message="Request could not be completed")
        self._remember_put(key, response)
        return response

    def _execute(self, request: ProtocolMessage, principal: str) -> ProtocolMessage:
        p = request.payload
        op = request.operation
        if op == "signup":
            result = self.auth.signup(self._prepared(p))
            return create_response(request, result.success, {"username": result.username} if result.username else {}, result.error_code, result.message)
        if op == "login_begin":
            self._required(p, "username")
            challenge = self.auth.begin_login(p["username"])
            return create_response(request, True, self._challenge(challenge))
        if op == "login_finish":
            self._required(p, "challenge_id", "proof")
            result = self.auth.finish_login(p["challenge_id"], p["proof"])
            payload = {"username": result.username, "session_token": result.session_token}
            return create_response(request, result.success, payload, result.error_code, result.message)
        if op == "logout":
            return create_response(request, self.auth.logout(request.session_token), {}, None, "Logged out")
        if op == "get_public_keys":
            self._required(p, "username")
            keys = self.auth.store.get_public_keys(p["username"])
            if keys is None:
                return create_response(request, False, error_code="USER_NOT_FOUND", error_message="User not found")
            return create_response(request, True, {"username": p["username"], "x25519_public_key": keys[0], "ed25519_public_key": keys[1]})
        if op == "upload_document":
            self._required(p, "document_id", "iv", "ciphertext", "metadata", "tag", "signature_content_hash", "signature_metadata", "signature")
            doc = EncryptedDocument(p["iv"], p["ciphertext"], p["metadata"], p["tag"])
            sig = DocumentSignature(p["signature_content_hash"], p["signature_metadata"], p["signature"])
            stored = self.documents.create_document(p["document_id"], principal, doc, sig)
            return create_response(request, True, {"document_id": stored.document_id}, error_message="Document uploaded")
        if op == "share_document":
            self._required(p, "document_id", "recipient_username", "kdf_salt", "iv", "ciphertext", "metadata", "tag")
            wrapped = WrappedDocumentKeys(p["kdf_salt"], p["iv"], p["ciphertext"], p["metadata"], p["tag"])
            stored = self.documents.create_share(p["document_id"], principal, p["recipient_username"], wrapped)
            return create_response(request, True, {"document_id": stored.document_id, "recipient_username": stored.recipient_username}, error_message="Document shared")
        if op == "list_documents":
            return create_response(request, True, {"owned": self.documents.list_owned_documents(principal), "shared": self.documents.list_shared_documents(principal)})
        if op == "retrieve_document":
            self._required(p, "document_id")
            doc, share = self.documents.retrieve_for_recipient(p["document_id"], principal)
            return create_response(request, True, {"document_id": doc.document_id, "owner_username": doc.owner_username,
                "iv": doc.encrypted_document.iv, "ciphertext": doc.encrypted_document.ciphertext,
                "metadata": doc.encrypted_document.metadata, "tag": doc.encrypted_document.tag,
                "signature_content_hash": doc.signature.content_hash, "signature_metadata": doc.signature.metadata,
                "signature": doc.signature.signature, "kdf_salt": share.wrapped_keys.kdf_salt,
                "wrapped_iv": share.wrapped_keys.iv, "wrapped_ciphertext": share.wrapped_keys.ciphertext,
                "wrapped_metadata": share.wrapped_keys.metadata, "wrapped_tag": share.wrapped_keys.tag})
        raise ValueError("Unsupported operation")
