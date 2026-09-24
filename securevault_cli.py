"""Interactive SecureVault terminal client and TCP server launcher.

This file is a demonstration CLI around the existing project APIs. It does not
replace the protocol, request handler, or cryptographic modules.

Examples:
    python securevault_cli.py server
    python securevault_cli.py shell
"""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import threading
import hmac
from dataclasses import asdict
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.auth.auth_service import AuthService
from src.auth.models import PasswordRecord
from src.auth.password import create_password_record, derive_password_secret
from src.auth.signup import prepare_signup
from src.crypto.cbc import cbc_decrypt, cbc_encrypt, generate_iv
from src.crypto.hkdf_sha256 import hkdf_expand, hkdf_extract
from src.crypto.hmac_sha256 import hmac_sha256
from src.crypto.sharing import create_shared_document
from src.crypto.x25519 import derive_public_key
from src.network.client import ClientRequestError, SecureVaultClient
from src.network.tcp import SecureVaultTCPClient, SecureVaultTCPServer
from src.storage.document_store import DocumentStore
from src.trust.tofu import TofuTrustStore, compute_fingerprint

DEFAULT_DATA = Path("data")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000
WALLET_DOMAIN = b"SecureVault-CLI-wallet-v1" #separates wallet encryption from any other use of HMAC or HKDF


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)

#password -> Argon2id -> password_secret -> HKDF -> encryption_key & mac_key
def _wallet_keys(
    password: str,
    record: PasswordRecord,
) -> tuple[bytes, bytes]:
    password_secret = derive_password_secret(
        password,
        record,
    )

    pseudorandom_key = hkdf_extract(
        record.salt,
        password_secret,
    )

    derived = hkdf_expand(
        pseudorandom_key,
        WALLET_DOMAIN,
        64,
    )

    encryption_key = derived[:32]
    mac_key = derived[32:]

    return encryption_key, mac_key

#take the private key and place it temporarily within the plaintext in memory 
def _encrypt_wallet(
    username: str,
    password: str,
    x_private: bytes,
    ed_private: bytes,
) -> dict:
    record = create_password_record(password)

    encryption_key, mac_key = _wallet_keys(
        password,
        record,
    )

    plaintext = json.dumps(
        {
            "username": username,
            "x25519_private_key": _b64(x_private),
            "ed25519_private_key": _b64(ed_private),
        },
        separators=(",", ":"),
    ).encode("utf-8")

    iv = generate_iv()

    ciphertext = cbc_encrypt(
        plaintext,
        encryption_key,
        iv,
    )

    tag = hmac_sha256(
        mac_key,
        WALLET_DOMAIN
        + record.salt
        + iv
        + ciphertext,
    )

    return {
        "format": "SecureVault-EncryptedWallet-v1",
        "username": username,
        "password_record": {
            **asdict(record),
            "salt": _b64(record.salt),
        },
        "iv": _b64(iv),
        "ciphertext": _b64(ciphertext),
        "tag": _b64(tag),
    }

def _decrypt_wallet(
    wallet: dict,
    password: str,
) -> dict:
    if wallet.get("format") != "SecureVault-EncryptedWallet-v1":
        raise RuntimeError(
            "Wallet is not encrypted. "
            "Delete it and run signup again."
        )

    try:
        record_data = wallet["password_record"]

        record = PasswordRecord(
            **{
                **record_data,
                "salt": _unb64(record_data["salt"]),
            }
        )

        encryption_key, mac_key = _wallet_keys(
            password,
            record,
        )

        iv = _unb64(wallet["iv"])
        ciphertext = _unb64(wallet["ciphertext"])
        tag = _unb64(wallet["tag"])

        expected = hmac_sha256(
            mac_key,
            WALLET_DOMAIN
            + record.salt
            + iv
            + ciphertext,
        )

        if not hmac.compare_digest(expected, tag):
            raise RuntimeError(
                "Invalid wallet password or corrupted wallet."
            )

        plaintext = cbc_decrypt(
            ciphertext,
            encryption_key,
            iv,
        )

        decoded = json.loads(
            plaintext.decode("utf-8")
        )

        if decoded.get("username") != wallet.get("username"):
            raise RuntimeError(
                "Wallet username mismatch."
            )

        return decoded

    except (
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise RuntimeError(
            "Invalid wallet password or corrupted wallet."
        ) from error



def _ed_public(private_key: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()


class CLI:
    def __init__(self, host: str, port: int, data_dir: Path):
        self.host = host
        self.port = port
        self.data_dir = data_dir
        self.wallet_dir = data_dir / "cli_wallets"
        self.wallet_dir.mkdir(parents=True, exist_ok=True)
        self.current_username: str | None = None
        self.current_wallet: dict | None = None
        self.clients: dict[str, SecureVaultClient] = {}
        self.transports: dict[str, SecureVaultTCPClient] = {}

    def wallet_path(self, username: str) -> Path:
        return self.wallet_dir / f"{username}.json"

    def load_wallet_file(self, username: str) -> dict:
        path = self.wallet_path(username)
        if not path.exists():
            raise RuntimeError(f"No local wallet for {username}. Run: signup {username}")
        return json.loads(path.read_text(encoding="utf-8"))

    def save_wallet(self, username: str, wallet: dict) -> None:
        self.wallet_path(username).write_text(json.dumps(wallet, indent=2), encoding="utf-8")

    def client(self, username: str) -> SecureVaultClient:
        if username not in self.clients:
            transport = SecureVaultTCPClient(self.host, self.port)
            trust = TofuTrustStore(self.data_dir / "tofu" / f"{username}.db")
            self.transports[username] = transport
            self.clients[username] = SecureVaultClient(transport, username, trust)
        return self.clients[username]

    def signup(self, username: str, password: str) -> None:
        if self.wallet_path(username).exists():
            raise RuntimeError(f"Local wallet already exists: {self.wallet_path(username)}")
        x_private = secrets.token_bytes(32)
        x_public = derive_public_key(x_private)
        ed_private = Ed25519PrivateKey.generate()
        ed_private_raw = ed_private.private_bytes_raw()
        ed_public = ed_private.public_key().public_bytes_raw()
        encrypted_wallet = _encrypt_wallet(
            username=username,
            password=password,
            x_private=x_private,
            ed_private=ed_private_raw,
        )

        prepared = prepare_signup(
            username=username,
            password=password,
            x25519_public_key=x_public,
            ed25519_public_key=ed_public,
            encrypted_private_key_bundle=json.dumps(
                encrypted_wallet,
                separators=(",", ":"),
            ).encode("utf-8"),
        )

        result = self.client(username).signup(
            prepared
        )

        self.save_wallet(
            username,
            encrypted_wallet,
        )

        print(f"Signup successful for {username}: {result}")
        print(f"Local wallet saved at {self.wallet_path(username)}")

    def login(
        self,
        username: str,
        password: str,
    ) -> None:
        wallet_file = self.load_wallet_file(
            username
        )

        wallet = _decrypt_wallet(
            wallet_file,
            password,
        )

        token = self.client(username).login(
            password
        )

        self.current_username = username
        self.current_wallet = wallet

        print(
            f"Login successful: {username}"
        )

        print(
            f"Session token received: "
            f"{token[:12]}... "
            f"(hidden remainder)"
        )


    def require_current(
        self,
    ) -> tuple[str, SecureVaultClient, dict]:
        if not self.current_username:
            raise RuntimeError(
                "No logged-in user. "
                "Use: login USER PASSWORD"
            )

        if self.current_wallet is None:
            raise RuntimeError(
                "Local wallet is locked. "
                "Log in again."
            )

        username = self.current_username

        return (
            username,
            self.client(username),
            self.current_wallet,
        )


    def get_keys(self, username: str) -> None:
        _, client, _ = self.require_current()
        x_key, ed_key = client.get_public_keys(username)
        print(f"Public keys received for {username}")
        print("X25519:", x_key.hex())
        print("Ed25519:", ed_key.hex())
        print("TOFU fingerprint:", compute_fingerprint(username, x_key, ed_key))

    def list_documents(self) -> None:
        _, client, _ = self.require_current()
        print(json.dumps(client.list_documents(), indent=2))

    def upload_and_share(self, filename: str, recipient: str, document_id: str | None) -> None:
        username, client, wallet = self.require_current()
        path = Path(filename)
        if not path.is_file():
            raise RuntimeError(f"File not found: {path}")
        if not document_id:
            document_id = f"{username.lower()}-{secrets.token_hex(6)}"
        recipient_x, _ = client.get_public_keys(recipient)
        plaintext = path.read_bytes()
        package = create_shared_document(
            plaintext=plaintext,
            metadata={"filename": path.name, "size": len(plaintext)},
            document_id=document_id,
            sender_username=username,
            recipient_username=recipient,
            sender_x25519_private_key=_unb64(wallet["x25519_private_key"]),
            sender_ed25519_private_key=_unb64(wallet["ed25519_private_key"]),
            recipient_x25519_public_key=recipient_x,
        )
        client.upload_document(document_id, package)
        client.share_document(document_id, recipient, package)
        print(f"Upload successful: {document_id}")
        print(f"Share successful: {username} -> {recipient}")
        print("Server received encrypted document fields only.")

    def retrieve(self, document_id: str, output: str) -> None:
        username, client, wallet = self.require_current()
        plaintext = client.open_retrieved_document(
            document_id,
            _unb64(wallet["x25519_private_key"]),
        )
        Path(output).write_bytes(plaintext)
        print(f"Retrieve successful: {document_id}")
        print(f"Decrypted file written to: {output}")
        print("HMAC verification: OK")
        print("Ed25519 signature verification: OK")

    def logout(self) -> None:
        username, client, _ = self.require_current()
        client.logout()
        self.current_username = None
        self.current_wallet = None
        print(f"Logged out: {username}")

    def close(self) -> None:
        for transport in self.transports.values():
            transport.close()


def run_server(host: str, port: int, data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    auth = AuthService(data_dir / "users.db")
    documents = DocumentStore(data_dir / "documents.db")
    from src.network.request_handler import RequestHandler
    handler = RequestHandler(auth, documents)
    server = SecureVaultTCPServer(handler, host=host, port=port)
    actual_host, actual_port = server.start()
    print(f"SecureVault server listening on {actual_host}:{actual_port}")
    print("Press Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("Stopping server...")
    finally:
        server.close()


HELP = """Commands:
  signup USER PASSWORD                  create an account and local wallet
  login USER PASSWORD                   obtain a session token
  keys USER                             fetch public keys and apply TOFU
  upload FILE RECIPIENT [DOCUMENT_ID]  encrypt, upload, and share a file
  list                                  list owned/shared documents
  retrieve DOCUMENT_ID [OUTPUT_FILE]   retrieve, verify, decrypt
  logout                                invalidate the current session
  whoami                                show the current logged-in user
  help                                  show this help
  quit                                  exit the CLI
"""


def run_shell(host: str, port: int, data_dir: Path) -> None:
    cli = CLI(host, port, data_dir)
    print("SecureVault interactive CLI")
    print(f"Connected target: {host}:{port}")
    print("Type 'help' for commands.")
    try:
        while True:
            try:
                line = input("securevault> ").strip()
            except EOFError:
                break
            if not line:
                continue
            parts = line.split()
            command = parts[0].lower()
            try:
                if command in {"quit", "exit"}:
                    break
                if command == "help":
                    print(HELP)
                elif command == "signup" and len(parts) == 3:
                    cli.signup(parts[1], parts[2])
                elif command == "login" and len(parts) == 3:
                    cli.login(parts[1], parts[2])
                elif command == "keys" and len(parts) == 2:
                    cli.get_keys(parts[1])
                elif command == "upload" and len(parts) in {3, 4}:
                    cli.upload_and_share(parts[1], parts[2], parts[3] if len(parts) == 4 else None)
                elif command == "list" and len(parts) == 1:
                    cli.list_documents()
                elif command == "retrieve" and len(parts) in {2, 3}:
                    cli.retrieve(parts[1], parts[2] if len(parts) == 3 else f"retrieved-{parts[1]}")
                elif command == "logout" and len(parts) == 1:
                    cli.logout()
                elif command == "whoami" and len(parts) == 1:
                    print(cli.current_username or "not logged in")
                else:
                    print("Invalid command. Type 'help'.")
            except (ClientRequestError, ValueError, OSError, RuntimeError) as error:
                print(f"ERROR: {error}")
    finally:
        cli.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureVault TCP CLI")
    parser.add_argument("mode", choices=["server", "shell"])
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA)
    args = parser.parse_args()
    if args.mode == "server":
        run_server(args.host, args.port, args.data_dir)
    else:
        run_shell(args.host, args.port, args.data_dir)


if __name__ == "__main__":
    main()
