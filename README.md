# SecureVault

**ENCS4320 – Applied Cryptography (Term 1253), Birzeit University**

SecureVault is a multi-user encrypted document exchange system. Users store and
share documents through a server they do not trust: the server keeps every byte,
but it cannot read a document, learn a password, or change a file without the
change being detected. All client–server traffic runs inside TLS 1.2+.

## Team Members

| Name | Student ID |
|------|------------|
| Shahd Shreteh   | 1210444 |
| Besan Maaly     | 1222776 |
| Dania Abuayyash | 1210464 |

Instructor: Dr. Ahmad Shawahna — Section 2

---

## Security Design at a Glance

| Goal | Mechanism |
|------|-----------|
| Password protection | Argon2id (32 MiB, t=1, p=1, 16-byte salt); the password never leaves the client; challenge-response login with a fresh nonce and ephemeral X25519 key |
| Confidentiality | AES-256-CBC with fresh random keys and IV for every document |
| Integrity | HMAC-SHA256, Encrypt-then-MAC, verified **before** decryption |
| Key sharing | X25519 + HKDF-SHA256 key wrapping for the recipient |
| Origin + non-repudiation | Ed25519 signature over SHA-256(plaintext) and the canonical metadata |
| Public-key trust | Trust-On-First-Use (TOFU) with key-change detection |
| Freshness | Single-use login challenges, request-ID replay cache, unique document IDs |
| Transport | TLS 1.2+; the client trusts only `server.crt` (checks certificate and host name) |
| Private keys at rest | Encrypted local wallet (AES-256-CBC + HMAC, keys from Argon2id + HKDF) |

Core implementations of AES-256, CBC, PKCS#7, HMAC-SHA256, HKDF-SHA256, X25519, Encrypt-then-MAC, key wrapping, TOFU, and wallet protection were written by the team. Libraries are used for Argon2id, Ed25519, SHA-256, TLS, and the X25519/HMAC operations inside the login path.

---

## Project Structure

```
SecureVault-ENCS4320-main/
├── securevault_cli.py        # TLS server launcher + interactive client shell
├── generate_tls_cert.py      # creates server.crt / server.key (self-signed, RSA-3072)
├── tamper_test.py            # demo: flips one bit of a stored ciphertext
├── tamper_metadata.py        # demo: changes the file name inside stored metadata
├── src/
│   ├── auth/                 # Argon2id, sign-up, challenge-response login, sessions
│   ├── crypto/               # AES, CBC, padding, HMAC, HKDF, X25519, EtM, key wrap, signatures
│   ├── network/              # length-prefixed JSON protocol, TLS TCP server/client, request handler
│   ├── storage/              # SQLite document store
│   └── trust/                # TOFU trust store and fingerprints
├── tests/                    # 219 pytest tests (auth, crypto, network, storage, trust)
├── scripts/
│   ├── benchmark_argon2.py         # measures Argon2id time per guess
│   └── estimate_offline_attack.py  # offline-guessing arithmetic
└── demo/demo_auth.py         # authentication-only demo
```

---

## Requirements

- Python 3.10+ (tested with Python 3.13 on Windows 11)
- Packages: `cryptography`, `argon2-cffi`, `pytest`

```bash
python -m pip install cryptography argon2-cffi pytest
```

---

## How to Run

All commands are run from the project root folder.

### 1. Generate the TLS certificate (once)

```bash
python generate_tls_cert.py
```

Creates `server.crt` (certificate, given to clients) and `server.key`
(private key, stays on the server).

### 2. Start the server (terminal 1)

```bash
python securevault_cli.py server --cert server.crt --key server.key
```

Expected output:

```
SecureVault server listening on 127.0.0.1:5000
Press Ctrl+C to stop.
```

### 3. Start two clients (terminals 2 and 3)

Each user needs a separate `--data-dir`, so each has their own wallet and TOFU store.

```bash
python securevault_cli.py shell --ca-cert server.crt --data-dir data/alice
python securevault_cli.py shell --ca-cert server.crt --data-dir data/bob
```

Optional flags for both modes: `--host` (default `127.0.0.1`) and `--port` (default `5000`).

### 4. Use the shell

| Command | What it does |
|---------|--------------|
| `signup USER PASSWORD` | create an account and an encrypted local wallet |
| `login USER PASSWORD` | log in and receive a session token |
| `keys USER` | fetch a user's public keys and apply TOFU |
| `upload FILE RECIPIENT [DOCUMENT_ID]` | encrypt, sign, upload and share a file |
| `list` | list owned and shared documents |
| `retrieve DOCUMENT_ID [OUTPUT_FILE]` | download, verify and decrypt |
| `logout` | end the session |
| `whoami` / `help` / `quit` | current user / help / exit |

### Example session

Alice's terminal:

```
securevault> signup Alice AliceTest2026
securevault> login Alice AliceTest2026
securevault> upload massage.txt Bob demo2
Upload successful: demo2
Share successful: Alice -> Bob
Server received encrypted document fields only.
```

Bob's terminal:

```
securevault> signup Bob BobTest2026
securevault> login Bob BobTest2026
securevault> retrieve demo2 received_demo2.txt
Retrieve successful: demo2
Decrypted file written to: received_demo2.txt
HMAC verification: OK
Ed25519 signature verification: OK
```

(Bob must sign up before Alice uploads, because Alice needs Bob's public keys.)

---

## Tamper Demonstrations

Both scripts act as a malicious server that edits `data/documents.db` directly.
They work on a document with ID **`demo1`**, so first upload one as Alice
(`upload FILE Bob demo1`) and retrieve it once as Bob to see it succeed.

**Ciphertext tampering (one bit changed):**

```bash
python tamper_test.py            # flips one bit of demo1's ciphertext
# Bob: retrieve demo1 out.txt  ->  ERROR: Document integrity verification failed.
python tamper_test.py restore    # puts the original ciphertext back
```

**Metadata tampering (file name changed):**

```bash
python tamper_metadata.py            # renames the file to changed_name.txt in the metadata
# Bob: retrieve demo1 out.txt  ->  ERROR: Document integrity verification failed.
python tamper_metadata.py restore    # puts the original metadata back
```

Each script keeps a backup (`demo1_ciphertext_backup.bin` /
`demo1_metadata_backup.bin`) and refuses to run twice until you restore.

---

## Running the Tests

```bash
python -m pytest tests -q
```

Result: **219 passed**. Tests use official vectors (NIST SP 800-38A, RFC 4231,
RFC 5869, RFC 7748, RFC 8032), cross-checks against the `cryptography`
library, and negative tests that change one byte or field and expect a rejection.

Useful subsets:

```bash
python -m pytest tests/crypto -v                                    # every primitive
python -m pytest tests/auth/test_login.py::test_challenge_cannot_be_replayed -v
```

Benchmarks:

```bash
python scripts/benchmark_argon2.py
python scripts/estimate_offline_attack.py 0.0238
```

---

## Resetting the Demo

To start from a clean state, stop the server and delete the local data:

```bash
# Windows
rmdir /s /q data
# Linux / macOS
rm -rf data
```

This removes users, documents, wallets and TOFU stores. Keep `server.crt` and
`server.key`, or regenerate them with `generate_tls_cert.py`.

---

## Known Limitations

- The TLS certificate is self-signed: it is only as safe as the way `server.crt`
  reaches each client, and `server.key` is stored unencrypted.
- The signed SHA-256 of the plaintext is visible to the server.
- There is no signed timestamp or counter, so the client cannot tell an old
  version of a document from a new one.
- TOFU cannot detect a key swap at the very first contact.
- One recipient per upload; no password change or key revocation yet.

See the design report for the full threat model, justifications and security argument.
