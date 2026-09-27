import sqlite3
import sys
from pathlib import Path

database = Path("data/documents.db")
backup = Path("demo1_ciphertext_backup.bin")

if not database.exists():
    raise SystemExit("Database not found: data/documents.db")

with sqlite3.connect(database) as connection:
    row = connection.execute(
        "SELECT document_ciphertext FROM documents WHERE document_id = ?",
        ("demo1",),
    ).fetchone()

    if row is None:
        raise SystemExit("Document demo1 not found")

    if sys.argv[1:] == ["restore"]:
        ciphertext = backup.read_bytes()
        message = "Original ciphertext restored."
    else:
        if backup.exists():
            raise SystemExit("Backup exists. Restore before testing again.")

        original = bytes(row[0])
        with backup.open("xb") as file:
            file.write(original)

        modified = bytearray(original)
        modified[0] ^= 1
        ciphertext = bytes(modified)
        message = "One bit changed in demo1 ciphertext."

    connection.execute(
        "UPDATE documents SET document_ciphertext = ? WHERE document_id = ?",
        (ciphertext, "demo1"),
    )

print(message)