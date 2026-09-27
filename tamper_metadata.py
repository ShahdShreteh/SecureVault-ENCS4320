import json
import sqlite3
import sys
from pathlib import Path

database = Path("data/documents.db")
backup = Path("demo1_metadata_backup.bin")

if not database.exists():
    raise SystemExit("Database not found")

with sqlite3.connect(database) as connection:
    row = connection.execute(
        "SELECT document_metadata FROM documents WHERE document_id = ?",
        ("demo1",),
    ).fetchone()

    if row is None:
        raise SystemExit("Document demo1 not found")

    if sys.argv[1:] == ["restore"]:
        metadata = backup.read_bytes()
        message = "Original metadata restored."
    else:
        if backup.exists():
            raise SystemExit("Backup exists. Restore before testing again.")

        original = bytes(row[0])
        modified = json.loads(original.decode("utf-8"))
        modified["filename"] = "changed_name.txt"

        metadata = json.dumps(
            modified,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        with backup.open("xb") as file:
            file.write(original)

        message = "Metadata filename changed to changed_name.txt"

    connection.execute(
        "UPDATE documents SET document_metadata = ? WHERE document_id = ?",
        (metadata, "demo1"),
    )

print(message)