from src.auth.password import create_password_record, verify_password


def test_same_password_has_different_records():
    first = create_password_record("Correct-Horse-2026")
    second = create_password_record("Correct-Horse-2026")
    assert first.salt != second.salt
    assert first.password_hash != second.password_hash


def test_correct_password_passes_and_wrong_password_fails():
    record = create_password_record("Correct-Horse-2026")
    assert verify_password("Correct-Horse-2026", record)
    assert not verify_password("Wrong-Password-2026", record)


def test_record_does_not_contain_plaintext_password():
    password = "Correct-Horse-2026"
    record = create_password_record(password)
    assert password.encode() not in record.salt
    assert password.encode() not in record.password_hash
