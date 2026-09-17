"""Authentication-only demonstration. Key bytes are mocks from person 2."""

from pathlib import Path

from src.auth.auth_service import AuthService
from src.auth.login import client_create_proof
from src.auth.signup import prepare_signup


DEMO_DATABASE = Path("data/demo_users.db")


def signup(service: AuthService, username: str, password: str) -> None:
    prepared = prepare_signup(
        username=username,
        password=password,
        x25519_public_key=(username + "-x25519").encode().ljust(32, b"_"),
        ed25519_public_key=(username + "-ed25519").encode().ljust(32, b"_"),
        encrypted_private_key_bundle=(username + "-encrypted-private-keys").encode(),
    )
    result = service.signup(prepared)
    print(f"Sign-up {username}: {result.message}")


def login(service: AuthService, username: str, password: str):
    challenge = service.begin_login(username)
    proof = client_create_proof(password, challenge)
    result = service.finish_login(challenge.challenge_id, proof)
    print(f"Login {username}: {result.message}")
    return result


def main() -> None:
    if DEMO_DATABASE.exists():
        DEMO_DATABASE.unlink()
    service = AuthService(DEMO_DATABASE)
    signup(service, "Layla", "Layla-Strong-Password-2026")
    signup(service, "Omar", "Omar-Strong-Password-2026")

    layla = service.get_user("Layla")
    assert layla is not None
    print("\nStored credential record for Layla:")
    print("algorithm:", layla.password_record.algorithm)
    print("salt:", layla.password_record.salt.hex())
    print("password hash:", layla.password_record.password_hash.hex())
    print("memory cost:", layla.password_record.memory_cost, "KiB")
    print("plaintext password stored: NO")
    print("plaintext private key stored: NO")

    correct = login(service, "Layla", "Layla-Strong-Password-2026")
    login(service, "Layla", "wrong-password")
    login(service, "Nobody", "wrong-password")
    replay_challenge = service.begin_login("Omar")
    replay_proof = client_create_proof("Omar-Strong-Password-2026", replay_challenge)
    print("First proof:", service.finish_login(replay_challenge.challenge_id, replay_proof).message)
    print("Replayed proof:", service.finish_login(replay_challenge.challenge_id, replay_proof).message)
    if correct.session_token:
        print("Logout Layla:", service.logout(correct.session_token))


if __name__ == "__main__":
    main()
