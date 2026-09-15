"""Broad regression check for obvious account-enumeration timing differences."""

import statistics
import time

from src.auth.login import client_create_proof
from src.auth.signup import prepare_signup


def attempt(service, username, password):
    start = time.perf_counter()
    challenge = service.begin_login(username)
    proof = client_create_proof(password, challenge)
    result = service.finish_login(challenge.challenge_id, proof)
    return result, time.perf_counter() - start


def test_wrong_password_and_unknown_user_have_similar_cost(service):
    prepared = prepare_signup(
        "Layla",
        "Correct-Horse-2026",
        b"x" * 32,
        b"e" * 32,
        b"encrypted-private-key-bundle",
    )
    assert service.signup(prepared).success
    wrong_times = []
    unknown_times = []
    for _ in range(3):
        wrong_result, wrong_time = attempt(service, "Layla", "Wrong-Password-2026")
        unknown_result, unknown_time = attempt(service, "Nobody", "Wrong-Password-2026")
        assert wrong_result.message == unknown_result.message
        wrong_times.append(wrong_time)
        unknown_times.append(unknown_time)
    smaller = min(statistics.median(wrong_times), statistics.median(unknown_times))
    larger = max(statistics.median(wrong_times), statistics.median(unknown_times))
    assert larger / smaller < 2.0
