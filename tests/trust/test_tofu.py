import pytest

from src.crypto.signatures import (
    generate_ed25519_keypair,
)
from src.crypto.x25519 import (
    generate_keypair,
)
from src.trust.tofu import (
    KeyChangeDetected,
    TrustError,
    TofuTrustStore,
    compute_fingerprint,
    verification_code,
)


def make_keys():

    _, x_public = (
        generate_keypair()
    )

    _, ed_public = (
        generate_ed25519_keypair()
    )

    return (
        x_public,
        ed_public,
    )


def test_first_use_stores_peer(
    tmp_path,
):

    store = TofuTrustStore(
        tmp_path / "trust.db"
    )

    x_public, ed_public = (
        make_keys()
    )

    peer = store.observe_peer(
        "Alice",
        x_public,
        ed_public,
    )

    assert peer.username == "Alice"

    assert (
        peer.x25519_public_key
        == x_public
    )

    assert (
        peer.ed25519_public_key
        == ed_public
    )

    assert not peer.manually_verified


def test_same_keys_are_accepted_again(
    tmp_path,
):

    store = TofuTrustStore(
        tmp_path / "trust.db"
    )

    x_public, ed_public = (
        make_keys()
    )

    first = store.observe_peer(
        "Alice",
        x_public,
        ed_public,
    )

    second = store.observe_peer(
        "Alice",
        x_public,
        ed_public,
    )

    assert first == second


def test_x25519_key_change_is_rejected(
    tmp_path,
):

    store = TofuTrustStore(
        tmp_path / "trust.db"
    )

    first_x, ed_public = (
        make_keys()
    )

    second_x, _ = (
        make_keys()
    )

    store.observe_peer(
        "Alice",
        first_x,
        ed_public,
    )

    with pytest.raises(
        KeyChangeDetected
    ):
        store.observe_peer(
            "Alice",
            second_x,
            ed_public,
        )


def test_ed25519_key_change_is_rejected(
    tmp_path,
):

    store = TofuTrustStore(
        tmp_path / "trust.db"
    )

    x_public, first_ed = (
        make_keys()
    )

    _, second_ed = (
        make_keys()
    )

    store.observe_peer(
        "Alice",
        x_public,
        first_ed,
    )

    with pytest.raises(
        KeyChangeDetected
    ):
        store.observe_peer(
            "Alice",
            x_public,
            second_ed,
        )


def test_trust_survives_restart(
    tmp_path,
):

    database = (
        tmp_path / "trust.db"
    )

    x_public, ed_public = (
        make_keys()
    )

    first_store = (
        TofuTrustStore(
            database
        )
    )

    first_store.observe_peer(
        "Alice",
        x_public,
        ed_public,
    )

    second_store = (
        TofuTrustStore(
            database
        )
    )

    peer = second_store.get_peer(
        "Alice"
    )

    assert peer is not None

    assert (
        peer.x25519_public_key
        == x_public
    )

    assert (
        peer.ed25519_public_key
        == ed_public
    )


def test_fingerprint_is_deterministic():

    x_public, ed_public = (
        make_keys()
    )

    first = compute_fingerprint(
        "Alice",
        x_public,
        ed_public,
    )

    second = compute_fingerprint(
        "Alice",
        x_public,
        ed_public,
    )

    assert first == second


def test_different_keys_change_fingerprint():

    first_x, first_ed = (
        make_keys()
    )

    second_x, second_ed = (
        make_keys()
    )

    first = compute_fingerprint(
        "Alice",
        first_x,
        first_ed,
    )

    second = compute_fingerprint(
        "Alice",
        second_x,
        second_ed,
    )

    assert first != second


def test_different_username_changes_fingerprint():

    x_public, ed_public = (
        make_keys()
    )

    alice = compute_fingerprint(
        "Alice",
        x_public,
        ed_public,
    )

    bob = compute_fingerprint(
        "Bob",
        x_public,
        ed_public,
    )

    assert alice != bob


def test_verification_code_matches(
    tmp_path,
):

    store = TofuTrustStore(
        tmp_path / "trust.db"
    )

    x_public, ed_public = (
        make_keys()
    )

    store.observe_peer(
        "Alice",
        x_public,
        ed_public,
    )

    code = verification_code(
        "Alice",
        x_public,
        ed_public,
    )

    assert store.verify_code(
        "Alice",
        code,
    )

def test_wrong_verification_code_fails(
    tmp_path,
):

    store = TofuTrustStore(
        tmp_path / "trust.db"
    )

    x_public, ed_public = (
        make_keys()
    )

    store.observe_peer(
        "Alice",
        x_public,
        ed_public,
    )

    assert not store.verify_code(
        "Alice",
        "0000 0000 0000 0000 0000 0000",
    )


def test_mark_peer_verified(
    tmp_path,
):

    store = TofuTrustStore(
        tmp_path / "trust.db"
    )

    x_public, ed_public = (
        make_keys()
    )

    store.observe_peer(
        "Alice",
        x_public,
        ed_public,
    )

    peer = store.mark_verified(
        "Alice"
    )

    assert peer.manually_verified


def test_unknown_peer_cannot_be_marked_verified(
    tmp_path,
):

    store = TofuTrustStore(
        tmp_path / "trust.db"
    )

    with pytest.raises(
        TrustError
    ):
        store.mark_verified(
            "Nobody"
        )


def test_unknown_peer_returns_none(
    tmp_path,
):

    store = TofuTrustStore(
        tmp_path / "trust.db"
    )

    assert (
        store.get_peer(
            "Nobody"
        )
        is None
    )


def test_invalid_x25519_key_length(
    tmp_path,
):

    store = TofuTrustStore(
        tmp_path / "trust.db"
    )

    _, ed_public = (
        make_keys()
    )

    with pytest.raises(
        TrustError
    ):
        store.observe_peer(
            "Alice",
            b"short",
            ed_public,
        )


def test_invalid_ed25519_key_length(
    tmp_path,
):

    store = TofuTrustStore(
        tmp_path / "trust.db"
    )

    x_public, _ = (
        make_keys()
    )

    with pytest.raises(
        TrustError
    ):
        store.observe_peer(
            "Alice",
            x_public,
            b"short",
        )