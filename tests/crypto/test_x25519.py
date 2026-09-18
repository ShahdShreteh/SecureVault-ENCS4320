import pytest

from cryptography.hazmat.primitives import (
    serialization,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from src.crypto.x25519 import (
    KEY_SIZE,
    X25519Error,
    clamp_scalar,
    compute_shared_secret,
    derive_public_key,
    generate_keypair,
    x25519,
)


def test_rfc7748_vector_1():

    scalar = bytes.fromhex(
        "a546e36bf0527c9d3b16154b82465edd"
        "62144c0ac1fc5a18506a2244ba449ac4"
    )

    coordinate = bytes.fromhex(
        "e6db6867583030db3594c1a424b15f7c"
        "726624ec26b3353b10a903a6d0ab1c4c"
    )

    expected = bytes.fromhex(
        "c3da55379de9c6908e94ea4df28d084f"
        "32eccf03491c71f754b4075577a28552"
    )

    assert (
        x25519(
            scalar,
            coordinate,
        )
        == expected
    )


def test_rfc7748_vector_2():

    scalar = bytes.fromhex(
        "4b66e9d4d1b4673c5ad22691957d6af5"
        "c11b6421e0ea01d42ca4169e7918ba0d"
    )

    coordinate = bytes.fromhex(
        "e5210f12786811d3f4b7959d0538ae2c"
        "31dbe7106fc03c3efc4cd549c715a493"
    )

    expected = bytes.fromhex(
        "95cbde9476e8907d7aade45cb4b873f8"
        "8b595a68799fa152e6f8f7647aac7957"
    )

    assert (
        x25519(
            scalar,
            coordinate,
        )
        == expected
    )


def test_public_key_matches_reference():

    private_key = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645"
        "df4c2f87ebc0992ab177fba51db92c2a"
    )

    ours = derive_public_key(
        private_key
    )

    reference_private = (
        X25519PrivateKey
        .from_private_bytes(
            private_key
        )
    )

    reference_public = (
        reference_private
        .public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )

    assert ours == reference_public


def test_shared_secret_matches_reference():

    alice_private = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645"
        "df4c2f87ebc0992ab177fba51db92c2a"
    )

    bob_private = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee6"
        "6f3bb1292618b6fd1c2f8b27ff88e0eb"
    )

    alice_public = derive_public_key(
        alice_private
    )

    bob_public = derive_public_key(
        bob_private
    )

    ours = compute_shared_secret(
        alice_private,
        bob_public,
    )

    reference_alice = (
        X25519PrivateKey
        .from_private_bytes(
            alice_private
        )
    )

    reference_bob_public = (
        X25519PublicKey
        .from_public_bytes(
            bob_public
        )
    )

    expected = (
        reference_alice.exchange(
            reference_bob_public
        )
    )

    assert ours == expected

    assert alice_public != bob_public


def test_both_users_get_same_shared_secret():

    alice_private, alice_public = (
        generate_keypair()
    )

    bob_private, bob_public = (
        generate_keypair()
    )

    alice_secret = compute_shared_secret(
        alice_private,
        bob_public,
    )

    bob_secret = compute_shared_secret(
        bob_private,
        alice_public,
    )

    assert alice_secret == bob_secret


def test_generated_key_sizes():

    private_key, public_key = (
        generate_keypair()
    )

    assert len(private_key) == KEY_SIZE

    assert len(public_key) == KEY_SIZE


def test_generated_keypairs_are_different():

    first_private, first_public = (
        generate_keypair()
    )

    second_private, second_public = (
        generate_keypair()
    )

    assert (
        first_private
        != second_private
    )

    assert (
        first_public
        != second_public
    )


def test_clamping():

    scalar = b"\xff" * 32

    clamped = clamp_scalar(
        scalar
    )

    assert (
        clamped[0] & 0b00000111
    ) == 0

    assert (
        clamped[31] & 0b10000000
    ) == 0

    assert (
        clamped[31] & 0b01000000
    ) != 0


def test_private_key_wrong_length_rejected():

    with pytest.raises(
        X25519Error
    ):
        derive_public_key(
            b"short"
        )


def test_public_key_wrong_length_rejected():

    private_key, _ = (
        generate_keypair()
    )

    with pytest.raises(
        X25519Error
    ):
        compute_shared_secret(
            private_key,
            b"short",
        )


def test_private_key_must_be_bytes():

    with pytest.raises(
        TypeError
    ):
        derive_public_key(
            "not-bytes"
        )


def test_all_zero_public_key_rejected():

    private_key, _ = (
        generate_keypair()
    )

    with pytest.raises(
        X25519Error
    ):
        compute_shared_secret(
            private_key,
            b"\x00" * 32,
        )