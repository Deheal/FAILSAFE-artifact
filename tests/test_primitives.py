import hashlib
import json
import os
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from failsafe.primitives.auth_data import (
    make_auth_data, FLAG_UP, FLAG_UV, FLAG_AT, RP_ID,
)
from failsafe.primitives.signing import sign_assertion, verify_assertion


@pytest.fixture
def keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def test_sign_verify_roundtrip(keypair):
    priv, pub = keypair
    auth = make_auth_data(FLAG_UP | FLAG_UV, 10)
    cdj = json.dumps({"type": "webauthn.get", "challenge": "abc",
                      "origin": "https://example.org"}).encode()
    sig = sign_assertion(priv, auth, cdj)
    assert verify_assertion(pub, auth, cdj, sig)


def test_tampered_signature_fails(keypair):
    priv, pub = keypair
    auth = make_auth_data(FLAG_UP | FLAG_UV, 10)
    cdj = b'{"type":"webauthn.get"}'
    sig = bytearray(sign_assertion(priv, auth, cdj))
    sig[-1] ^= 0xFF
    assert not verify_assertion(pub, auth, cdj, bytes(sig))


def test_uv_flag_variants_are_validly_signed(keypair):
    priv, pub = keypair
    cdj = b'{"type":"webauthn.get"}'
    for flags in (FLAG_UP, FLAG_UP | FLAG_UV):
        auth = make_auth_data(flags, 10)
        sig = sign_assertion(priv, auth, cdj)
        assert verify_assertion(pub, auth, cdj, sig)


def test_aaguid_allowlist_variant_is_validly_signed(keypair):
    priv, pub = keypair
    bad = b"\xff" * 16
    auth = make_auth_data(FLAG_UP | FLAG_UV | FLAG_AT, 12, aaguid=bad)
    cdj = b'{"type":"webauthn.get"}'
    sig = sign_assertion(priv, auth, cdj)
    assert verify_assertion(pub, auth, cdj, sig)
    assert bad in auth.to_bytes()


def test_rp_id_hash_matches_sha256():
    auth = make_auth_data(FLAG_UP, 0)
    assert auth.rp_id_hash == hashlib.sha256(RP_ID.encode()).digest()