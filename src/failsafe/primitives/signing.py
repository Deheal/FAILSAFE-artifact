from __future__ import annotations
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from .auth_data import AuthenticatorData


def sign_assertion(private_key: ec.EllipticCurvePrivateKey,
                   auth_data: AuthenticatorData,
                   client_data_json: bytes) -> bytes:
    client_hash = hashlib.sha256(client_data_json).digest()
    return private_key.sign(auth_data.to_bytes() + client_hash,
                            ec.ECDSA(hashes.SHA256()))


def verify_assertion(public_key: ec.EllipticCurvePublicKey,
                     auth_data: AuthenticatorData,
                     client_data_json: bytes,
                     signature: bytes) -> bool:
    client_hash = hashlib.sha256(client_data_json).digest()
    try:
        public_key.verify(signature, auth_data.to_bytes() + client_hash,
                          ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False