from __future__ import annotations
import hashlib
import os
from dataclasses import dataclass
from typing import Optional

FLAG_UP = 1 << 0
FLAG_UV = 1 << 2
FLAG_BE = 1 << 3
FLAG_BS = 1 << 4
FLAG_AT = 1 << 6
FLAG_ED = 1 << 7

RP_ID = "example.org"


@dataclass(frozen=True)
class AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    attested_credential_data: Optional[bytes] = None

    def to_bytes(self) -> bytes:
        out = self.rp_id_hash + bytes([self.flags]) + self.sign_count.to_bytes(4, "big")
        if self.attested_credential_data is not None:
            out += self.attested_credential_data
        return out

    @property
    def user_present(self) -> bool:
        return bool(self.flags & FLAG_UP)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & FLAG_UV)

    @property
    def backup_eligible(self) -> bool:
        return bool(self.flags & FLAG_BE)

    @property
    def backup_state(self) -> bool:
        return bool(self.flags & FLAG_BS)


def make_auth_data(flags: int, sign_count: int,
                   aaguid: bytes = b"\x00" * 16,
                   rp_id: str = RP_ID) -> AuthenticatorData:
    rp_hash = hashlib.sha256(rp_id.encode()).digest()
    if flags & FLAG_AT:
        cred_id = os.urandom(32)
        acd = aaguid + len(cred_id).to_bytes(2, "big") + cred_id
    else:
        acd = None
    return AuthenticatorData(rp_hash, flags, sign_count, acd)