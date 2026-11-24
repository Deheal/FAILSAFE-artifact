from __future__ import annotations
import json
import os
from dataclasses import dataclass
import numpy as np
from cryptography.hazmat.primitives.asymmetric import ec

from ..primitives.auth_data import (
    make_auth_data, FLAG_UP, FLAG_UV, FLAG_AT, FLAG_BE, FLAG_BS
)
from ..primitives.signing import sign_assertion, verify_assertion
from ..policies.profiles import GOOD_AAGUID

_GLOBAL_KEY = ec.generate_private_key(ec.SECP256R1())
_GLOBAL_PUB = _GLOBAL_KEY.public_key()


@dataclass(frozen=True)
class FailureEvent:
    scenario: str
    cause: str                 
    error_name: str
    error_message: str
    timing_ms: float
    signature_valid: bool      
    assertion_received: bool   
    uv_flag: int
    aaguid: bytes
    sign_count: int
    flags: int = 0             


SCENARIOS = [
    "normal_cancel", "normal_timeout", "normal_no_cred",
    "tamper_uv", "tamper_aaguid", "tamper_signcount",
]

MATRIX_SCENARIOS = ["normal_cancel", "tamper_be_bs"]


def generate_failure_event(scenario: str,
                           rng: np.random.Generator) -> FailureEvent:
    client_data = json.dumps({
        "type": "webauthn.get",
        "challenge": os.urandom(16).hex(),
        "origin": "https://example.org",
    }).encode()

    if scenario == "normal_cancel":
        return FailureEvent(scenario, "normal", "NotAllowedError", "...", float(max(200, rng.normal(3500, 800))), False, False, 1, GOOD_AAGUID, 10, flags=0)
    if scenario == "normal_timeout":
        return FailureEvent(scenario, "normal", "NotAllowedError", "...", float(max(5000, rng.normal(30000, 2000))), False, False, 1, GOOD_AAGUID, 10, flags=0)
    if scenario == "normal_no_cred":
        return FailureEvent(scenario, "normal", "NotAllowedError", "...", float(max(50, rng.normal(120, 30))), False, False, 1, b"\x00" * 16, 0, flags=0)

    if scenario == "tamper_uv":
        auth = make_auth_data(FLAG_UP, 11)
        sig = sign_assertion(_GLOBAL_KEY, auth, client_data)
        assert verify_assertion(_GLOBAL_PUB, auth, client_data, sig)
        return FailureEvent(scenario, "tamper", "NotAllowedError", "...", float(max(100, rng.normal(800, 200))), True, True, 0, GOOD_AAGUID, 11, flags=FLAG_UP)

    if scenario == "tamper_aaguid":
        bad = b"\xff" * 16
        auth = make_auth_data(FLAG_UP | FLAG_UV | FLAG_AT, 12, aaguid=bad)
        sig = sign_assertion(_GLOBAL_KEY, auth, client_data)
        assert verify_assertion(_GLOBAL_PUB, auth, client_data, sig)
        return FailureEvent(scenario, "tamper", "NotAllowedError", "...", float(max(100, rng.normal(900, 200))), True, True, 1, bad, 12, flags=FLAG_UP|FLAG_UV|FLAG_AT)

    if scenario == "tamper_signcount":
        auth = make_auth_data(FLAG_UP | FLAG_UV, 5)
        sig = sign_assertion(_GLOBAL_KEY, auth, client_data)
        assert verify_assertion(_GLOBAL_PUB, auth, client_data, sig)
        return FailureEvent(scenario, "tamper", "NotAllowedError", "...", float(max(100, rng.normal(700, 200))), True, True, 1, GOOD_AAGUID, 5, flags=FLAG_UP|FLAG_UV)

    if scenario == "tamper_be_bs":
        auth = make_auth_data(FLAG_UP | FLAG_UV | FLAG_BS, 14) 
        sig = sign_assertion(_GLOBAL_KEY, auth, client_data)
        assert verify_assertion(_GLOBAL_PUB, auth, client_data, sig)
        return FailureEvent(scenario, "tamper", "NotAllowedError", "...", float(max(100, rng.normal(850, 200))), True, True, 1, GOOD_AAGUID, 14, flags=FLAG_UP|FLAG_UV|FLAG_BS)

    if scenario == "tamper_forged_be_bs":
        auth = make_auth_data(FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS, 1)
        sig = bytearray(sign_assertion(_GLOBAL_KEY, auth, client_data))
        sig[-1] ^= 0xFF
        assert not verify_assertion(_GLOBAL_PUB, auth, client_data, bytes(sig))
        return FailureEvent(scenario, "tamper", "NotAllowedError", "...", float(max(100, rng.normal(850, 200))), False, True, 1, GOOD_AAGUID, 1, flags=FLAG_UP|FLAG_UV|FLAG_BE|FLAG_BS)

    if scenario == "tamper_forged_be0bs0":
        auth = make_auth_data(FLAG_UP | FLAG_UV, 1)
        sig = bytearray(sign_assertion(_GLOBAL_KEY, auth, client_data))
        sig[-1] ^= 0xFF
        assert not verify_assertion(_GLOBAL_PUB, auth, client_data, bytes(sig))
        return FailureEvent(scenario, "tamper", "NotAllowedError", "...", float(max(100, rng.normal(850, 200))), False, True, 1, GOOD_AAGUID, 1, flags=FLAG_UP|FLAG_UV)

    raise ValueError(f"Unknown scenario: {scenario}")