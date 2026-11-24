from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any

from ..primitives.auth_data import FLAG_BE, FLAG_BS
from ..policies.profiles import RPPolicy
from .events import FailureEvent


@dataclass
class RPSessionState:
    failure_counter: int = 0
    locked_until: float = 0.0
    lockout_count: int = 0
    last_sign_count: int = 10
    credential_revoked: bool = False
    stored_be: bool = False
    stored_bs: bool = False
    state_corrupted: bool = False


def rp_process_failure(policy: RPPolicy, event: FailureEvent,
                       state: RPSessionState, now: float) -> Dict[str, Any]:
    if state.credential_revoked:
        return {"accepted": False, "reason": "credential_revoked",
                "violation_detected": False,
                "failure_counter": state.failure_counter, "locked": False}

    if now < state.locked_until:
        return {"accepted": False, "reason": "already_locked",
                "violation_detected": False,
                "failure_counter": state.failure_counter, "locked": False}

    if event.assertion_received and policy.store_before_verify:
        presented_be = bool(event.flags & FLAG_BE)
        presented_bs = bool(event.flags & FLAG_BS)
        if presented_be != state.stored_be or presented_bs != state.stored_bs:
            state.stored_be = presented_be
            state.stored_bs = presented_bs
            state.state_corrupted = True

    violation = False
    if event.assertion_received:
        if not event.signature_valid:
            violation = True
        if policy.require_uv and event.uv_flag == 0:
            violation = True
        if (policy.aaguid_allowlist is not None
                and event.aaguid not in policy.aaguid_allowlist
                and event.aaguid != b"\x00" * 16):
            violation = True
        if (policy.track_sign_count and event.sign_count > 0
                and event.sign_count <= state.last_sign_count):
            violation = True
        if policy.require_be_bs_consistency:
            has_be = bool(event.flags & FLAG_BE)
            has_bs = bool(event.flags & FLAG_BS)
            if has_bs and not has_be:
                violation = True
                
        if policy.track_sign_count and event.sign_count > state.last_sign_count:
            state.last_sign_count = event.sign_count

    if violation and policy.revoke_on_tamper:
        state.credential_revoked = True

    if violation:
        if policy.count_tamper_failure:
            state.failure_counter += 1
    else:
        if policy.count_normal_failure:
            state.failure_counter += 1

    locked = state.failure_counter >= policy.max_failures_before_lock
    if locked:
        state.locked_until = now + policy.lock_duration_sec
        state.failure_counter = 0
        state.lockout_count += 1

    return {"accepted": False, "violation_detected": violation,
            "failure_counter": state.failure_counter, "locked": locked}


def rp_process_normal_assertion(policy: RPPolicy, state: RPSessionState,
                                now: float,
                                presented_be: bool = False,
                                presented_bs: bool = False) -> Dict[str, Any]:
    if state.credential_revoked:
        return {"accepted": False, "reason": "credential_revoked"}
    if now < state.locked_until:
        return {"accepted": False, "reason": "shadow_blocked"}
    if policy.require_be_bs_consistency and presented_bs and not presented_be:
        return {"accepted": False, "reason": "invalid_flags"}
    if policy.required_be is not None and presented_be != policy.required_be:
        return {"accepted": False, "reason": "flag_policy"}
    if not flag_transition_allowed(policy, state.stored_be, state.stored_bs,
                                   presented_be, presented_bs):
        return {"accepted": False, "reason": "flag_mismatch"}
    state.stored_be, state.stored_bs = presented_be, presented_bs
    return {"accepted": True, "reason": "ok"}


def flag_transition_allowed(policy: RPPolicy, stored_be: bool, stored_bs: bool,
                            presented_be: bool, presented_bs: bool) -> bool:
    transitions = set()
    if not stored_be and presented_be:
        transitions.add("BE01")
    if stored_be and not presented_be:
        transitions.add("BE10")
    if not stored_bs and presented_bs:
        transitions.add("BS01")
    if stored_bs and not presented_bs:
        transitions.add("BS10")
    return not (transitions - set(policy.allowed_flag_transitions))


def rp_register_credential(policy: RPPolicy, state: RPSessionState,
                           be: bool, bs: bool) -> None:
    state.stored_be = False if policy.registration_drops_be else be
    state.stored_bs = bs


def rp_process_reregistration(policy: RPPolicy,
                              state: RPSessionState) -> Dict[str, Any]:
    if state.credential_revoked and policy.revoke_deletes_record:
        return {"allowed": True, "reason": "new_registration"}
    return {"allowed": False, "reason": "already_registered"}