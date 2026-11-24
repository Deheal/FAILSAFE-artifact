from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Optional

GOOD_AAGUID = b"\x01" * 16
ALT_AAGUID = b"\x02" * 16

FLAG_TRANSITIONS = ("BE01", "BE10", "BS01", "BS10")
VW_FLAG_TRANSITIONS = frozenset({"BE01", "BS01", "BS10"})


@dataclass(frozen=True)
class RPPolicy:
    name: str
    require_uv: bool = True
    aaguid_allowlist: Optional[frozenset] = None
    require_attestation: bool = True
    track_sign_count: bool = True
    max_failures_before_lock: int = 10
    lock_duration_sec: int = 300
    count_normal_failure: bool = True
    count_tamper_failure: bool = True
    observes_uv: bool = True
    observes_aaguid: bool = True
    require_be_bs_consistency: bool = True
    revoke_on_tamper: bool = False
    store_before_verify: bool = False
    store_counter_before_verify: bool = False
    revoke_deletes_record: bool = True
    allowed_flag_transitions: frozenset = frozenset()
    registration_drops_be: bool = False
    required_be: Optional[bool] = None

    def lambda_penalty(self) -> float:
        base = 1.0 / max(1, self.max_failures_before_lock)
        duration_factor = 1.0 + (self.lock_duration_sec / 3600.0)
        counting_factor = ((1.0 if self.count_normal_failure else 0.5) *
                           (1.0 if self.count_tamper_failure else 0.5))
        return base * duration_factor * counting_factor


POLICY_PROFILES: Dict[str, RPPolicy] = {
    "P1_lenient": RPPolicy(name="P1_lenient", aaguid_allowlist=frozenset({GOOD_AAGUID, ALT_AAGUID}), max_failures_before_lock=20, lock_duration_sec=60, count_normal_failure=False, count_tamper_failure=True),
    "P2_normal_counted": RPPolicy(name="P2_normal_counted", aaguid_allowlist=frozenset({GOOD_AAGUID, ALT_AAGUID}), max_failures_before_lock=20, lock_duration_sec=60, count_normal_failure=True, count_tamper_failure=True),
    "P3_strict": RPPolicy(name="P3_strict", aaguid_allowlist=frozenset({GOOD_AAGUID, ALT_AAGUID}), max_failures_before_lock=5, lock_duration_sec=300, count_normal_failure=True, count_tamper_failure=True),
    "P4_aggressive": RPPolicy(name="P4_aggressive", aaguid_allowlist=frozenset({GOOD_AAGUID, ALT_AAGUID}), max_failures_before_lock=3, lock_duration_sec=1800, count_normal_failure=True, count_tamper_failure=True),
}


def build_policy_grid() -> Dict[str, RPPolicy]:
    grid: Dict[str, RPPolicy] = {}
    for counting in (False, True):
        for threshold in (3, 10, 20):
            name = f"P_cnt{int(counting)}_thr{threshold}"
            grid[name] = RPPolicy(
                name=name,
                aaguid_allowlist=frozenset({GOOD_AAGUID, ALT_AAGUID}),
                max_failures_before_lock=threshold,
                lock_duration_sec=300,
                count_normal_failure=counting,
                count_tamper_failure=True,
            )
    return grid


POLICY_PROFILES_V2: Dict[str, RPPolicy] = build_policy_grid()

MATRIX_POLICIES: Dict[str, RPPolicy] = {
    "A_Normal_CountOFF": RPPolicy(
        name="A_Normal_CountOFF",
        count_normal_failure=False, count_tamper_failure=False,
        revoke_on_tamper=False, max_failures_before_lock=5
    ),
    "B_Normal_CountON": RPPolicy(
        name="B_Normal_CountON",
        count_normal_failure=True, count_tamper_failure=True,
        revoke_on_tamper=False, max_failures_before_lock=5
    ),
    "C_Tamper_CountOFF": RPPolicy(
        name="C_Tamper_CountOFF",
        count_normal_failure=False, count_tamper_failure=False,
        revoke_on_tamper=False, max_failures_before_lock=5
    ),
    "D_Tamper_CountON": RPPolicy(
        name="D_Tamper_CountON",
        count_normal_failure=True, count_tamper_failure=True,
        revoke_on_tamper=True, max_failures_before_lock=5
    ),
}


ATTRIBUTION_POLICIES: Dict[str, RPPolicy] = {
    "RP_normal": RPPolicy(
        name="RP_normal",
        store_before_verify=False, revoke_on_tamper=False,
        count_normal_failure=True, count_tamper_failure=True,
        max_failures_before_lock=3, lock_duration_sec=300,
    ),
    "RP_long_lockout": RPPolicy(
        name="RP_long_lockout",
        store_before_verify=False, revoke_on_tamper=False,
        count_normal_failure=True, count_tamper_failure=True,
        max_failures_before_lock=3, lock_duration_sec=7200,
    ),
    "RP_revoke": RPPolicy(
        name="RP_revoke",
        store_before_verify=False, revoke_on_tamper=True,
        count_normal_failure=True, count_tamper_failure=True,
        max_failures_before_lock=3, lock_duration_sec=300,
    ),
    "RP_revoke_keep": RPPolicy(
        name="RP_revoke_keep",
        store_before_verify=False, revoke_on_tamper=True,
        revoke_deletes_record=False,
        count_normal_failure=True, count_tamper_failure=True,
        max_failures_before_lock=3, lock_duration_sec=300,
    ),
    "RP_vulnerable": RPPolicy(
        name="RP_vulnerable",
        store_before_verify=True, revoke_on_tamper=False,
        count_normal_failure=True, count_tamper_failure=True,
        max_failures_before_lock=3, lock_duration_sec=300,
    ),
}


ATTRIBUTION_HOLDOUT_POLICIES: Dict[str, RPPolicy] = {
    "H_normal_t5_600": RPPolicy(
        name="H_normal_t5_600", max_failures_before_lock=5, lock_duration_sec=600),
    "H_long_lockout_t5_14400": RPPolicy(
        name="H_long_lockout_t5_14400", max_failures_before_lock=5,
        lock_duration_sec=14400),
    "H_revoke_t5": RPPolicy(
        name="H_revoke_t5", revoke_on_tamper=True, max_failures_before_lock=5,
        lock_duration_sec=600),
    "H_revoke_keep_t2": RPPolicy(
        name="H_revoke_keep_t2", revoke_on_tamper=True, revoke_deletes_record=False,
        max_failures_before_lock=2, lock_duration_sec=120),
    "H_vulnerable_t5_900": RPPolicy(
        name="H_vulnerable_t5_900", store_before_verify=True,
        max_failures_before_lock=5, lock_duration_sec=900),
    "H_vulnerable_long_lock": RPPolicy(
        name="H_vulnerable_long_lock", store_before_verify=True,
        max_failures_before_lock=3, lock_duration_sec=7200),
    "H_vulnerable_permissive": RPPolicy(
        name="H_vulnerable_permissive", store_before_verify=True,
        allowed_flag_transitions=VW_FLAG_TRANSITIONS,
        max_failures_before_lock=3, lock_duration_sec=300),
    "H_flag_policy_permissive": RPPolicy(
        name="H_flag_policy_permissive",
        allowed_flag_transitions=VW_FLAG_TRANSITIONS,
        required_be=True,
        max_failures_before_lock=3, lock_duration_sec=300),
}