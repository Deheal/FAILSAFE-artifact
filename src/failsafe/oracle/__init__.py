from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from ..policies.profiles import RPPolicy


@dataclass
class ServerStateSnapshot:
    actual_policy_label: str
    failure_counter: int
    is_locked: bool
    is_revoked: bool


def true_hypothesis(policy: RPPolicy) -> Dict[str, int]:
    return {
        "verify_before_store": int(not policy.store_before_verify),
        "store_counter_before_verify": int(policy.store_counter_before_verify),
        "check_uv": int(policy.require_uv),
        "check_bebs": int(policy.require_be_bs_consistency),
        "check_signcount": int(policy.track_sign_count),
        "count_normal": int(policy.count_normal_failure),
        "count_tamper": int(policy.count_tamper_failure),
        "revoke_on_tamper": int(policy.revoke_on_tamper),
    }


__all__ = ["ServerStateSnapshot", "true_hypothesis"]
