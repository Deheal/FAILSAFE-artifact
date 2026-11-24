from __future__ import annotations

import itertools
from typing import Dict, List

from ..policies.profiles import RPPolicy, VW_FLAG_TRANSITIONS
from ..probe.catalog import PROBE_K, WAIT_HORIZON_SEC

DIMENSIONS = (
    "verify_before_store",
    "store_counter_before_verify",
    "check_uv",
    "check_bebs",
    "check_signcount",
    "count_normal",
    "count_tamper",
    "revoke_on_tamper",
)

DEFECT_DIMENSIONS = {"verify_before_store": 0, "store_counter_before_verify": 1}

LOCK_THRESHOLD = PROBE_K
LOCK_DURATION_SEC = 300
assert LOCK_DURATION_SEC < WAIT_HORIZON_SEC

Hypothesis = Dict[str, int]


DIMENSIONS_V1 = tuple(d for d in DIMENSIONS if d != "store_counter_before_verify")

_DIM_DEFAULT = {"store_counter_before_verify": 0}


def all_hypotheses(dimensions=DIMENSIONS) -> List[Hypothesis]:
    return [dict(zip(dimensions, bits)) for bits in itertools.product((0, 1), repeat=len(dimensions))]


def hypothesis_key(h: Hypothesis, dimensions=DIMENSIONS) -> tuple:
    return tuple(int(h[d]) for d in dimensions)


def policy_from_hypothesis(h: Hypothesis) -> RPPolicy:
    g = lambda d: h.get(d, _DIM_DEFAULT.get(d, 0))
    return RPPolicy(
        name="H_" + "".join(str(g(d)) for d in DIMENSIONS),
        store_before_verify=not h["verify_before_store"],
        store_counter_before_verify=bool(g("store_counter_before_verify")),
        require_uv=bool(h["check_uv"]),
        require_be_bs_consistency=bool(h["check_bebs"]),
        track_sign_count=bool(h["check_signcount"]),
        count_normal_failure=bool(h["count_normal"]),
        count_tamper_failure=bool(h["count_tamper"]),
        revoke_on_tamper=bool(h["revoke_on_tamper"]),
        max_failures_before_lock=LOCK_THRESHOLD,
        lock_duration_sec=LOCK_DURATION_SEC,
        allowed_flag_transitions=VW_FLAG_TRANSITIONS,
        aaguid_allowlist=None,
    )
