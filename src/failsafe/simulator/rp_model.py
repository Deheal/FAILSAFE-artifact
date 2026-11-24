from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Tuple

from ..policies.profiles import GOOD_AAGUID, RPPolicy
from ..primitives.auth_data import FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV
from .events import FailureEvent
from .rp import RPSessionState, rp_process_failure, rp_process_normal_assertion

ACCEPT = "ACCEPT"
REJECT = "REJECT"
BLOCKED_PRE = "BLOCKED_PRE"
ERROR = "ERROR"

REQUEST_KINDS = ("valid", "forged", "wrong_cred")


@dataclass(frozen=True)
class Request:
    kind: str
    be: bool = False
    bs: bool = False
    uv: bool = True
    counter: int = 0

    def __post_init__(self):
        if self.kind not in REQUEST_KINDS:
            raise ValueError(f"알 수 없는 요청 종류: {self.kind}")


def _as_event(req: Request) -> FailureEvent:
    if req.kind == "wrong_cred":
        return FailureEvent("psm_wrong_cred", "normal", "NotAllowedError", "", 0.0,
                            False, False, 1, GOOD_AAGUID, 0, flags=0)
    flags = (FLAG_UP | (FLAG_UV if req.uv else 0)
             | (FLAG_BE if req.be else 0) | (FLAG_BS if req.bs else 0))
    return FailureEvent(f"psm_{req.kind}", "unlabeled", "NotAllowedError", "", 0.0,
                        req.kind == "valid", True, 1 if req.uv else 0, GOOD_AAGUID,
                        req.counter, flags=flags)


def rp_handle(policy: RPPolicy, state: RPSessionState, request: Request,
              now: float) -> Tuple[str, RPSessionState]:
    if request.kind != "valid":
        before_counter = state.last_sign_count
        rp_process_failure(policy, _as_event(request), state, now)
        if not policy.store_counter_before_verify:
            state.last_sign_count = before_counter
        return REJECT, state

    if state.credential_revoked or now < state.locked_until:
        return REJECT, state

    event = _as_event(request)
    if rp_process_failure(policy, event, copy.deepcopy(state), now)["violation_detected"]:
        before_counter = state.last_sign_count
        rp_process_failure(policy, event, state, now)
        state.last_sign_count = before_counter
        return REJECT, state

    result = rp_process_normal_assertion(policy, state, now, request.be, request.bs)
    if result["accepted"] and policy.track_sign_count and request.counter > state.last_sign_count:
        state.last_sign_count = request.counter
    return (ACCEPT if result["accepted"] else REJECT), state
