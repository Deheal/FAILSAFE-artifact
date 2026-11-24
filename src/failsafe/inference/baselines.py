from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from ..probe.catalog import ProbeObservation, _script, tail_symbols
from ..simulator.attribution import (NONE, NORMAL_POLICY, STATE_CORRUPTION, UNKNOWN, ExternalObservation,
                                     failsafe_attribution, failsafe_without_control,
                                     recovery_only_attribution, simple_retry_attribution,
                                     single_response_attribution)
from ..simulator.rp_model import ACCEPT, BLOCKED_PRE, ERROR, REJECT

BASELINES = {
    "v2 규칙": lambda o: failsafe_attribution(o)[0],
    "v2 규칙(대조 없음)": failsafe_without_control,
    "복구만": recovery_only_attribution,
    "단순 재시도": simple_retry_attribution,
    "단일 응답": single_response_attribution,
}

TO_Q2 = {STATE_CORRUPTION: "state_corruption", NORMAL_POLICY: "normal_policy",
         NONE: "normal_policy", UNKNOWN: "undetermined"}


def _norm(symbols):
    return tuple(REJECT if s == BLOCKED_PRE else s for s in symbols)


def to_episode(obs: ProbeObservation) -> Optional[ExternalObservation]:
    ctrl, syms = _norm(obs.control_symbols), _norm(obs.symbols)
    if ERROR in ctrl or ERROR in syms:
        return None
    first, retry, waited = tail_symbols(ProbeObservation(obs.probe_id, ctrl, syms, obs.victim))
    n = len(_script(obs.probe_id))
    flag_probe_ok = (syms[n] == ACCEPT) if len(syms) > n else None
    return ExternalObservation(
        control_login_ok=all(s == ACCEPT for s in ctrl),
        immediate_blocked=first != ACCEPT,
        immediate_retry_ok=retry == ACCEPT,
        recovered_after_wait=waited == ACCEPT,
        flag_probe_ok=flag_probe_ok,
        reregistration_allowed=None,
    )


def episode_verdicts(observations: Iterable[ProbeObservation]) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {name: {} for name in BASELINES}
    for obs in observations:
        ep = to_episode(obs)
        for name, method in BASELINES.items():
            out[name][obs.probe_id] = "excluded" if ep is None else method(ep)
    return out


def aggregate(verdicts: Dict[str, str]) -> str:
    v: List[str] = [x for x in verdicts.values() if x != "excluded"]
    if not v:
        return "undetermined"
    if STATE_CORRUPTION in v:
        return "state_corruption"
    if UNKNOWN in v:
        return "undetermined"
    return "normal_policy"


def baseline_q2(observations: Iterable[ProbeObservation]) -> Dict[str, str]:
    return {name: aggregate(per_probe) for name, per_probe in episode_verdicts(list(observations)).items()}
