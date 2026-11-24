from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from ..policies.profiles import RPPolicy
from .events import generate_failure_event
from .rp import (RPSessionState, rp_process_failure,
                 rp_process_normal_assertion, rp_process_reregistration,
                 rp_register_credential, flag_transition_allowed)


WAIT_HORIZON = 3600.0
ALL_FLAGS = [(False, False), (True, False), (False, True), (True, True)]


@dataclass(frozen=True)
class VictimProfile:
    name: str
    registered: Tuple[bool, bool]
    current: Tuple[bool, bool]

    @property
    def probe_flags(self) -> List[Tuple[bool, bool]]:
        return [f for f in ALL_FLAGS if f != self.current]


DEVICE_BOUND = VictimProfile("기기 종속", (False, False), (False, False))
VICTIMS = [
    DEVICE_BOUND,
    VictimProfile("동기화 전", (True, False), (True, False)),
    VictimProfile("동기화 완료", (True, False), (True, True)),
    VictimProfile("백업 해제", (True, True), (True, False)),
]

NONE = "none"
NORMAL_POLICY = "normal_policy"
STATE_CORRUPTION = "state_corruption"
UNKNOWN = "unknown"

FINE_TO_CLASS = {
    NONE: NONE,
    "lockout": NORMAL_POLICY,
    "revocation": NORMAL_POLICY,
    "flag_policy": NORMAL_POLICY,
    "flag_update_policy": NORMAL_POLICY,
    "rp_bug": NORMAL_POLICY,
    "corruption": STATE_CORRUPTION,
}


@dataclass(frozen=True)
class ExternalObservation:
    control_login_ok: bool
    immediate_blocked: bool
    immediate_retry_ok: bool
    recovered_after_wait: bool
    flag_probe_ok: Optional[bool]
    reregistration_allowed: Optional[bool]
    current_after_probe_ok: Optional[bool] = None


@dataclass(frozen=True)
class GroundTruth:
    fine_cause: str

    @property
    def cause_class(self) -> str:
        return FINE_TO_CLASS[self.fine_cause]


def _ground_truth(state: RPSessionState, blocked: bool,
                  reason: str, policy: RPPolicy,
                  current: Tuple[bool, bool] = (False, False)) -> GroundTruth:
    if not blocked:
        return GroundTruth(NONE)
    if state.state_corrupted and not flag_transition_allowed(
            policy, state.stored_be, state.stored_bs, *current):
        return GroundTruth("corruption")
    if state.credential_revoked:
        return GroundTruth("revocation")
    if reason == "flag_policy":
        return GroundTruth("flag_policy")
    if reason in ("flag_mismatch", "invalid_flags"):
        return GroundTruth("rp_bug" if policy.registration_drops_be
                           else "flag_update_policy")
    return GroundTruth("lockout")


def _replay_legit_history(policy: RPPolicy, state: RPSessionState,
                          victim: VictimProfile) -> None:
    rp_register_credential(policy, state, *victim.registered)
    if victim.current != victim.registered:
        rp_process_normal_assertion(policy, state, -1.0, *victim.current)


def run_trial(policy: RPPolicy, scenario: str, rng: np.random.Generator,
              lambda_user: float = 2.0,
              rereg_available: bool = False,
              wait_horizon: float = WAIT_HORIZON,
              victim: VictimProfile = DEVICE_BOUND,
              ) -> Tuple[ExternalObservation, GroundTruth]:
    cur = victim.current

    control = RPSessionState()
    _replay_legit_history(policy, control, victim)
    control_ok = rp_process_normal_assertion(policy, control, 1.0, *cur)["accepted"]

    st = RPSessionState()
    _replay_legit_history(policy, st, victim)
    t = 0.0
    for _ in range(int(rng.poisson(lambda_user))):
        rp_process_failure(policy, generate_failure_event(scenario, rng), st, t)
        t += 2.0
    t_login = t + 0.5
    first = rp_process_normal_assertion(policy, st, t_login, *cur)
    blocked = not first["accepted"]
    truth = _ground_truth(st, blocked, first["reason"], policy, cur)

    retry_ok = rp_process_normal_assertion(policy, st, t_login + 0.1, *cur)["accepted"]

    t_wait = t_login + wait_horizon
    recovered = rp_process_normal_assertion(policy, st, t_wait, *cur)["accepted"]

    flag_probe_ok: Optional[bool] = None
    current_after_probe_ok: Optional[bool] = None
    if blocked and not recovered:
        flag_probe_ok = any(
            rp_process_normal_assertion(policy, st, t_wait, be, bs)["accepted"]
            for be, bs in victim.probe_flags
        )
        current_after_probe_ok = rp_process_normal_assertion(
            policy, st, t_wait, *cur)["accepted"]

    rereg: Optional[bool] = None
    if rereg_available and blocked and not recovered and not flag_probe_ok:
        rereg = rp_process_reregistration(policy, st)["allowed"]

    obs = ExternalObservation(
        control_login_ok=control_ok,
        immediate_blocked=blocked,
        immediate_retry_ok=retry_ok,
        recovered_after_wait=recovered,
        flag_probe_ok=flag_probe_ok,
        reregistration_allowed=rereg,
        current_after_probe_ok=current_after_probe_ok,
    )
    return obs, truth


def failsafe_attribution(obs: ExternalObservation) -> Tuple[str, str]:
    if not obs.control_login_ok:
        return UNKNOWN, "R0 대조 실행 실패(환경 문제)"
    if not obs.immediate_blocked:
        return NONE, "R1 차단 없음"
    if obs.recovered_after_wait:
        return NORMAL_POLICY, "R2 대기 후 복구 → 시간 기반 잠금"
    if obs.flag_probe_ok:
        return STATE_CORRUPTION, "R3 다른 플래그로만 통과 → 저장 플래그 변조"
    if obs.reregistration_allowed:
        return NORMAL_POLICY, "R4 재등록 허용 → 자격증명 폐기"
    return UNKNOWN, "R5 지속 차단, 프로브 음성 → 판별 유보"


def failsafe_without_control(obs: ExternalObservation) -> str:
    if not obs.immediate_blocked:
        return NONE
    if obs.recovered_after_wait:
        return NORMAL_POLICY
    if obs.flag_probe_ok:
        return STATE_CORRUPTION
    if obs.reregistration_allowed:
        return NORMAL_POLICY
    return UNKNOWN


def recovery_only_attribution(obs: ExternalObservation) -> str:
    if not obs.immediate_blocked:
        return NONE
    return NORMAL_POLICY if obs.recovered_after_wait else STATE_CORRUPTION


def single_response_attribution(obs: ExternalObservation) -> str:
    if not obs.immediate_blocked:
        return NONE
    return NORMAL_POLICY


def simple_retry_attribution(obs: ExternalObservation) -> str:
    if not obs.immediate_blocked:
        return NONE
    return NORMAL_POLICY if obs.immediate_retry_ok else STATE_CORRUPTION


METHODS = {
    "FAILSAFE": lambda o: failsafe_attribution(o)[0],
    "FAILSAFE(대조 없음)": failsafe_without_control,
    "복구만(이전 버전)": recovery_only_attribution,
    "단순 재시도": simple_retry_attribution,
    "단일 응답": single_response_attribution,
}


def run_attribution_experiment(
    conditions: Dict[str, Tuple[str, RPPolicy]],
    n_trials: int = 1000, seed: int = 42, lambda_user: float = 2.0,
    rereg_available: bool = False,
) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows: List[Dict[str, Any]] = []
    for label, (scenario, policy) in conditions.items():
        for _ in range(n_trials):
            obs, truth = run_trial(policy, scenario, rng, lambda_user,
                                   rereg_available)
            row = {
                "condition": label,
                "truth_fine": truth.fine_cause,
                "truth_class": truth.cause_class,
                "blocked": obs.immediate_blocked,
                "rule": failsafe_attribution(obs)[1],
            }
            for name, fn in METHODS.items():
                row[name] = fn(obs)
            rows.append(row)
    return pd.DataFrame(rows)


def _metrics(truth: pd.Series, pred: pd.Series) -> Dict[str, float]:
    pos = truth == STATE_CORRUPTION
    neg = truth == NORMAL_POLICY
    tp = int(((pred == STATE_CORRUPTION) & pos).sum())
    fp = int(((pred == STATE_CORRUPTION) & neg).sum())
    tn = int(((pred == NORMAL_POLICY) & neg).sum())
    n_pos, n_neg = int(pos.sum()), int(neg.sum())
    unknown = int((pred == UNKNOWN).sum())
    decided = len(pred) - unknown

    def div(a, b):
        return a / b if b else float("nan")

    precision = div(tp, tp + fp)
    recall = div(tp, n_pos)
    tnr = div(tn, n_neg)
    f1 = (div(2 * precision * recall, precision + recall)
          if precision == precision and recall == recall else float("nan"))
    correct = int((pred == truth).sum())
    return {
        "n": len(pred),
        "정확도(유보=오답)": div(correct, len(pred)),
        "정확도(판정한 것만)": div(correct, decided),
        "정밀도": precision,
        "재현율": recall,
        "F1": f1,
        "오탐률": div(fp, n_neg),
        "균형정확도": (recall + tnr) / 2 if n_pos and n_neg else float("nan"),
        "판별불가율": div(unknown, len(pred)),
    }


def evaluate_attribution(df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    b = df[df["blocked"]]
    return {name: _metrics(b["truth_class"], b[name]) for name in METHODS}


def per_condition_table(df: pd.DataFrame) -> pd.DataFrame:
    b = df[df["blocked"]]
    t = (b.groupby("condition")["FAILSAFE"].value_counts(normalize=True)
         .unstack(fill_value=0.0))
    for c in (NORMAL_POLICY, STATE_CORRUPTION, UNKNOWN):
        if c not in t.columns:
            t[c] = 0.0
    t = t[[NORMAL_POLICY, STATE_CORRUPTION, UNKNOWN]]
    t.insert(0, "차단건수", b.groupby("condition").size())
    t.insert(1, "정답", b.groupby("condition")["truth_class"].agg(
        lambda s: "/".join(sorted(set(s)))))
    return t
