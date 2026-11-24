from __future__ import annotations

import dataclasses
import math
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..probe.catalog import ProbeObservation, run_probe
from ..probe.targets import SimTarget
from ..simulator.attribution import DEVICE_BOUND, VictimProfile
from ..simulator.rp_model import ACCEPT, BLOCKED_PRE, ERROR, REJECT
from .hypotheses import (DIMENSIONS, Hypothesis, all_hypotheses, hypothesis_key,
                         policy_from_hypothesis)

INFERENCE_SYMBOLS = (ACCEPT, REJECT)


@dataclass(frozen=True)
class EngineParams:
    eps: float = 0.01
    tau: float = 0.95
    m: int = 0
    per_probe_a1: bool = False


@dataclass
class PolicyMap:
    values: Dict[str, Optional[int]]
    marginals: Dict[str, float]
    abstain_reason: Optional[str]
    excluded_probes: List[str]
    q2: str
    best_mismatches: Optional[int] = None
    best_hypotheses: List[Hypothesis] = field(default_factory=list)
    q2_undetermined_reason: Optional[str] = None
    posterior: Optional[List[Tuple[Hypothesis, float]]] = None


@lru_cache(maxsize=None)
def _predict(key: tuple, dims: tuple, probe_id: str, victim: VictimProfile):
    h = dict(zip(dims, key))
    obs = run_probe(SimTarget(policy_from_hypothesis(h), victim), probe_id)
    return obs.control_symbols, obs.symbols


def predict(hypothesis: Hypothesis, probe_id: str,
            victim: VictimProfile = DEVICE_BOUND) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    dims = tuple(hypothesis.keys())
    return _predict(tuple(int(hypothesis[d]) for d in dims), dims, probe_id, victim)


def _normalize(symbols: Sequence[str]) -> Tuple[str, ...]:
    return tuple(REJECT if s == BLOCKED_PRE else s for s in symbols)


def _mismatches(predicted: Sequence[str], observed: Sequence[str]) -> int:
    return sum(a != b for a, b in zip(predicted, observed)) + abs(len(predicted) - len(observed))


def _usable(observations: Iterable[ProbeObservation]):
    usable, excluded = [], []
    for o in observations:
        ctrl, syms = _normalize(o.control_symbols), _normalize(o.symbols)
        if ERROR in ctrl or ERROR in syms or any(s != ACCEPT for s in ctrl):
            excluded.append(o.probe_id)
            continue
        usable.append((o.probe_id, syms, o.victim))
    return usable, excluded


@dataclass(frozen=True)
class Scored:
    scored: Tuple[Tuple[Hypothesis, int, int], ...]
    has_evidence: bool
    excluded: Tuple[str, ...]
    per_probe: Tuple[Tuple[str, Tuple[int, ...], int], ...] = ()


def score_hypotheses(observations: Iterable[ProbeObservation], hyps=None) -> Scored:
    usable, excluded = _usable(observations)
    hyps = all_hypotheses() if hyps is None else hyps
    per_probe = []
    for probe_id, syms, victim in usable:
        dists = tuple(_mismatches(predict(h, probe_id, victim)[1], syms) for h in hyps)
        length = max((len(predict(h, probe_id, victim)[1]) for h in hyps), default=0)
        per_probe.append((probe_id, dists, max(length, len(syms))))
    scored = []
    for i, h in enumerate(hyps):
        mism = sum(pp[1][i] for pp in per_probe)
        length = sum(pp[2] for pp in per_probe)
        scored.append((h, mism, length))
    return Scored(tuple(scored), bool(usable), tuple(excluded), tuple(per_probe))


def infer(observations: Iterable[ProbeObservation], params: EngineParams = EngineParams()) -> PolicyMap:
    return decide(score_hypotheses(observations), params)


def infer_v1(observations: Iterable[ProbeObservation], params: EngineParams = EngineParams()) -> PolicyMap:
    from .hypotheses import DIMENSIONS_V1
    s = score_hypotheses(observations, hyps=all_hypotheses(DIMENSIONS_V1))
    return decide(s, dataclasses.replace(params, per_probe_a1=False))


def decide(s: Scored, params: EngineParams = EngineParams()) -> PolicyMap:
    scored, usable, excluded = list(s.scored), s.has_evidence, list(s.excluded)
    undecided = {d: None for d in DIMENSIONS}

    if params.per_probe_a1:
        kept = [pp for pp in s.per_probe if min(pp[1], default=0) <= params.m]
        a1_excluded = [pp[0] for pp in s.per_probe if min(pp[1], default=0) > params.m]
        excluded = excluded + a1_excluded
        if not kept:
            best = min((min(pp[1], default=0) for pp in s.per_probe), default=0)
            return PolicyMap(undecided, {}, "A1", excluded, "undetermined", best,
                             [h for h, m, _ in scored if m == best])
        scored = [(h, sum(pp[1][i] for pp in kept), sum(pp[2] for pp in kept))
                  for i, (h, _, _) in enumerate(scored)]
        best = min(m for _, m, _ in scored)
        best_hyps = [h for h, m, _ in scored if m == best]
        a1_reason = "A1-probe" if a1_excluded else None
        return _posterior(scored, params, excluded, best, best_hyps, a1_reason)

    best = min(m for _, m, _ in scored) if usable else 0
    best_hyps = [h for h, m, _ in scored if m == best]

    if usable and best > params.m:
        return PolicyMap(undecided, {}, "A1", excluded, "undetermined", best, best_hyps)
    return _posterior(scored, params, excluded, best, best_hyps, None)


def _posterior(scored, params, excluded, best, best_hyps, a1_reason):

    k = len(INFERENCE_SYMBOLS)
    log_miss, log_hit = math.log(params.eps / (k - 1)), math.log(1.0 - params.eps)
    logliks = [m * log_miss + (n - m) * log_hit for _, m, n in scored]
    top = max(logliks)
    weights = [math.exp(ll - top) for ll in logliks]
    z = sum(weights)

    dims = list(scored[0][0].keys()) if scored else list(DIMENSIONS)
    marginals = {d: sum(w * h[d] for (h, _, _), w in zip(scored, weights)) / z for d in dims}
    values = {}
    for d, p in marginals.items():
        values[d] = 1 if p >= params.tau else (0 if p <= 1.0 - params.tau else None)

    from .hypotheses import DEFECT_DIMENSIONS
    p_defect_each = {d: (1.0 - marginals[d] if val == 0 else marginals[d])
                     for d, val in DEFECT_DIMENSIONS.items() if d in marginals}
    p_not_defect = 1.0
    for p in p_defect_each.values():
        p_not_defect *= (1.0 - p)
    p_defect = 1.0 - p_not_defect
    undet_reason = None
    if p_defect >= params.tau:
        q2 = "state_corruption"
    elif p_not_defect >= params.tau:
        q2 = "normal_policy"
    else:
        q2 = "undetermined"
        def _is_defect(h):
            return any(h.get(d) == val for d, val in DEFECT_DIMENSIONS.items() if d in h)
        kinds = {_is_defect(h) for h in best_hyps}
        undet_reason = "unidentifiable" if len(kinds) > 1 else "insufficient"
    posterior = [(h, w / z) for (h, _, _), w in zip(scored, weights)]
    return PolicyMap(values, marginals, a1_reason, excluded, q2, best, best_hyps, undet_reason, posterior)
