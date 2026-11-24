from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, Iterable, Optional

from ..probe.catalog import ProbeObservation, tail_symbols
from ..simulator.rp_model import REJECT
from .hypotheses import DEFECT_DIMENSIONS
from .policy_mapper import EngineParams, PolicyMap, _usable, decide, predict, score_hypotheses

CORRUPTION, POLICY, NONE = "corruption", "policy", "none"
DEFECT_PROBES = ("P_CORRUPT", "P_CORRUPT_CTR")
FORGED_PROBES = ("P_TAMPER_K", "P_REVOKE", "P_CORRUPT", "P_CORRUPT_CTR")


@dataclass
class BlockCause:
    verdict: str
    reason: Optional[str]
    per_probe: Dict[str, dict] = field(default_factory=dict)
    policy_map: Optional[PolicyMap] = None
    note: Optional[str] = None


def blocked(probe_id: str, symbols) -> bool:
    tail = tail_symbols(ProbeObservation(probe_id, (), tuple(symbols)))
    return len(tail) >= 2 and tail[0] == REJECT and tail[1] == REJECT


@lru_cache(maxsize=None)
def _cause(key: tuple, dims: tuple, probe_id: str, victim) -> str:
    h = dict(zip(dims, key))
    if not blocked(probe_id, predict(h, probe_id, victim)[1]):
        return NONE
    fixed = dict(h)
    for d, defect_value in DEFECT_DIMENSIONS.items():
        if d in fixed:
            fixed[d] = 1 - defect_value
    if fixed == h:
        return POLICY
    return POLICY if blocked(probe_id, predict(fixed, probe_id, victim)[1]) else CORRUPTION


def cause(h, probe_id: str, victim) -> str:
    dims = tuple(h.keys())
    return _cause(tuple(int(h[d]) for d in dims), dims, probe_id, victim)


def _trial_cause(h, kept) -> str:
    causes = {cause(h, probe_id, victim) for probe_id, victim in kept}
    return CORRUPTION if CORRUPTION in causes else (POLICY if POLICY in causes else NONE)


def attribute(observations: Iterable[ProbeObservation], params: EngineParams) -> BlockCause:
    observations = list(observations)
    pm = decide(score_hypotheses(observations), params)
    if pm.abstain_reason == "A1" or pm.posterior is None:
        return BlockCause("undetermined", "out_of_model", {}, pm)

    usable, a0 = _usable(observations)
    a1 = set(pm.excluded_probes) - set(a0)
    kept = tuple((probe_id, victim) for probe_id, _, victim in usable if probe_id not in a1)
    kept_ids = {probe_id for probe_id, _ in kept}

    mass = {CORRUPTION: 0.0, POLICY: 0.0, NONE: 0.0}
    for h, w in pm.posterior:
        mass[_trial_cause(h, kept)] += w
    per: Dict[str, dict] = {"_trial": {"p_corruption": mass[CORRUPTION], "p_policy": mass[POLICY], "p_none": mass[NONE]}}
    for probe_id, victim in kept:
        per[probe_id] = {"p_corruption": sum(w for h, w in pm.posterior if cause(h, probe_id, victim) == CORRUPTION),
                         "p_policy": sum(w for h, w in pm.posterior if cause(h, probe_id, victim) == POLICY)}

    if mass[CORRUPTION] >= params.tau:
        return BlockCause("state_corruption", None, per, pm)
    if any(blocked(probe_id, syms) for probe_id, syms, _ in usable if probe_id in a1):
        return BlockCause("undetermined", "out_of_model", per, pm)
    if not all(p in kept_ids for p in DEFECT_PROBES):
        return BlockCause("undetermined", "defect_probe_missing", per, pm)
    if mass[POLICY] + mass[NONE] >= params.tau:
        unexplained = [probe_id for probe_id, syms, victim in usable
                       if probe_id in kept_ids and blocked(probe_id, syms)
                       and any(cause(h, probe_id, victim) == NONE for h in pm.best_hypotheses)]
        if any(p in FORGED_PROBES for p in unexplained):
            return BlockCause("undetermined", "out_of_model", per, pm)
        if unexplained:
            return BlockCause("normal_policy", None, per, pm, note="unmodeled_policy")
        return BlockCause("normal_policy" if mass[POLICY] >= mass[NONE] else "no_block", None, per, pm)
    kinds = {_trial_cause(h, kept) == CORRUPTION for h in pm.best_hypotheses}
    return BlockCause("undetermined", "unidentifiable" if len(kinds) > 1 else "insufficient", per, pm)
