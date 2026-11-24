from __future__ import annotations

from typing import List

from ..probe.catalog import PROBE_IDS
from ..simulator.attribution import DEVICE_BOUND, VictimProfile
from .hypotheses import Hypothesis, all_hypotheses
from .policy_mapper import predict


def indistinguishable_groups(victim: VictimProfile = DEVICE_BOUND) -> List[List[Hypothesis]]:
    groups = {}
    for h in all_hypotheses():
        signature = tuple(predict(h, p, victim) for p in PROBE_IDS)
        groups.setdefault(signature, []).append(h)
    return list(groups.values())
