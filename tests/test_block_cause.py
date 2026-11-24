import pytest

from failsafe.inference.block_cause import attribute
from failsafe.inference.hypotheses import policy_from_hypothesis
from failsafe.inference.policy_mapper import EngineParams
from failsafe.probe import PROBE_IDS, SimTarget, run_probe

PARAMS = EngineParams(eps=0.1, tau=0.99, m=2, per_probe_a1=True)
BASE = dict(verify_before_store=1, store_counter_before_verify=0, check_uv=0, check_bebs=1, check_signcount=1,
            count_normal=0, count_tamper=0, revoke_on_tamper=0)


def _attribute(**changes):
    target = SimTarget(policy_from_hypothesis({**BASE, **changes}))
    return attribute([run_probe(target, p) for p in PROBE_IDS], PARAMS)


@pytest.mark.parametrize("changes, expected", [
    ({}, "no_block"),
    ({"verify_before_store": 0}, "state_corruption"),
    ({"store_counter_before_verify": 1}, "state_corruption"),
    ({"count_tamper": 1}, "normal_policy"),
    ({"count_normal": 1}, "normal_policy"),
    ({"revoke_on_tamper": 1}, "normal_policy"),
    ({"verify_before_store": 0, "revoke_on_tamper": 1}, "normal_policy"),
    ({"store_counter_before_verify": 1, "check_signcount": 0}, "no_block"),
])
def test_block_cause_on_in_model_rp(changes, expected):
    assert _attribute(**changes).verdict == expected


def test_defect_presence_output_is_unchanged_by_block_cause():
    bc = _attribute(store_counter_before_verify=1, check_signcount=0)
    assert bc.verdict == "no_block" and bc.policy_map.q2 == "undetermined"


def test_missing_defect_probe_never_yields_normal():
    target = SimTarget(policy_from_hypothesis(BASE))
    obs = [run_probe(target, p) for p in PROBE_IDS if p != "P_CORRUPT"]
    bc = attribute(obs, PARAMS)
    assert bc.verdict == "undetermined" and bc.reason == "defect_probe_missing"


def test_every_defect_hypothesis_has_clean_twin_without_defect_probes():
    from failsafe.inference.hypotheses import all_hypotheses
    from failsafe.simulator.attribution import VICTIMS
    rest = [p for p in PROBE_IDS if p not in ("P_CORRUPT", "P_CORRUPT_CTR")]
    hyps = all_hypotheses()
    is_defect = [h["verify_before_store"] == 0 or h["store_counter_before_verify"] == 1 for h in hyps]
    assert sum(is_defect) == 192
    for victim in VICTIMS:
        pred = [tuple(run_probe(SimTarget(policy_from_hypothesis(h), victim=victim), p).symbols for p in rest)
                for h in hyps]
        clean = {pred[i] for i, d in enumerate(is_defect) if not d}
        missing = [hyps[i] for i, d in enumerate(is_defect) if d and pred[i] not in clean]
        assert not missing, (victim.name, missing[:3])
