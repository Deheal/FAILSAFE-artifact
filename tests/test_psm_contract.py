import dataclasses

DIMS = ["verify_before_store", "store_counter_before_verify", "check_uv", "check_bebs",
        "check_signcount", "count_normal", "count_tamper", "revoke_on_tamper"]
PROBES = {"P_UV0", "P_BEBS", "P_SC_DEC", "P_WRONG_CRED", "P_TAMPER_K", "P_REVOKE",
          "P_CORRUPT", "P_CORRUPT_CTR"}


def _hypotheses():
    from failsafe.inference.hypotheses import all_hypotheses
    return all_hypotheses()


def _observe(policy, victim=None, order=None):
    from failsafe.probe.catalog import PROBE_IDS, run_probe
    from failsafe.probe.targets import SimTarget
    target = SimTarget(policy, victim=victim)
    return [run_probe(target, p) for p in (order or PROBE_IDS)]


def _infer(observations):
    from failsafe.inference.policy_mapper import EngineParams, infer
    return infer(observations, EngineParams(per_probe_a1=True))


def _is_defect(h):
    from failsafe.inference.hypotheses import DEFECT_DIMENSIONS
    return any(h[d] == val for d, val in DEFECT_DIMENSIONS.items())


def _policy(h):
    from failsafe.inference.hypotheses import policy_from_hypothesis
    return policy_from_hypothesis(h)


def test_hypothesis_space_has_eight_dimensions_and_256_hypotheses():
    from failsafe.inference.hypotheses import DIMENSIONS
    assert list(DIMENSIONS) == DIMS
    hs = _hypotheses()
    assert len(hs) == 256
    assert len({tuple(h[d] for d in DIMS) for h in hs}) == 256


def test_probe_catalog_matches_protocol():
    from failsafe.probe.catalog import PROBE_IDS
    assert set(PROBE_IDS) == PROBES


def test_prediction_equals_simulated_observation_for_every_hypothesis():
    from failsafe.inference.policy_mapper import predict
    for h in _hypotheses():
        for obs in _observe(_policy(h)):
            assert predict(h, obs.probe_id) == (obs.control_symbols, obs.symbols), (h, obs.probe_id)


def test_probe_results_do_not_depend_on_order():
    from failsafe.probe.catalog import PROBE_IDS
    for h in _hypotheses():
        forward = {o.probe_id: o for o in _observe(_policy(h))}
        backward = {o.probe_id: o for o in _observe(_policy(h), order=list(reversed(PROBE_IDS)))}
        assert forward == backward, h


def test_in_model_decisions_are_never_wrong():
    for h in _hypotheses():
        pm = _infer(_observe(_policy(h)))
        assert pm.abstain_reason is None, h
        for d in DIMS:
            assert pm.values[d] in (None, h[d]), (h, d, pm.values[d])


def test_undetermined_dimensions_are_explained_by_identifiability():
    from failsafe.inference.identifiability import indistinguishable_groups
    group_of = {}
    for group in indistinguishable_groups():
        for h in group:
            group_of[tuple(h[d] for d in DIMS)] = group
    for h in _hypotheses():
        pm = _infer(_observe(_policy(h)))
        group = group_of[tuple(h[d] for d in DIMS)]
        for d in DIMS:
            if pm.values[d] is None:
                assert len({g[d] for g in group}) > 1, (h, d)


def test_revoke_masks_defect_as_expected():
    from failsafe.inference.identifiability import indistinguishable_groups
    base = dict({d: 1 for d in DIMS}, store_counter_before_verify=0)
    a = dict(base, verify_before_store=0, revoke_on_tamper=1)
    b = dict(base, verify_before_store=1, revoke_on_tamper=1)
    assert any(a in g and b in g for g in indistinguishable_groups())


def test_defect_rp_is_attributed_to_state_corruption():
    for defect in ({d: 0 for d in DIMS},
                   dict({d: 0 for d in DIMS}, verify_before_store=1,
                        store_counter_before_verify=1, check_signcount=1)):
        assert _infer(_observe(_policy(defect))).q2 == "state_corruption", defect


def test_revoking_rp_is_not_attributed_to_state_corruption():
    h = dict({d: 0 for d in DIMS}, verify_before_store=1, revoke_on_tamper=1)
    assert _infer(_observe(_policy(h))).q2 != "state_corruption"


def test_no_state_corruption_verdict_for_any_non_defect_hypothesis():
    for h in _hypotheses():
        if not _is_defect(h):
            assert _infer(_observe(_policy(h))).q2 != "state_corruption", h


def test_oom_dev_lock_longer_than_wait_is_never_corruption():
    for h in _hypotheses():
        if _is_defect(h):
            continue
        if h["count_normal"] == 1 or h["count_tamper"] == 1:
            policy = dataclasses.replace(_policy(h), lock_duration_sec=7200)
            assert _infer(_observe(policy)).q2 != "state_corruption", h


def test_oom_dev_persistent_block_after_normal_failures_excludes_that_probe():
    for h in _hypotheses():
        if not _is_defect(h) and h["count_normal"] == 1 and h["revoke_on_tamper"] == 0:
            policy = dataclasses.replace(_policy(h), lock_duration_sec=7200)
            pm = _infer(_observe(policy))
            assert pm.abstain_reason == "A1-probe", h
            assert "P_WRONG_CRED" in pm.excluded_probes, h
            assert pm.q2 != "state_corruption", h


def test_oom_dev_strict_rp_rejecting_legit_sync_is_never_corruption():
    from failsafe.simulator.attribution import VictimProfile
    synced = VictimProfile("동기화 완료", (True, False), (True, True))
    for h in _hypotheses():
        policy = dataclasses.replace(_policy(h), allowed_flag_transitions=frozenset())
        pm = _infer(_observe(policy, victim=synced))
        assert pm.q2 != "state_corruption", h


def test_ground_truth_type_lives_only_in_oracle():
    import failsafe.contracts as contracts
    from failsafe.oracle import ServerStateSnapshot
    assert not hasattr(contracts, "ServerStateSnapshot")
