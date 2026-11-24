import dataclasses
import itertools
import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from failsafe.inference.hypotheses import DIMENSIONS, all_hypotheses, hypothesis_key, policy_from_hypothesis
from failsafe.inference.policy_mapper import EngineParams, decide, score_hypotheses
from failsafe.oracle import true_hypothesis
from failsafe.probe import PROBE_IDS, SimTarget, run_probe
from failsafe.probe.catalog import ProbeObservation
from failsafe.simulator.attribution import VICTIMS as VICTIM_PROFILES, VictimProfile
from failsafe.simulator.rp_model import ACCEPT, REJECT

SEED = 20261111
Q_LEVELS = (0.0, 0.01, 0.05)
NOISY_REPS = 30
GRID = list(itertools.product((0.001, 0.01, 0.05, 0.1), (0.9, 0.95, 0.99), (0, 1, 2)))
SYNCED = VictimProfile("동기화 완료", (True, False), (True, True))


from failsafe.inference.hypotheses import DEFECT_DIMENSIONS


def _is_defect(h):
    return any(h[d] == v for d, v in DEFECT_DIMENSIONS.items())


def split():
    n = len(all_hypotheses())
    keys = sorted(hypothesis_key(h) for h in all_hypotheses())
    random.Random(SEED).shuffle(keys)
    to_h = lambda k: dict(zip(DIMENSIONS, k))
    half = n // 2
    return [to_h(k) for k in keys[:half]], [to_h(k) for k in keys[half:]]


def targets(dev):
    out = []
    for h in dev:
        for v in VICTIM_PROFILES:
            out.append(("sim-dev", policy_from_hypothesis(h), v, _is_defect(h)))
    for h in dev:
        if h["count_normal"] or h["count_tamper"]:
            p = dataclasses.replace(policy_from_hypothesis(h), lock_duration_sec=7200)
            for v in VICTIM_PROFILES:
                out.append(("oom-dev:lock>W", p, v, _is_defect(h)))
        p = dataclasses.replace(policy_from_hypothesis(h), allowed_flag_transitions=frozenset())
        out.append(("oom-dev:strict+sync", p, SYNCED, _is_defect(h)))
    return out


def flip(symbols, q, rng):
    return tuple((REJECT if s == ACCEPT else ACCEPT) if rng.random() < q else s for s in symbols)


def noisy(obs, q, rng):
    return [ProbeObservation(o.probe_id, flip(o.control_symbols, q, rng), flip(o.symbols, q, rng), o.victim)
            for o in obs]


def main():
    t0 = time.time()
    dev, _ = split()
    rng = random.Random(SEED + 1)
    tally = {g: {} for g in GRID}
    by_victim = {g: {} for g in GRID}
    for set_name, policy, victim, is_defect in targets(dev):
        truth = true_hypothesis(policy)
        clean = [run_probe(SimTarget(policy, victim), p) for p in PROBE_IDS]
        for q in Q_LEVELS:
            for _ in range(1 if q == 0 else NOISY_REPS):
                scored = score_hypotheses(clean if q == 0 else noisy(clean, q, rng))
                for g in GRID:
                    pm = decide(scored, EngineParams(*g, per_probe_a1=True))
                    c = tally[g].setdefault((set_name.split(":")[0], q), dict(
                        n=0, fp=0, confident_miss=0, q2_undet=0, a1=0, dims=0, dims_undet=0, dims_wrong=0))
                    c["n"] += 1
                    c["fp"] += (not is_defect) and pm.q2 == "state_corruption"
                    c["confident_miss"] += is_defect and pm.q2 == "normal_policy"
                    c["q2_undet"] += pm.q2 == "undetermined"
                    c["a1"] += pm.abstain_reason in ("A1", "A1-probe")
                    if set_name == "sim-dev" and q == 0:
                        b = by_victim[g].setdefault(victim.name, dict(n=0, corruption=0, normal=0, undetermined=0))
                        b["n"] += 1
                        b[{"state_corruption": "corruption", "normal_policy": "normal"}.get(pm.q2, "undetermined")] += 1
                    if set_name == "sim-dev":
                        for d in DIMENSIONS:
                            c["dims"] += 1
                            c["dims_undet"] += pm.values[d] is None
                            c["dims_wrong"] += pm.values[d] is not None and pm.values[d] != truth[d]
    print(f"관측 완료 {time.time() - t0:.0f}초")

    def feasible(g, qs, q1=True):
        return all(c["fp"] == 0 and c["confident_miss"] == 0 and (not q1 or c["dims_wrong"] == 0)
                   for (s, q), c in tally[g].items() if q in qs)

    qs = list(Q_LEVELS)
    while qs and not any(feasible(g, qs) for g in GRID):
        qs.pop()
    dropped = [q for q in Q_LEVELS if q not in qs]
    v12 = [g for g in GRID if feasible(g, list(Q_LEVELS), q1=False)]

    def objective(g):
        dev_cells = [tally[g][("sim-dev", q)] for q in qs]
        q2u = sum(c["q2_undet"] / c["n"] for c in dev_cells) / len(qs)
        du = sum(c["dims_undet"] / c["dims"] for c in dev_cells) / len(qs)
        eps, tau, m = g
        return (round(q2u, 9), round(du, 9), m, -tau, eps)

    candidates = sorted((g for g in GRID if feasible(g, qs)), key=objective)
    chosen = candidates[0] if candidates else None

    rows = []
    for g in GRID:
        for (s, q), c in sorted(tally[g].items()):
            rows.append(dict(eps=g[0], tau=g[1], m=g[2], set=s, q=q, **c))
    out = dict(protocol="policy_protocol.md 6.1", seed=SEED, q_levels=Q_LEVELS, noisy_reps=NOISY_REPS,
               q_levels_used=qs, q_levels_dropped=dropped,
               feasible=[list(g) for g in candidates],
               chosen=dict(zip(("eps", "tau", "m"), chosen)) if chosen else None,
               chosen_objective=objective(chosen) if chosen else None,
               chosen_under_v1_2_rule=dict(zip(("eps", "tau", "m"), min(v12, key=objective))) if v12 else None,
               by_victim_q0={f"{g[0]},{g[1]},{g[2]}": by_victim[g] for g in GRID},
               cells=rows)
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "param_selection_v2.json").write_text(json.dumps(out, indent=1, ensure_ascii=False),
                                                           encoding="utf-8")

    print(f"사용한 q: {qs}  뺀 q: {dropped}  제약 만족 조합 {len(candidates)}/{len(GRID)}")
    print(f"선택: {out['chosen']}  목적값(Q2 판별불가, 차원 판별불가, m, -τ, ε) = {out['chosen_objective']}")
    print(f"\n{'ε':>6} {'τ':>5} {'m':>2} | {'세트':<8} {'q':>5} {'n':>5} {'오탐':>4} {'확신놓침':>6} "
          f"{'Q2유보':>7} {'A1':>6} {'차원틀림':>6} {'차원유보':>7}")
    for g in ([chosen] if chosen else []) + [x for x in GRID if x != chosen][:0]:
        for (s, q), c in sorted(tally[g].items()):
            du = f"{c['dims_undet'] / c['dims']:.3f}" if c["dims"] else "-"
            print(f"{g[0]:>6} {g[1]:>5} {g[2]:>2} | {s:<8} {q:>5} {c['n']:>5} {c['fp']:>4} {c['confident_miss']:>6} "
                  f"{c['q2_undet'] / c['n']:>7.3f} {c['a1'] / c['n']:>6.3f} {c['dims_wrong']:>6} {du:>7}")


if __name__ == "__main__":
    main()
