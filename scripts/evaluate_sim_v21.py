import dataclasses
import json
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import evaluate_sim_v2 as test_sets
import select_params_v2 as dev_sets
from evaluate_sim import OOMTarget, noisy
from failsafe.inference.baselines import baseline_q2
from failsafe.inference.block_cause import attribute, blocked
from failsafe.inference.hypotheses import all_hypotheses
from failsafe.inference.policy_mapper import EngineParams
from failsafe.probe import PROBE_IDS, run_probe
from failsafe.probe.targets import SimSession

SEED = 20261111
Q_LEVELS = (0.0, 0.01, 0.05)
NOISY_REPS = 30
PARAMS = EngineParams(eps=0.1, tau=0.99, m=2, per_probe_a1=True)
ENGINE = "FAILSAFE v2.2(차단 원인)"
BASELINES = ["v2 규칙", "v2 규칙(대조 없음)", "복구만", "단순 재시도", "단일 응답"]


def trial_truth(policy, victim, cls):
    fixed = dataclasses.replace(policy, store_before_verify=False, store_counter_before_verify=False)
    clean, causes = [], set()
    for p in PROBE_IDS:
        obs = run_probe(OOMTarget(policy, victim, cls), p)
        clean.append(obs)
        if blocked(p, obs.symbols):
            still = blocked(p, run_probe(OOMTarget(fixed, victim, cls), p).symbols)
            causes.add("policy" if still else "corruption")
    truth = "state_corruption" if "corruption" in causes else ("normal_policy" if causes else "no_block")
    return truth, clean


def targets(which):
    if which == "dev":
        dev, _ = dev_sets.split()
        return [(name, policy, victim, SimSession) for name, policy, victim, _ in dev_sets.targets(dev)]
    _, holdout = test_sets.split()
    return test_sets.targets(holdout, all_hypotheses())


def main(which):
    t0 = time.time()
    rng = random.Random(SEED + (11 if which == "dev" else 12))
    cells = defaultdict(lambda: defaultdict(Counter))
    reasons = defaultdict(Counter)
    for set_name, policy, victim, cls in targets(which):
        truth, clean = trial_truth(policy, victim, cls)
        for q in Q_LEVELS:
            for _ in range(1 if q == 0 else NOISY_REPS):
                obs = clean if q == 0 else noisy(clean, q, rng)
                bc = attribute(obs, PARAMS)
                verdicts = {ENGINE: bc.verdict}
                if which == "test":
                    verdicts.update(baseline_q2(obs))
                if bc.verdict == "undetermined":
                    reasons[(set_name, q)][bc.reason] += 1
                for m, v in verdicts.items():
                    c = cells[(set_name, q)][m]
                    c["n"] += 1
                    c["v_" + v] += 1
                    c["t_" + truth] += 1
                    c["fp"] += truth != "state_corruption" and v == "state_corruption"
                    c["miss"] += truth == "state_corruption" and v in ("normal_policy", "no_block")
                    c["hit"] += truth == "state_corruption" and v == "state_corruption"
                    c["policy_ok"] += truth == "normal_policy" and v == "normal_policy"
                    c["noblock_ok"] += truth == "no_block" and v == "no_block"
                    c["label_swap"] += {truth, v} == {"normal_policy", "no_block"}
    print(f"[{which}] 완료 {time.time() - t0:.0f}초\n")

    out = {"which": which, "params": dataclasses.asdict(PARAMS), "seed": SEED, "cells": []}
    print(f"{'세트':<22} {'q':>5} {'방식':<24} {'n':>6} {'오탐':>12} {'확신놓침':>12} {'변조 탐지':>12} "
          f"{'정책 맞힘':>12} {'차단없음 맞힘':>13} {'정책↔없음':>9} {'불가':>6}")
    failed = False
    for (s, q) in sorted(cells):
        for m in [ENGINE] + (BASELINES if which == "test" else []):
            c = cells[(s, q)][m]
            neg = c["n"] - c["t_state_corruption"]
            out["cells"].append({"set": s, "q": q, "method": m, **c})
            print(f"{s:<22} {q:>5} {m:<24} {c['n']:>6} {str(c['fp']) + '/' + str(neg):>12} "
                  f"{str(c['miss']) + '/' + str(c['t_state_corruption']):>12} "
                  f"{str(c['hit']) + '/' + str(c['t_state_corruption']):>12} "
                  f"{str(c['policy_ok']) + '/' + str(c['t_normal_policy']):>12} "
                  f"{str(c['noblock_ok']) + '/' + str(c['t_no_block']):>13} {c['label_swap']:>9} {c['v_undetermined']:>6}")
            if m == ENGINE and q <= 0.01 and (c["fp"] or c["miss"]):
                failed = True
        r = reasons[(s, q)]
        print(f"{'':<28} 유보 사유: {dict(r)}")
        out["cells"].append({"set": s, "q": q, "method": "유보 사유", **r})
    if which == "dev":
        print("\n통과 기준(q<=0.01에서 확신 오판 0): " + ("실패" if failed else "통과"))
        out["dev_pass"] = not failed
    (ROOT / "results" / f"sim_eval_v22_{which}.json").write_text(
        json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    assert len(sys.argv) == 2 and sys.argv[1] in ("dev", "test"), "사용법: evaluate_sim_v21.py dev|test"
    main(sys.argv[1])
