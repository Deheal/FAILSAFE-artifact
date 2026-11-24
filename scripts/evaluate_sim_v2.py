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

from evaluate_sim import CloneStickySession, FlagRequireSession, OOMTarget, noisy
from failsafe.inference.baselines import baseline_q2
from failsafe.inference.hypotheses import (DEFECT_DIMENSIONS, DIMENSIONS, all_hypotheses,
                                           hypothesis_key, policy_from_hypothesis)
from failsafe.inference.policy_mapper import EngineParams, decide, score_hypotheses
from failsafe.oracle import true_hypothesis
from failsafe.probe import PROBE_IDS, run_probe
from failsafe.probe.catalog import HIGH_COUNTER, tampered_flags
from failsafe.probe.targets import SimSession
from failsafe.simulator.attribution import DEVICE_BOUND, VICTIMS
from failsafe.simulator.rp_model import ACCEPT, REJECT, Request

SEED = 20261111
Q_LEVELS = (0.0, 0.01, 0.05)
NOISY_REPS = 30
PARAMS = EngineParams(eps=0.1, tau=0.99, m=2, per_probe_a1=True)
PARAMS_WHOLE = dataclasses.replace(PARAMS, per_probe_a1=False)
ENGINE, ENGINE_WHOLE = "엔진(프로브별 A1)", "엔진(시행 전체 A1)"
METHODS = [ENGINE, ENGINE_WHOLE, "v2 규칙", "v2 규칙(대조 없음)", "복구만", "단순 재시도", "단일 응답"]


def split():
    keys = sorted(hypothesis_key(h) for h in all_hypotheses())
    random.Random(SEED).shuffle(keys)
    to_h = lambda k: dict(zip(DIMENSIONS, k))
    half = len(keys) // 2
    return [to_h(k) for k in keys[:half]], [to_h(k) for k in keys[half:]]


def _first_login_after_forged(policy, victim, cls, forged):
    s = cls(policy, victim)
    s.send(forged, at=2.0)
    return s.send(Request("valid", be=victim.current[0], bs=victim.current[1], uv=True, counter=s.next_counter()), at=4.0)


def blocking_truth(policy, victim, cls):
    fixed = dataclasses.replace(policy, store_before_verify=False, store_counter_before_verify=False)
    be, bs = tampered_flags(victim)
    forged_reqs = [Request("forged", be=be, bs=bs, uv=True, counter=0),
                   Request("forged", be=victim.current[0], bs=victim.current[1], uv=True, counter=HIGH_COUNTER)]
    return any(_first_login_after_forged(policy, victim, cls, r) == REJECT
               and _first_login_after_forged(fixed, victim, cls, r) == ACCEPT for r in forged_reqs)


def targets(holdout, hyps):
    out = []
    for h in holdout:
        for v in VICTIMS:
            out.append(("sim-holdout", policy_from_hypothesis(h), v, SimSession))
    for h in hyps:
        if h["check_signcount"]:
            for v in VICTIMS:
                out.append(("oom-test:clone_sticky", policy_from_hypothesis(h), v, CloneStickySession))
        out.append(("oom-test:flag_require", policy_from_hypothesis(h), DEVICE_BOUND, FlagRequireSession))
    return out


def main():
    t0 = time.time()
    _, holdout = split()
    rng = random.Random(SEED + 2)
    cells = defaultdict(lambda: defaultdict(Counter))
    q1 = defaultdict(Counter)
    for set_name, policy, victim, cls in targets(holdout, all_hypotheses()):
        truth = true_hypothesis(policy)
        defect = any(truth[d] == v for d, v in DEFECT_DIMENSIONS.items())
        block = blocking_truth(policy, victim, cls)
        target = OOMTarget(policy, victim, cls)
        clean = [run_probe(target, p) for p in PROBE_IDS]
        for q in Q_LEVELS:
            for _ in range(1 if q == 0 else NOISY_REPS):
                obs = clean if q == 0 else noisy(clean, q, rng)
                scored = score_hypotheses(obs)
                pm = decide(scored, PARAMS)
                verdicts = {ENGINE: pm.q2, ENGINE_WHOLE: decide(scored, PARAMS_WHOLE).q2, **baseline_q2(obs)}
                for m, v in verdicts.items():
                    c = cells[(set_name, q)][m]
                    c["n"] += 1
                    c[v] += 1
                    c["neg_defect"] += not defect
                    c["pos_defect"] += defect
                    c["fp_defect"] += (not defect) and v == "state_corruption"
                    c["miss_defect"] += defect and v == "normal_policy"
                    c["hit_defect"] += defect and v == "state_corruption"
                    c["pos_block"] += block
                    c["fp_block"] += (not block) and v == "state_corruption"
                    c["hit_block"] += block and v == "state_corruption"
                    c["miss_block"] += block and v == "normal_policy"
                c = q1[(set_name, q)]
                c["n"] += 1
                c["A1_all"] += pm.abstain_reason == "A1"
                c["excluded_any"] += bool(pm.excluded_probes)
                c["undet_" + str(pm.q2_undetermined_reason)] += pm.q2 == "undetermined"
                if set_name == "sim-holdout":
                    for d in DIMENSIONS:
                        v = pm.values[d]
                        c["dims"] += 1
                        c["dim_undet"] += v is None
                        c["dim_wrong"] += v is not None and v != truth[d]
    print(f"완료 {time.time() - t0:.0f}초\n")

    out = {"params": dataclasses.asdict(PARAMS), "seed": SEED, "q_levels": Q_LEVELS, "noisy_reps": NOISY_REPS, "cells": []}
    print(f"{'세트':<22} {'q':>5} {'방식':<18} {'n':>6} {'변조':>6} {'정상':>6} {'불가':>6} "
          f"{'오탐/결함없음':>12} {'확신놓침/결함':>12} {'탐지/결함':>12} {'오탐(차단)':>9} {'탐지/차단양성':>12}")
    for (s, q) in sorted(cells):
        for m in METHODS:
            c = cells[(s, q)][m]
            out["cells"].append({"set": s, "q": q, "method": m, **c})
            print(f"{s:<22} {q:>5} {m:<18} {c['n']:>6} {c['state_corruption']:>6} {c['normal_policy']:>6} "
                  f"{c['undetermined']:>6} {str(c['fp_defect']) + '/' + str(c['neg_defect']):>12} "
                  f"{str(c['miss_defect']) + '/' + str(c['pos_defect']):>12} "
                  f"{str(c['hit_defect']) + '/' + str(c['pos_defect']):>12} {c['fp_block']:>9} "
                  f"{str(c['hit_block']) + '/' + str(c['pos_block']):>12}")
        x = q1[(s, q)]
        extra = (f", Q1 틀림 {x['dim_wrong']}/{x['dims']}, Q1 판별불가 {x['dim_undet'] / x['dims']:.3f}" if x["dims"] else "")
        print(f"{'':<28} 엔진(프로브별): 전체 유보 {x['A1_all']}/{x['n']}, 프로브 제외 있음 {x['excluded_any']}/{x['n']}, "
              f"유보 분해 원리 {x['undet_unidentifiable']} / 증거부족 {x['undet_insufficient']}{extra}")
        out["cells"].append({"set": s, "q": q, "method": "엔진 Q1/유보", **x})
    (ROOT / "results" / "sim_eval_v2.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
