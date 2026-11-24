import copy
import dataclasses
import json
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from failsafe.inference.baselines import baseline_q2
from failsafe.inference.hypotheses import DIMENSIONS, all_hypotheses, hypothesis_key, policy_from_hypothesis
from failsafe.inference.policy_mapper import EngineParams, decide, score_hypotheses
from failsafe.oracle import true_hypothesis
from failsafe.simulator.rp import flag_transition_allowed
from failsafe.probe import PROBE_IDS, run_probe
from failsafe.probe.catalog import ProbeObservation, tampered_flags
from failsafe.probe.targets import SimSession, SimTarget
from failsafe.simulator.attribution import DEVICE_BOUND, VICTIMS
from failsafe.simulator.rp_model import ACCEPT, REJECT, Request, rp_handle

SEED = 20261111
Q_LEVELS = (0.0, 0.01, 0.05)
NOISY_REPS = 30
PARAMS = EngineParams(eps=0.1, tau=0.99, m=2)
METHODS = ["엔진(PSM)", "v2 규칙", "v2 규칙(대조 없음)", "복구만", "단순 재시도", "단일 응답"]


def split():
    keys = sorted(hypothesis_key(h) for h in all_hypotheses())
    random.Random(SEED).shuffle(keys)
    to_h = lambda k: dict(zip(DIMENSIONS, k))
    return [to_h(k) for k in keys[:64]], [to_h(k) for k in keys[64:]]


class CloneStickySession(SimSession):
    def __init__(self, policy, victim):
        self.clone = False
        super().__init__(policy, victim)

    def send(self, request, at):
        st = self.state
        if request.kind == "valid" and self.clone:
            return REJECT
        if (request.kind == "valid" and self.policy.track_sign_count and not st.credential_revoked
                and at >= st.locked_until and request.counter <= st.last_sign_count):
            self.clone = True
            return REJECT
        return super().send(request, at)


class FlagRequireSession(SimSession):
    def send(self, request, at):
        if request.kind == "valid" and not request.be:
            return REJECT
        return super().send(request, at)


class OOMTarget(SimTarget):
    def __init__(self, policy, victim, session_cls):
        super().__init__(policy, victim)
        self.session_cls = session_cls

    def new_session(self):
        return self.session_cls(self.policy, self.victim)


def blocking_truth(policy, victim, session_cls=SimSession):
    s = session_cls(policy, victim)
    before = (s.state.stored_be, s.state.stored_bs)
    be, bs = tampered_flags(victim)
    s.send(Request("forged", be=be, bs=bs, counter=0), at=2.0)
    after = (s.state.stored_be, s.state.stored_bs)
    changed = before != after
    blocked_by_flags = changed and not flag_transition_allowed(policy, after[0], after[1], *victim.current)
    return blocked_by_flags


def flip(symbols, q, rng):
    return tuple((REJECT if s == ACCEPT else ACCEPT) if rng.random() < q else s for s in symbols)


def noisy(obs, q, rng):
    return [ProbeObservation(o.probe_id, flip(o.control_symbols, q, rng), flip(o.symbols, q, rng), o.victim)
            for o in obs]


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
        defect = truth["verify_before_store"] == 0
        block = blocking_truth(policy, victim, cls)
        target = OOMTarget(policy, victim, cls)
        clean = [run_probe(target, p) for p in PROBE_IDS]
        for q in Q_LEVELS:
            for _ in range(1 if q == 0 else NOISY_REPS):
                obs = clean if q == 0 else noisy(clean, q, rng)
                pm = decide(score_hypotheses(obs), PARAMS)
                verdicts = {"엔진(PSM)": pm.q2, **baseline_q2(obs)}
                for m, v in verdicts.items():
                    c = cells[(set_name, q)][m]
                    c["n"] += 1
                    c[v] += 1
                    c["fp_defect"] += (not defect) and v == "state_corruption"
                    c["miss_defect"] += defect and v == "normal_policy"
                    c["fp_block"] += (not block) and v == "state_corruption"
                    c["miss_block"] += block and v == "normal_policy"
                    c["pos_block"] += block
                    c["hit_block"] += block and v == "state_corruption"
                c = q1[(set_name, q)]
                c["A1"] += pm.abstain_reason == "A1"
                c["A0_any"] += bool(pm.excluded_probes)
                c["n"] += 1
                if set_name == "sim-holdout":
                    for d in DIMENSIONS:
                        v = pm.values[d]
                        c["dims"] += 1
                        c["dim_undet"] += v is None
                        c["dim_wrong"] += v is not None and v != truth[d]
    print(f"완료 {time.time() - t0:.0f}초")

    out = {"params": PARAMS.__dict__, "seed": SEED, "q_levels": Q_LEVELS, "noisy_reps": NOISY_REPS, "cells": []}
    print(f"\n{'세트':<22} {'q':>5} {'방식':<16} {'n':>5} {'변조':>5} {'정상':>5} {'불가':>5} "
          f"{'오탐(결함)':>8} {'오탐(차단)':>8} {'탐지/차단양성':>12} {'확신놓침(차단)':>10}")
    for (s, q) in sorted(cells):
        for m in METHODS:
            c = cells[(s, q)][m]
            out["cells"].append({"set": s, "q": q, "method": m, **c})
            print(f"{s:<22} {q:>5} {m:<16} {c['n']:>5} {c['state_corruption']:>5} {c['normal_policy']:>5} "
                  f"{c['undetermined']:>5} {c['fp_defect']:>8} {c['fp_block']:>8} "
                  f"{str(c['hit_block']) + '/' + str(c['pos_block']):>12} {c['miss_block']:>10}")
        x = q1[(s, q)]
        extra = (f" Q1 틀림 {x['dim_wrong']}/{x['dims']}, Q1 판별불가 {x['dim_undet'] / x['dims']:.3f}"
                 if x["dims"] else "")
        print(f"{'':<22} {'':>5} 엔진 A1 {x['A1']}/{x['n']}, A0(프로브 제외 있음) {x['A0_any']}/{x['n']}{extra}")
        out["cells"].append({"set": s, "q": q, "method": "엔진 Q1/유보", **x})
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "sim_eval.json").write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    main()
