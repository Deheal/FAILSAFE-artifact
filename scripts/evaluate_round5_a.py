import json
import random
import sys
import time
from collections import Counter
from multiprocessing import Pool
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_sim import flip
from failsafe.inference.baselines import baseline_q2
from failsafe.inference.block_cause import attribute
from failsafe.inference.policy_mapper import EngineParams
from failsafe.probe import PROBE_IDS
from failsafe.probe.catalog import ProbeObservation
from failsafe.simulator.attribution import VICTIMS
from failsafe.simulator.rp_model import BLOCKED_PRE, ERROR, REJECT

PARAMS = EngineParams(eps=0.1, tau=0.99, m=2, per_probe_a1=True)
VICTIM_BY_NAME = {v.name: v for v in VICTIMS}
SOURCES = [ROOT / "results" / "real_v3", ROOT / "results" / "real_v4"]
OUT = ROOT / "results" / "round5_a"
SEED_A = 20261115
QS = [0.0, 0.01, 0.05]
DRAWS = 30
METHODS = ["FAILSAFE", "v2 규칙", "복구만", "단순 재시도", "단일 응답"]


def conditions():
    dirs = [d for src in SOURCES for d in src.iterdir() if (d / "observations.jsonl").exists()]
    return sorted(dirs, key=lambda d: d.name)


def load(rp_dir):
    reps = {}
    for line in (rp_dir / "observations.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        reps.setdefault(r["rep"], {})[r["probe_id"]] = ProbeObservation(
            r["probe_id"], tuple(r["control_symbols"]), tuple(r["symbols"]), VICTIM_BY_NAME[r["victim"]])
    return {rep: [obs[p] for p in PROBE_IDS if p in obs] for rep, obs in sorted(reps.items())}


def _fold(symbols):
    return tuple(REJECT if s == BLOCKED_PRE else s for s in symbols)


def noisy_real(obs, q, rng):
    out = []
    for o in obs:
        ctrl, syms = _fold(o.control_symbols), _fold(o.symbols)
        if ERROR in ctrl or ERROR in syms:
            for _ in range(len(ctrl) + len(syms)):
                rng.random()
            out.append(ProbeObservation(o.probe_id, ctrl, syms, o.victim))
        else:
            out.append(ProbeObservation(o.probe_id, flip(ctrl, q, rng), flip(syms, q, rng), o.victim))
    return out


def judge_condition(args):
    idx, rp_dir, q = args
    rng = random.Random(SEED_A + idx)
    reps = load(Path(rp_dir))
    rows = []
    for rep, obs in reps.items():
        for draw in range(DRAWS if q > 0 else 1):
            o = obs if q == 0 else noisy_real(obs, q, rng)
            bc = attribute(o, PARAMS)
            v = {"FAILSAFE": bc.verdict}
            v.update(baseline_q2(o))
            rows.append({"rep": rep, "draw": draw, **{m: v[m] for m in METHODS}})
    return Path(rp_dir).name, q, rows


def score(verdicts, truth):
    c = Counter(verdicts)
    n = len(verdicts)
    pos = truth == "state_corruption"
    return {
        "n": n,
        "dist": dict(c),
        "false_corruption": 0 if pos else c["state_corruption"],
        "confident_miss": (c["normal_policy"] + c["no_block"]) if pos else 0,
        "detected": c["state_corruption"] if pos else None,
        "undetermined": c["undetermined"],
        "label_correct": None if pos else c[truth],
    }


def evaluate(judged):
    from failsafe.oracle.real_ground_truth import BLOCK_CAUSE_TRUTH, BLOCK_CAUSE_TRUTH_V4
    truth_all = {**BLOCK_CAUSE_TRUTH, **BLOCK_CAUSE_TRUTH_V4}
    res = {}
    for (rp, q), rows in judged.items():
        truth = truth_all[rp]
        res.setdefault(str(q), {})[rp] = {"truth": truth,
                                          **{m: score([r[m] for r in rows], truth) for m in METHODS}}
    return res


def totals(per_cond):
    t = {}
    for m in METHODS:
        neg = [c[m] for c in per_cond.values() if c["truth"] != "state_corruption"]
        pos = [c[m] for c in per_cond.values() if c["truth"] == "state_corruption"]
        t[m] = {
            "fp_conditions": sum(x["false_corruption"] > 0 for x in neg), "n_neg": len(neg),
            "fp_trials": sum(x["false_corruption"] for x in neg), "neg_trials": sum(x["n"] for x in neg),
            "miss_conditions": sum(x["confident_miss"] > 0 for x in pos), "n_pos": len(pos),
            "miss_trials": sum(x["confident_miss"] for x in pos), "pos_trials": sum(x["n"] for x in pos),
            "detected_trials": sum(x["detected"] for x in pos),
            "undetermined_trials": sum(x["undetermined"] for x in neg + pos),
            "label_correct_trials": sum(x["label_correct"] for x in neg),
        }
        t[m]["confident_errors"] = t[m]["fp_trials"] + t[m]["miss_trials"]
    return t


def main():
    t0 = time.time()
    conds = conditions()
    assert len(conds) == 17, [d.name for d in conds]
    tasks = [(i, str(d), q) for q in QS for i, d in enumerate(conds)]
    with Pool(10) as pool:
        judged = {(rp, q): rows for rp, q, rows in pool.imap_unordered(judge_condition, tasks)}
    res = evaluate(judged)
    tot = {q: totals(v) for q, v in res.items()}

    rule = {q: tot[q]["FAILSAFE"]["confident_errors"] < tot[q]["v2 규칙"]["confident_errors"] for q in ("0.01", "0.05")}
    verdict = all(rule.values())

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.json").write_text(json.dumps({
        "params": PARAMS.__dict__, "seed": SEED_A, "draws": DRAWS,
        "condition_order": [d.name for d in conds],
        "per_condition": res, "totals": tot, "decision_rule": {"per_q": rule, "superiority_confirmed": verdict},
        "elapsed_sec": round(time.time() - t0, 1)}, indent=1, ensure_ascii=False), encoding="utf-8")

    L = ["# 5차 실험 A — 실관측 잡음 재생 (자동 생성: scripts/evaluate_round5_a.py)", "",
         f"엔진 v2.2 동결, ε=0.1 τ=0.99 m=2. 17개 조건 × 30 실시행 × {DRAWS} 추첨. SEED_A={SEED_A}. "
         f"q=0은 잡음 없는 재현 점검(추첨 1회).", ""]
    for q in [str(x) for x in QS]:
        L += [f"## q = {q}", "",
              "| 방식 | 오탐 조건 | 오탐 시행 | 확신 놓침 조건 | 확신 놓침 시행 | 확신 오류 합 | 변조 탐지 | 유보 | 표지 정답(비변조) |",
              "|---|---|---|---|---|---|---|---|---|"]
        for m in METHODS:
            x = tot[q][m]
            L.append(f"| {m} | {x['fp_conditions']}/{x['n_neg']} | {x['fp_trials']}/{x['neg_trials']} "
                     f"| {x['miss_conditions']}/{x['n_pos']} | {x['miss_trials']}/{x['pos_trials']} "
                     f"| **{x['confident_errors']}** | {x['detected_trials']}/{x['pos_trials']} "
                     f"| {x['undetermined_trials']} | {x['label_correct_trials']}/{x['neg_trials']} |")
        L += ["", "조건별 (FAILSAFE / v2 규칙):", "",
              "| 조건 | 정답 | FAILSAFE 분포 | v2 규칙 분포 |", "|---|---|---|---|"]
        for rp, c in res[q].items():
            L.append(f"| {rp} | {c['truth']} | {c['FAILSAFE']['dist']} | {c['v2 규칙']['dist']} |")
        L.append("")
    L += ["## 사전 고정 판정 규칙 (계획서 4.4절)", "",
          f"- q=0.01: FAILSAFE 확신 오류 {tot['0.01']['FAILSAFE']['confident_errors']} vs v2 규칙 "
          f"{tot['0.01']['v2 규칙']['confident_errors']} → {'충족' if rule['0.01'] else '미충족'}",
          f"- q=0.05: FAILSAFE 확신 오류 {tot['0.05']['FAILSAFE']['confident_errors']} vs v2 규칙 "
          f"{tot['0.05']['v2 규칙']['confident_errors']} → {'충족' if rule['0.05'] else '미충족'}",
          f"- 결론: {'실관측 기저에서도 우위 확인' if verdict else '우위 주장 범위를 줄여 보고'}",
          "", f"소요 {round(time.time() - t0)}초"]
    (OUT / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
