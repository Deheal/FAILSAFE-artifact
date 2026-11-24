import itertools
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

import failsafe.inference.block_cause as bcm
from evaluate_round5_a import conditions, load, noisy_real
from failsafe.inference.policy_mapper import EngineParams

OUT = ROOT / "results" / "round6"
SEED_D = 20261118
DRAWS = 5
QS = [0.0, 0.01, 0.05]
EPS = [0.01, 0.03, 0.1, 0.2, 0.3]
TAU = [0.9, 0.95, 0.99, 0.999]
M = [0, 1, 2, 3]
GRID = [EngineParams(eps=e, tau=t, m=m, per_probe_a1=True) for e, t, m in itertools.product(EPS, TAU, M)]
FIXED = (0.1, 0.99, 2)
NEIGHBORS = [(0.03, 0.99, 2), (0.2, 0.99, 2), (0.1, 0.95, 2), (0.1, 0.999, 2), (0.1, 0.99, 1), (0.1, 0.99, 3)]

_orig_score = bcm.score_hypotheses
_memo = {}


def _score_cached(observations, hyps=None):
    key = tuple(observations)
    if hyps is None and key in _memo:
        return _memo[key]
    s = _orig_score(key, hyps)
    if hyps is None:
        _memo[key] = s
    return s


bcm.score_hypotheses = _score_cached


def key_of(p):
    return (p.eps, p.tau, p.m)


def judge_condition(args):
    idx, rp_dir, q = args
    rng = random.Random(SEED_D + idx)
    rows = []
    for rep, obs in load(Path(rp_dir)).items():
        for _ in range(DRAWS if q > 0 else 1):
            o = obs if q == 0 else noisy_real(obs, q, rng)
            rows.append([bcm.attribute(o, p).verdict for p in GRID])
        _memo.clear()
    return Path(rp_dir).name, q, rows


def main():
    t0 = time.time()
    conds = conditions()
    assert len(conds) == 17
    tasks = [(i, str(d), q) for q in QS for i, d in enumerate(conds)]
    with Pool(10) as pool:
        judged = {(rp, q): rows for rp, q, rows in pool.imap_unordered(judge_condition, tasks)}

    from failsafe.oracle.real_ground_truth import BLOCK_CAUSE_TRUTH, BLOCK_CAUSE_TRUTH_V4
    truth_all = {**BLOCK_CAUSE_TRUTH, **BLOCK_CAUSE_TRUTH_V4}
    tot = {}
    for (rp, q), rows in judged.items():
        t = truth_all[rp]
        pos = t == "state_corruption"
        for gi, p in enumerate(GRID):
            c = Counter(r[gi] for r in rows)
            maj = c.most_common(1)[0][0]
            x = tot.setdefault(str(q), {}).setdefault(str(key_of(p)), Counter())
            x["n_pos" if pos else "n_neg"] += len(rows)
            x["fp"] += 0 if pos else c["state_corruption"]
            x["miss"] += (c["normal_policy"] + c["no_block"]) if pos else 0
            x["hit"] += c["state_corruption"] if pos else 0
            x["und"] += c["undetermined"]
            x["label_ok"] += 0 if pos else c[t]
            x["fp_cond"] += (not pos) and c["state_corruption"] > 0
            x["det_cond"] += pos and maj == "state_corruption"
            x["label_cond"] += (not pos) and maj == t
    tot = {q: {k: dict(v) | {"confident_errors": v["fp"] + v["miss"]} for k, v in d.items()} for q, d in tot.items()}
    z = tot["0.0"]
    ok = lambda k: z[str(k)]["fp_cond"] == 0 and z[str(k)]["det_cond"] == 5
    criterion = {str(k): ok(k) for k in NEIGHBORS}
    whole = {"fp0_points": sum(z[k]["fp_cond"] == 0 for k in z), "det5_points": sum(z[k]["det_cond"] == 5 for k in z),
             "both_points": sum(z[k]["fp_cond"] == 0 and z[k]["det_cond"] == 5 for k in z), "n_points": len(z)}

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "sensitivity.json").write_text(json.dumps({"grid": {"eps": EPS, "tau": TAU, "m": M}, "fixed": FIXED,
                                                      "draws": DRAWS, "seed": SEED_D, "totals": tot,
                                                      "neighbors_criterion": criterion,
                                                      "neighbors_met": all(criterion.values()), "whole_grid_q0": whole,
                                                      "elapsed_sec": round(time.time() - t0)},
                                                     indent=1, ensure_ascii=False), encoding="utf-8")
    L = ["# 6차 3번 — 파라미터 민감도 (자동 생성: scripts/evaluate_round6_sensitivity.py)", "",
         f"격자 ε {EPS} × τ {TAU} × m {M} (프로브별 A1). 고정점 {FIXED}. 잡음은 시행마다 {DRAWS}추첨(SEED_D={SEED_D}).", "",
         "## 사전 고정 기준 (q=0, 고정점의 이웃 6점: 오탐 조건 0 & 대상 5/5 탐지)", ""]
    for k, v in criterion.items():
        L.append(f"- {k}: {'유지' if v else '깨짐'} (오탐 조건 {z[k]['fp_cond']}, 탐지 조건 {z[k]['det_cond']}/5, "
                 f"비대상 표지 정답 조건 {z[k]['label_cond']}/12)")
    L += [f"- 결론: {'칼날 위가 아님(이웃 6점 모두 유지)' if all(criterion.values()) else '이웃 중 깨지는 점 있음 — 논문에 기록'}",
          f"- 격자 전체(q=0): 오탐 조건 0인 점 {whole['fp0_points']}/{whole['n_points']}, 대상 5/5 탐지 {whole['det5_points']}, 둘 다 {whole['both_points']}", ""]
    for q in ("0.0", "0.01", "0.05"):
        L += [f"## q = {q}", "",
              "| ε | τ | m | 오탐 조건 | 오탐 시행 | 확신 놓침 시행 | 확신 오류 합 | 탐지 조건 /5 | 탐지 시행 | 유보 | 비대상 표지 정답 조건 /12 |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
        for p in GRID:
            k = str(key_of(p))
            x = tot[q][k]
            mark = " ◀" if key_of(p) == FIXED else ""
            L.append(f"| {p.eps} | {p.tau} | {p.m}{mark} | {x['fp_cond']} | {x['fp']}/{x['n_neg']} | {x['miss']}/{x['n_pos']} "
                     f"| **{x['confident_errors']}** | {x['det_cond']} | {x['hit']}/{x['n_pos']} | {x['und']} | {x['label_cond']} |")
        L.append("")
    L.append(f"소요 {round(time.time() - t0)}초")
    (OUT / "sensitivity.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L[:16]))


if __name__ == "__main__":
    main()
