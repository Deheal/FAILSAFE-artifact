import json
import random
import sys
from collections import Counter
from multiprocessing import Pool
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_round5_a import DRAWS, PARAMS, SEED_A, conditions, load, noisy_real
from failsafe.inference.baselines import episode_verdicts
from failsafe.inference.block_cause import attribute
from failsafe.simulator.attribution import NONE, NORMAL_POLICY, STATE_CORRUPTION, UNKNOWN

OUT = ROOT / "results" / "round7_r4"
B = ROOT / "results" / "round5_b"
METHODS = ["FAILSAFE", "R4 규칙", "v2 규칙"]


def r4_aggregate(per_probe):
    v = [x for x in per_probe.values() if x != "excluded"]
    if not v:
        return "undetermined"
    if STATE_CORRUPTION in v:
        return "state_corruption"
    if UNKNOWN in v:
        return "undetermined"
    if NORMAL_POLICY in v:
        return "normal_policy"
    assert all(x == NONE for x in v), v
    return "no_block"


def v2_aggregate(per_probe):
    r = r4_aggregate(per_probe)
    return "normal_policy" if r == "no_block" else r


def verdicts(obs):
    ep = episode_verdicts(obs)["v2 규칙"]
    return {"FAILSAFE": attribute(obs, PARAMS).verdict, "R4 규칙": r4_aggregate(ep), "v2 규칙": v2_aggregate(ep)}


def judge_condition(args):
    idx, rp_dir, q = args
    rng = random.Random(SEED_A + idx)
    rows = []
    for rep, obs in load(Path(rp_dir)).items():
        for _ in range(DRAWS if q > 0 else 1):
            o = obs if q == 0 else noisy_real(obs, q, rng)
            rows.append(verdicts(o))
    return Path(rp_dir).name, q, rows


def coarse(t):
    return t.split("(")[0]


def score(vs, truth):
    c = Counter(vs)
    t = coarse(truth)
    pos = t == "state_corruption"
    return {"n": len(vs), "dist": dict(c),
            "fp": 0 if pos else c["state_corruption"],
            "miss": (c["normal_policy"] + c["no_block"]) if pos else 0,
            "hit": c["state_corruption"] if pos else None,
            "und": c["undetermined"],
            "label_ok": None if pos else c[t]}


def totals(per_cond):
    out = {}
    for m in METHODS:
        neg = {k: v[m] for k, v in per_cond.items() if coarse(v["truth"]) != "state_corruption"}
        pos = {k: v[m] for k, v in per_cond.items() if coarse(v["truth"]) == "state_corruption"}
        out[m] = {"fp": sum(x["fp"] for x in neg.values()), "neg_n": sum(x["n"] for x in neg.values()),
                  "miss": sum(x["miss"] for x in pos.values()), "pos_n": sum(x["n"] for x in pos.values()),
                  "hit": sum(x["hit"] for x in pos.values()), "und": sum(x["und"] for x in {**neg, **pos}.values()),
                  "label_ok": sum(x["label_ok"] for x in neg.values()),
                  "pos_cond_detected_all": sum(x["hit"] == x["n"] for x in pos.values()),
                  "pos_cond_detected_majority": sum(x["hit"] * 2 > x["n"] for x in pos.values()),
                  "neg_cond_label_majority": sum(x["label_ok"] * 2 > x["n"] for x in neg.values()),
                  "n_pos_cond": len(pos), "n_neg_cond": len(neg)}
        out[m]["conf_err"] = out[m]["fp"] + out[m]["miss"]
    return out


def main():
    from failsafe.oracle.real_ground_truth import BLOCK_CAUSE_TRUTH, BLOCK_CAUSE_TRUTH_V4
    truth_all = {**BLOCK_CAUSE_TRUTH, **BLOCK_CAUSE_TRUTH_V4}
    conds = conditions()
    tasks = [(i, str(d), q) for q in (0.0, 0.01, 0.05) for i, d in enumerate(conds)]
    with Pool() as pool:
        judged = list(pool.imap_unordered(judge_condition, tasks))
    res = {"replay": {}, "fault": {}}
    for rp, q, rows in judged:
        res["replay"].setdefault(str(q), {})[rp] = {"truth": truth_all[rp],
                                                   **{m: score([r[m] for r in rows], truth_all[rp]) for m in METHODS}}
    for q in ("0.01", "0.05"):
        for d in sorted((B / f"q{q}").iterdir()):
            if (d / "observations.jsonl").exists():
                rows = [verdicts(o) for o in load(d).values()]
                res["fault"].setdefault(q, {})[d.name] = {"truth": truth_all[d.name],
                                                         **{m: score([r[m] for r in rows], truth_all[d.name]) for m in METHODS}}
    tot = {kind: {q: totals(pc) for q, pc in res[kind].items()} for kind in res}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.json").write_text(json.dumps({"per_condition": res, "totals": tot}, ensure_ascii=False, indent=1),
                                      encoding="utf-8")

    L = ["# 7차 1절 — R4(같은 범주 규칙) 재적용 결과", "", "계획: docs/round7_plan.md 1절 (커밋 e3f8c60, 실행 전)", ""]
    for kind, title in (("replay", "실서버 17개 조건 / 기호 반전 재생"), ("fault", "5차 B 실서버 실패 주입 6개 조건")):
        L += [f"## {title}", "", "| q | 방식 | 오탐 | 확신 놓침 | 탐지 | 유보 | 비대상 표지 일치 | 대상 조건 전부 탐지 | 비대상 조건 과반 표지 일치 |",
              "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
        for q in sorted(tot[kind]):
            for m in METHODS:
                t = tot[kind][q][m]
                L.append(f"| {q} | {m} | {t['fp']}/{t['neg_n']} | {t['miss']}/{t['pos_n']} | {t['hit']}/{t['pos_n']} | "
                         f"{t['und']}/{t['neg_n'] + t['pos_n']} | {t['label_ok']}/{t['neg_n']} | "
                         f"{t['pos_cond_detected_all']}/{t['n_pos_cond']} | {t['neg_cond_label_majority']}/{t['n_neg_cond']} |")
        L.append("")
    L += ["## 잡음 없는 실서버 조건별 분포", "", "| 조건 | 정답 | FAILSAFE | R4 규칙 |", "|---|---|---|---|"]
    for rp, v in sorted(res["replay"]["0.0"].items()):
        L.append(f"| {rp} | {v['truth']} | {v['FAILSAFE']['dist']} | {v['R4 규칙']['dist']} |")
    (OUT / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
