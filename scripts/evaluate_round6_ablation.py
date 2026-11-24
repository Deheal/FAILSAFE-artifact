import dataclasses
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

import failsafe.inference.policy_mapper as pm
from evaluate_round5_a import DRAWS, PARAMS, SEED_A, conditions, load, noisy_real
from failsafe.inference.block_cause import attribute
from failsafe.probe.catalog import ProbeObservation, _script
from failsafe.simulator.rp_model import ACCEPT

OUT = ROOT / "results" / "round6"
QS = [0.0, 0.01, 0.05]
CONFIRM = ("P_CORRUPT", "P_CORRUPT_CTR")
NON_DEFECT = ("P_UV0", "P_BEBS", "P_SC_DEC", "P_WRONG_CRED", "P_TAMPER_K", "P_REVOKE")
ALL8 = NON_DEFECT + CONFIRM

VARIANTS = {
    "F 전체": ((), False, False, False),
    "C 대조 실행 제거": ((), True, False, False),
    "K 확인 단계 제거": ((), False, True, False),
    "A 시행 전체 A1": ((), False, False, True),
    **{f"L-{p}": ((p,), False, False, False) for p in ALL8},
    "T 상태 불변 대조 제거": (("P_TAMPER_K", "P_REVOKE"), False, False, False),
    "KT 확인+상태 불변 대조 제거": (("P_TAMPER_K", "P_REVOKE"), False, True, False),
    "M-BB 무효 서명 대조 전부 제거(BE·BS)": (("P_TAMPER_K", "P_REVOKE", "P_CORRUPT_CTR"), False, True, False),
    "M-CTR 무효 서명 대조 전부 제거(카운터)": (("P_TAMPER_K", "P_REVOKE", "P_CORRUPT"), False, True, False),
}

_ORIG_PREDICT = pm._predict
_NO_CONFIRM = [False]


def _predict_maybe_truncated(key, dims, probe_id, victim):
    c, s = _ORIG_PREDICT(key, dims, probe_id, victim)
    if _NO_CONFIRM[0] and probe_id in CONFIRM:
        s = s[:len(_script(probe_id))]
    return c, s


pm._predict = _predict_maybe_truncated
PARAMS_A = dataclasses.replace(PARAMS, per_probe_a1=False)


def apply_variant(obs, spec):
    drop, no_ctrl, no_confirm, _ = spec
    out = []
    for o in obs:
        if o.probe_id in drop:
            continue
        ctrl = tuple(ACCEPT for _ in o.control_symbols) if no_ctrl else o.control_symbols
        syms = o.symbols[:len(_script(o.probe_id))] if (no_confirm and o.probe_id in CONFIRM) else o.symbols
        out.append(ProbeObservation(o.probe_id, ctrl, syms, o.victim))
    return out


def judge_all(obs):
    v = {}
    for name, spec in VARIANTS.items():
        _NO_CONFIRM[0] = spec[2]
        v[name] = attribute(apply_variant(obs, spec), PARAMS_A if spec[3] else PARAMS).verdict
    _NO_CONFIRM[0] = False
    return v


def judge_condition(args):
    idx, rp_dir, q = args
    rng = random.Random(SEED_A + idx)
    rows = []
    for rep, obs in load(Path(rp_dir)).items():
        for draw in range(DRAWS if q > 0 else 1):
            o = obs if q == 0 else noisy_real(obs, q, rng)
            rows.append(judge_all(o))
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
    res, tot = {}, {}
    for (rp, q), rows in judged.items():
        t = truth_all[rp]
        pos = t == "state_corruption"
        for name in VARIANTS:
            c = Counter(r[name] for r in rows)
            maj = c.most_common(1)[0][0]
            res.setdefault(str(q), {}).setdefault(name, {})[rp] = {"truth": t, "dist": dict(c), "majority": maj}
            x = tot.setdefault(str(q), {}).setdefault(name, Counter())
            x["n_pos" if pos else "n_neg"] += len(rows)
            x["fp"] += 0 if pos else c["state_corruption"]
            x["miss"] += (c["normal_policy"] + c["no_block"]) if pos else 0
            x["hit"] += c["state_corruption"] if pos else 0
            x["und"] += c["undetermined"]
            x["label_ok"] += 0 if pos else c[t]
            x["fp_cond"] += (not pos) and c["state_corruption"] > 0
            x["miss_cond"] += pos and (c["normal_policy"] + c["no_block"]) > 0
            x["det_cond"] += pos and maj == "state_corruption"
            x["label_cond"] += (not pos) and maj == t
    tot = {q: {n: dict(v) | {"confident_errors": v["fp"] + v["miss"]} for n, v in d.items()} for q, d in tot.items()}

    a = json.loads((ROOT / "results" / "round5_a" / "summary.json").read_text(encoding="utf-8"))["totals"]
    check = {q: (tot[q]["F 전체"]["fp"], tot[q]["F 전체"]["miss"], tot[q]["F 전체"]["und"]) ==
             (a[q]["FAILSAFE"]["fp_trials"], a[q]["FAILSAFE"]["miss_trials"], a[q]["FAILSAFE"]["undetermined_trials"])
             for q in ("0.0", "0.01", "0.05")}

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "ablation.json").write_text(json.dumps({"params": PARAMS.__dict__, "seed": SEED_A, "draws": DRAWS,
                                                   "variants": {k: {"drop": list(v[0]), "no_control": v[1], "no_confirm": v[2],
                                                                    "whole_trial_a1": v[3]} for k, v in VARIANTS.items()},
                                                   "totals": tot, "per_condition": res, "check_vs_round5a": check,
                                                   "elapsed_sec": round(time.time() - t0)},
                                                  indent=1, ensure_ascii=False), encoding="utf-8")
    L = ["# 6차 1번 — 구성요소 제거 (자동 생성: scripts/evaluate_round6_ablation.py)", "",
         f"엔진 v2.2 불변. 17개 조건(비대상 12, 대상 5) × 30시행, 잡음은 5차 A와 같은 난수열(DRAWS={DRAWS}). "
         f"F와 5차 A 일치 점검: {check}", ""]
    for q in ("0.0", "0.01", "0.05"):
        L += [f"## q = {q}", "",
              "| 변형 | 오탐 조건 /12 | 오탐 시행 | 확신 놓침 조건 /5 | 확신 놓침 시행 | 확신 오류 합 | 탐지 조건 /5 | 탐지 시행 | 유보 시행 | 비대상 표지 정답 조건 /12 |",
              "|---|---|---|---|---|---|---|---|---|---|"]
        for n in VARIANTS:
            x = tot[q][n]
            L.append(f"| {n} | {x['fp_cond']} | {x['fp']}/{x['n_neg']} | {x['miss_cond']} | {x['miss']}/{x['n_pos']} "
                     f"| **{x['confident_errors']}** | {x['det_cond']} | {x['hit']}/{x['n_pos']} | {x['und']} | {x['label_cond']} |")
        L.append("")
    L += ["## q = 0 조건별 다수 판정 (F와 다른 것만)", ""]
    base = res["0.0"]["F 전체"]
    for n in VARIANTS:
        diff = {rp: f"{base[rp]['majority']}→{c['majority']} {c['dist']}" for rp, c in res["0.0"][n].items()
                if c["dist"] != base[rp]["dist"]}
        if diff:
            L.append(f"- **{n}**: " + "; ".join(f"{rp}: {d}" for rp, d in diff.items()))
    L += ["", f"소요 {round(time.time() - t0)}초"]
    (OUT / "ablation.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
