import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_round5_a import load
from failsafe.inference.baselines import baseline_q2
from failsafe.inference.block_cause import attribute
from failsafe.inference.policy_mapper import EngineParams
from failsafe.probe.catalog import _script

PARAMS = EngineParams(eps=0.1, tau=0.99, m=2, per_probe_a1=True)
B = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results" / "round5_b"
QS = ["0.01", "0.05"]
METHODS = ["FAILSAFE", "v2 규칙", "복구만", "단순 재시도", "단일 응답"]


def judge(rp_dir):
    rows = {}
    for rep, obs in load(rp_dir).items():
        bc = attribute(obs, PARAMS)
        v = {"FAILSAFE": bc.verdict, "FAILSAFE_label": bc.verdict + (f"({bc.reason or bc.note})" if (bc.reason or bc.note) else "")}
        v.update(baseline_q2(obs))
        rows[rep] = v
    return rows


def diagnostics(rp_dir):
    d = Counter()
    for line in (rp_dir / "logs.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        d["probes"] += 1
        d["faults"] += r["n_fault"]
        d["probes_with_fault"] += r["n_fault"] > 0
        if any(e["symbol"] != "ACCEPT" for e in r["control"]):
            d["control_not_all_accept"] += 1
        n = len(_script(r["probe_id"]))
        if r["probe_id"] in ("P_CORRUPT", "P_CORRUPT_CTR") and len(r["probe"]) > n:
            d[f"extra_step:{r['probe_id']}"] += 1
    return dict(d)


def score(verdicts, truth):
    c = Counter(verdicts)
    pos = truth == "state_corruption"
    return {"n": len(verdicts), "dist": dict(c),
            "fp": 0 if pos else c["state_corruption"],
            "miss": (c["normal_policy"] + c["no_block"]) if pos else 0,
            "hit": c["state_corruption"] if pos else None,
            "undetermined": c["undetermined"]}


def main():
    judged, diag = {}, {}
    for q in QS:
        for rp_dir in sorted((B / f"q{q}").iterdir()):
            if (rp_dir / "observations.jsonl").exists():
                judged[(q, rp_dir.name)] = judge(rp_dir)
                diag[(q, rp_dir.name)] = diagnostics(rp_dir)

    from failsafe.oracle.real_ground_truth import BLOCK_CAUSE_TRUTH, BLOCK_CAUSE_TRUTH_V4
    truth_all = {**BLOCK_CAUSE_TRUTH, **BLOCK_CAUSE_TRUTH_V4}
    pred = json.loads((B / "prediction.json").read_text(encoding="utf-8"))["per_q"]

    res = {}
    for (q, rp), rows in judged.items():
        t = truth_all[rp]
        r = {"truth": t, "n": len(rows), "diagnostics": diag[(q, rp)]}
        for m in METHODS:
            r[m] = score([v[m] for v in rows.values()], t)
        r["FAILSAFE_labels"] = dict(Counter(v["FAILSAFE_label"] for v in rows.values()))
        paired = {p["rep"]: p for p in pred[q][rp]["paired_trials"]}
        for m in ("FAILSAFE", "v2 규칙"):
            same = sum(1 for rep, v in rows.items() if rep in paired and paired[rep][m] == v[m])
            changes = Counter(f"{paired[rep][m]}→{v[m]}" for rep, v in rows.items()
                              if rep in paired and paired[rep][m] != v[m])
            r[f"vs_paired:{m}"] = {"same": same, "n": len(rows), "changes": dict(changes),
                                   "predicted_dist": pred[q][rp][f"paired:{m}"]["dist"]}
        res.setdefault(q, {})[rp] = r

    tot = {}
    for q in QS:
        tot[q] = {}
        for m in METHODS:
            xs = list(res[q].values())
            tot[q][m] = {
                "fp_conditions": sum(x[m]["fp"] > 0 for x in xs), "fp": sum(x[m]["fp"] for x in xs),
                "miss_conditions": sum(x[m]["miss"] > 0 for x in xs), "miss": sum(x[m]["miss"] for x in xs),
                "hit": sum(x[m]["hit"] or 0 for x in xs),
                "pos_trials": sum(x["n"] for x in xs if x["truth"] == "state_corruption"),
                "neg_trials": sum(x["n"] for x in xs if x["truth"] != "state_corruption"),
                "undetermined": sum(x[m]["undetermined"] for x in xs)}
            tot[q][m]["confident_errors"] = tot[q][m]["fp"] + tot[q][m]["miss"]
    rule = {q: tot[q]["FAILSAFE"]["confident_errors"] < tot[q]["v2 규칙"]["confident_errors"] for q in QS}

    (B / "summary.json").write_text(json.dumps({"params": PARAMS.__dict__, "per_q": res, "totals": tot,
                                                "decision_rule": {"per_q": rule, "met": all(rule.values())},
                                                "judged": {f"{q}|{rp}": v for (q, rp), v in judged.items()}},
                                               indent=1, ensure_ascii=False), encoding="utf-8")
    L = ["# 5차 실험 B — 실서버 일시 실패 주입 (자동 생성: scripts/evaluate_round5_b.py)", "",
         "엔진 v2.2 동결. 정상 로그인을 확률 q로 서명 무효 요청으로 바꿔 실제 서버에 전송. 조건당 30시행.", ""]
    for q in QS:
        L += [f"## q = {q}", "",
              "| 방식 | 오탐 (조건/시행) | 확신 놓침 (조건/시행) | 확신 오류 합 | 상태 오염 탐지 | 유보 |", "|---|---|---|---|---|---|"]
        for m in METHODS:
            x = tot[q][m]
            L.append(f"| {m} | {x['fp_conditions']} / {x['fp']} (of {x['neg_trials']}) | {x['miss_conditions']} / {x['miss']} "
                     f"(of {x['pos_trials']}) | **{x['confident_errors']}** | {x['hit']}/{x['pos_trials']} | {x['undetermined']} |")
        L += ["", "| 조건 | 정답 | 주입 수 | 대조 실행 실패 프로브 | 확인 단계 수행 | FAILSAFE 실측 | 짝 예상 | 일치 | v2 규칙 실측 | 짝 예상 | 일치 |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
        for rp, r in res[q].items():
            d = r["diagnostics"]
            ex = ", ".join(f"{k.split(':')[1]} {v}" for k, v in d.items() if k.startswith("extra_step")) or "0"
            f, v = r["vs_paired:FAILSAFE"], r["vs_paired:v2 규칙"]
            L.append(f"| {rp} | {r['truth']} | {d['faults']} ({d['probes_with_fault']}프로브) | {d.get('control_not_all_accept', 0)} "
                     f"| {ex} | {r['FAILSAFE']['dist']} | {f['predicted_dist']} | {f['same']}/{f['n']} "
                     f"| {r['v2 규칙']['dist']} | {v['predicted_dist']} | {v['same']}/{v['n']} |")
        L += ["", "짝 예상과 달라진 시행 (예상→실측):", ""]
        for rp, r in res[q].items():
            for m in ("FAILSAFE", "v2 규칙"):
                ch = r[f"vs_paired:{m}"]["changes"]
                if ch:
                    L.append(f"- {rp} / {m}: {ch}")
        L.append("")
    L += ["## 사전 고정 판정 규칙 (round5_plan.md 4.4절, 5.5절)", ""]
    for q in QS:
        L.append(f"- q={q}: FAILSAFE 확신 오류 {tot[q]['FAILSAFE']['confident_errors']} vs v2 규칙 "
                 f"{tot[q]['v2 규칙']['confident_errors']} → {'충족' if rule[q] else '미충족'}")
    L.append(f"- 결론: {'B에서도 우위' if all(rule.values()) else 'B에서는 우위 미확인 (그대로 보고)'}")
    (B / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
