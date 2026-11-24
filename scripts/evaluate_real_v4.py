import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from failsafe.inference.baselines import baseline_q2
from failsafe.inference.block_cause import attribute
from failsafe.inference.policy_mapper import EngineParams
from failsafe.probe import PROBE_IDS
from failsafe.probe.catalog import ProbeObservation
from failsafe.simulator.attribution import VICTIMS

PARAMS = EngineParams(eps=0.1, tau=0.99, m=2, per_probe_a1=True)
VICTIM_BY_NAME = {v.name: v for v in VICTIMS}
REAL = ROOT / "results" / "real_v4"
BASELINES = ["v2 규칙", "복구만", "단순 재시도", "단일 응답"]


def load(rp_dir):
    reps = defaultdict(dict)
    for line in (rp_dir / "observations.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        reps[r["rep"]][r["probe_id"]] = ProbeObservation(
            r["probe_id"], tuple(r["control_symbols"]), tuple(r["symbols"]), VICTIM_BY_NAME[r["victim"]])
    return {rep: [obs[p] for p in PROBE_IDS if p in obs] for rep, obs in sorted(reps.items())}


def label(bc):
    extra = bc.reason or bc.note
    return bc.verdict + (f"({extra})" if extra else "")


def judge_all():
    out = {}
    for rp_dir in sorted(d for d in REAL.iterdir() if (d / "observations.jsonl").exists()):
        reps = load(rp_dir)
        rows = []
        for rep, obs in reps.items():
            bc = attribute(obs, PARAMS)
            rows.append({"rep": rep, "n_probes": len(obs), "block_cause": label(bc), "verdict": bc.verdict,
                         "defect_presence": bc.policy_map.q2, "baselines": baseline_q2(obs),
                         "symbols": {o.probe_id: "/".join(s[0] for s in o.symbols) for o in obs}})
        out[rp_dir.name] = rows
    return out


def q3_verdict(defect_counter):
    keys = set(defect_counter)
    if keys == {"state_corruption"}:
        return "state_corruption"
    if keys <= {"no_block", "normal_policy", "undetermined"}:
        return "undetermined"
    return "mixed"


def evaluate(judged):
    from failsafe.oracle.real_ground_truth import (BLOCK_CAUSE_PREDICTED_V4, BLOCK_CAUSE_TRUTH_V4,
                                                   GROUND_TRUTH, Q3_PREDICTED_V4)
    res = {}
    for rp, rows in judged.items():
        truth = BLOCK_CAUSE_TRUTH_V4[rp]
        verdicts = Counter(r["block_cause"] for r in rows)
        plain = Counter(r["verdict"] for r in rows)
        defect = Counter(r["defect_presence"] for r in rows)
        n = len(rows)
        res[rp] = {
            "n": n, "truth": truth, "predicted": BLOCK_CAUSE_PREDICTED_V4[rp], "block_cause": dict(verdicts),
            "correct": plain[truth],
            "false_corruption": 0 if truth == "state_corruption" else plain["state_corruption"],
            "confident_miss": (plain["normal_policy"] + plain["no_block"]) if truth == "state_corruption" else 0,
            "undetermined": plain["undetermined"],
            "matches_prediction": verdicts.get(BLOCK_CAUSE_PREDICTED_V4[rp], 0),
            "q3_truth": GROUND_TRUTH[rp]["q2"],
            "q3_predicted": Q3_PREDICTED_V4[rp],
            "q3_observed": q3_verdict(defect),
            "defect_presence": dict(defect),
            "mutation": GROUND_TRUTH[rp].get("mutation", "(없음/원본)"),
            "library": GROUND_TRUTH[rp].get("library", GROUND_TRUTH[rp].get("instance", "")),
            "baselines": {b: dict(Counter(r["baselines"][b] for r in rows)) for b in BASELINES},
            "symbol_patterns": {p: dict(Counter(r["symbols"].get(p) for r in rows)) for p in PROBE_IDS},
        }
    return res


def main():
    judged = judge_all()
    res = evaluate(judged)
    (REAL / "summary.json").write_text(json.dumps({"params": PARAMS.__dict__, "conditions": res, "judged": judged},
                                                  indent=1, ensure_ascii=False), encoding="utf-8")
    lines = ["# 4차 실서버 평가 (자동 생성: scripts/evaluate_real_v4.py)", "",
             "엔진 v2.2 동결. 보고 단위=조건. ε=0.1 τ=0.99 m=2.", "",
             "## 차단 원인(Q2)", "",
             "| 조건 | 변이 | 정답 | 예상 | 판정 | 예상 일치 | 오탐 | 확신 놓침 | 유보 |",
             "|---|---|---|---|---|---|---|---|---|"]
    for rp, r in res.items():
        lines.append(f"| {rp} | {r['mutation']} | {r['truth']} | {r['predicted']} | {r['block_cause']} "
                     f"| {r['matches_prediction']}/{r['n']} | {r['false_corruption']} | {r['confident_miss']} "
                     f"| {r['undetermined']} |")
    neg = [r for r in res.values() if r["truth"] != "state_corruption"]
    pos = [r for r in res.values() if r["truth"] == "state_corruption"]
    lines += ["",
              f"- 오탐이 난 정상(원본) 조건: {sum(r['false_corruption'] > 0 for r in neg)} / {len(neg)} "
              f"(시행 {sum(r['false_corruption'] for r in neg)} / {sum(r['n'] for r in neg)})",
              f"- 모든 시행을 변조로 판정한 변이 조건: {sum(r['correct'] == r['n'] for r in pos)} / {len(pos)}",
              f"- 예상과 전부 일치한 조건: {sum(r['matches_prediction'] == r['n'] for r in res.values())} / {len(res)}",
              "",
              "## 결함 유무(Q3)", "",
              "| 조건 | 정답 | 예상 | 관측 요약 | 분포 |", "|---|---|---|---|---|"]
    for rp, r in res.items():
        ok = "✓" if r["q3_observed"] == r["q3_predicted"] else "✗"
        lines.append(f"| {rp} | {r['q3_truth']} | {r['q3_predicted']} | {r['q3_observed']} {ok} | {r['defect_presence']} |")
    lines += ["",
              "## W1 (선택 편향) — 변이 분석", "",
              "서로 다른 라이브러리에 동일 연산자 M_C(검증 전 카운터 저장)를 기계적으로 주입한 결과:", ""]
    for rp, r in res.items():
        if r["truth"] == "state_corruption":
            lines.append(f"- **{rp}** ({r['library']}): {r['mutation']} → "
                         f"state_corruption {r['correct']}/{r['n']}, store_counter_before_verify 확정")
    lines += ["",
              "## 비교군 (조건별 판정 분포)", "",
              "| 조건 | 정답 | " + " | ".join(BASELINES) + " |",
              "|---|---|" + "---|" * len(BASELINES)]
    for rp, r in res.items():
        lines.append(f"| {rp} | {r['truth']} | " + " | ".join(str(r["baselines"][b]) for b in BASELINES) + " |")
    (REAL / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
