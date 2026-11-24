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
REAL = ROOT / "results" / "real_v3"
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


def evaluate(judged):
    from failsafe.oracle.real_ground_truth import BLOCK_CAUSE_PREDICTED, BLOCK_CAUSE_TRUTH, GROUND_TRUTH
    res = {}
    for rp, rows in judged.items():
        truth = BLOCK_CAUSE_TRUTH[rp]
        verdicts = Counter(r["block_cause"] for r in rows)
        plain = Counter(r["verdict"] for r in rows)
        n = len(rows)
        res[rp] = {
            "n": n, "truth": truth, "predicted": BLOCK_CAUSE_PREDICTED[rp], "block_cause": dict(verdicts),
            "correct": plain[truth],
            "false_corruption": 0 if truth == "state_corruption" else plain["state_corruption"],
            "confident_miss": plain["normal_policy"] + plain["no_block"] if truth == "state_corruption" else 0,
            "undetermined": plain["undetermined"],
            "matches_prediction": verdicts.get(BLOCK_CAUSE_PREDICTED[rp], 0),
            "defect_presence_v20": dict(Counter(r["defect_presence"] for r in rows)),
            "defect_q2_truth": GROUND_TRUTH[rp]["q2"],
            "baselines": {b: dict(Counter(r["baselines"][b] for r in rows)) for b in BASELINES},
            "symbol_patterns": {p: dict(Counter(r["symbols"].get(p) for r in rows)) for p in PROBE_IDS},
        }
    return res


def identical_observations(judged, a, b):
    if a not in judged or b not in judged:
        return None
    pa = {p: Counter(r["symbols"].get(p) for r in judged[a]) for p in PROBE_IDS}
    pb = {p: Counter(r["symbols"].get(p) for r in judged[b]) for p in PROBE_IDS}
    return {p: {"same": pa[p] == pb[p], a: dict(pa[p]), b: dict(pb[p])} for p in PROBE_IDS}


def main():
    judged = judge_all()
    res = evaluate(judged)
    same = identical_observations(judged, "vaultwarden-1.35.4-synced", "vaultwarden-1.35.5-synced")
    (REAL / "summary.json").write_text(json.dumps({"params": PARAMS.__dict__, "conditions": res,
                                                   "B_identical": same, "judged": judged},
                                                  indent=1, ensure_ascii=False), encoding="utf-8")
    lines = ["# 3차 실서버 평가 (자동 생성: scripts/evaluate_real_v3.py)", "",
             "| 조건 | 정답 | 예상 | 판정 | 예상 일치 | 오탐 | 확신 놓침 | 유보 |", "|---|---|---|---|---|---|---|---|"]
    for rp, r in res.items():
        lines.append(f"| {rp} | {r['truth']} | {r['predicted']} | {r['block_cause']} | {r['matches_prediction']}/{r['n']} "
                     f"| {r['false_corruption']} | {r['confident_miss']} | {r['undetermined']} |")
    neg = [r for r in res.values() if r["truth"] != "state_corruption"]
    pos = [r for r in res.values() if r["truth"] == "state_corruption"]
    lines += ["", f"- 오탐이 난 정상 조건: {sum(r['false_corruption'] > 0 for r in neg)} / {len(neg)} "
                  f"(시행 {sum(r['false_corruption'] for r in neg)} / {sum(r['n'] for r in neg)})",
              f"- 모든 시행을 변조로 판정한 결함 조건: {sum(r['correct'] == r['n'] for r in pos)} / {len(pos)}",
              f"- 예상과 전부 일치한 조건: {sum(r['matches_prediction'] == r['n'] for r in res.values())} / {len(res)}", ""]
    lines += ["## 비교군 (조건별 판정 분포)", "", "| 조건 | 정답 | " + " | ".join(BASELINES) + " |",
              "|---|---|" + "---|" * len(BASELINES)]
    for rp, r in res.items():
        lines.append(f"| {rp} | {r['truth']} | " + " | ".join(str(r["baselines"][b]) for b in BASELINES) + " |")
    if same:
        lines += ["", "## B 조건: 1.35.4-synced와 1.35.5-synced의 관측 동일성", "",
                  f"- 8개 프로브 중 기호 열 분포가 같은 프로브: {sum(v['same'] for v in same.values())} / {len(same)}"]
        for p, v in same.items():
            if not v["same"]:
                lines.append(f"  - {p}: 다름 {v}")
    (REAL / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
