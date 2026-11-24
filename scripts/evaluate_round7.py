import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_real_v4 import label, load
from evaluate_round7_r4 import r4_aggregate
from failsafe.inference.baselines import baseline_q2, episode_verdicts
from failsafe.inference.block_cause import attribute
from failsafe.inference.policy_mapper import EngineParams

PARAMS = EngineParams(eps=0.1, tau=0.99, m=2, per_probe_a1=True)
SET = sys.argv[2] if len(sys.argv) > 2 else "7"
R7 = ROOT / "results" / f"round{SET}"
METHODS = ["FAILSAFE", "R4 규칙", "v2 규칙", "복구만", "단순 재시도", "단일 응답"]


def judge():
    out = {}
    for d in sorted(p for p in (R7 / "obs").iterdir() if (p / "observations.jsonl").exists()):
        rows = []
        for rep, obs in load(d).items():
            bc = attribute(obs, PARAMS)
            base = baseline_q2(obs)
            rows.append({"rep": rep, "n_probes": len(obs), "block_cause": label(bc),
                         "FAILSAFE": bc.verdict, "defect_presence": bc.policy_map.q2,
                         "R4 규칙": r4_aggregate(episode_verdicts(obs)["v2 규칙"]),
                         **{m: base[m] for m in ("v2 규칙", "복구만", "단순 재시도", "단일 응답")},
                         "symbols": {o.probe_id: "/".join(s[0] for s in o.symbols) for o in obs}})
        out[d.name] = rows
    body = json.dumps(out, ensure_ascii=False, indent=1)
    (R7 / "verdicts.json").write_text(body, encoding="utf-8")
    print("verdicts.json sha256", hashlib.sha256(body.encode()).hexdigest())
    for code, rows in out.items():
        print(code, len(rows), "trials; probes/trial", Counter(r["n_probes"] for r in rows))


def evaluate():
    from failsafe.oracle.real_ground_truth import BLOCK_CAUSE_TRUTH_V7, BLOCK_CAUSE_TRUTH_V7B
    BLOCK_CAUSE_TRUTH_V7 = BLOCK_CAUSE_TRUTH_V7 if SET == "7" else BLOCK_CAUSE_TRUTH_V7B
    verdicts = json.loads((R7 / "verdicts.json").read_text(encoding="utf-8"))
    mapping = json.loads((R7 / "mapping.json").read_text(encoding="utf-8"))["mapping"]
    per = {}
    for code, rows in verdicts.items():
        cond = mapping[code]
        truth = BLOCK_CAUSE_TRUTH_V7[cond]
        pos = truth == "state_corruption"
        r = {"code": code, "truth": truth, "n": len(rows),
             "block_cause": dict(Counter(x["block_cause"] for x in rows)),
             "defect_presence": dict(Counter(x["defect_presence"] for x in rows))}
        for m in METHODS:
            c = Counter(x[m] for x in rows)
            r[m] = {"dist": dict(c), "fp": 0 if pos else c["state_corruption"],
                    "miss": (c["normal_policy"] + c["no_block"]) if pos else 0,
                    "hit": c["state_corruption"] if pos else None, "und": c["undetermined"],
                    "label_ok": None if pos else c[truth]}
        per[cond] = r
    pos = [c for c in per if per[c]["truth"] == "state_corruption"]
    neg = [c for c in per if c not in pos]
    crit = {"a_detect_majority": all(per[c]["FAILSAFE"]["hit"] * 2 > per[c]["n"] for c in pos),
            "b_no_false_corruption": sum(per[c]["FAILSAFE"]["fp"] for c in neg) == 0,
            "c_no_confident_miss": sum(per[c]["FAILSAFE"]["miss"] for c in pos) == 0}
    crit["passed"] = all(crit.values())
    summary = {"per_condition": per, "criteria": crit}
    (R7 / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")

    L = ["# 7차 2절 — 미사용 RP 블라인드 독립 검증 결과", "",
         "계획: docs/round7_plan.md 2절. 판정 파일을 커밋한 뒤 대응표를 공개하고 정답과 결합했다.", "",
         "| 조건 | 코드 | 정답 | FAILSAFE 차단 원인 | 결함 유무 출력 | R4 규칙 |", "|---|---|---|---|---|---|"]
    for cond, r in per.items():
        L.append(f"| {cond} | {r['code']} | {r['truth']} | {r['block_cause']} | {r['defect_presence']} | {r['R4 규칙']['dist']} |")
    L += ["", "## 방식별 합계", "", "| 방식 | 오탐(시행) | 확신 놓침 | 대상 탐지 | 유보 | 비대상 표지 일치 |", "|---|---:|---:|---:|---:|---:|"]
    for m in METHODS:
        fp = sum(per[c][m]["fp"] for c in neg); nn = sum(per[c]["n"] for c in neg)
        ms = sum(per[c][m]["miss"] for c in pos); pn = sum(per[c]["n"] for c in pos)
        hit = sum(per[c][m]["hit"] for c in pos); und = sum(per[c][m]["und"] for c in per)
        lab = sum(per[c][m]["label_ok"] for c in neg)
        L.append(f"| {m} | {fp}/{nn} | {ms}/{pn} | {hit}/{pn} | {und}/{nn + pn} | {lab}/{nn} |")
    L += ["", "## 사전 성공 기준(2.6절)", "", json.dumps(crit, ensure_ascii=False)]
    (R7 / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    {"judge": judge, "evaluate": evaluate}[sys.argv[1]]()
