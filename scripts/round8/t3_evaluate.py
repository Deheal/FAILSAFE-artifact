import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT / "src", ROOT / "scripts"):
    sys.path.insert(0, str(p))

from evaluate_real_v4 import load
from evaluate_round7_r4 import r4_aggregate
from failsafe.inference.baselines import episode_verdicts
from failsafe.inference.block_cause import attribute, blocked
from failsafe.inference.policy_mapper import EngineParams

PARAMS = EngineParams(eps=0.1, tau=0.99, m=2, per_probe_a1=True)
T3 = ROOT / "results" / "round8" / "t3"
CELLS = {"C1-fs2-L0": "state_corruption", "C2-fs2-L5": "state_corruption", "C3-fs2-L10": "state_corruption",
         "C4-fs2-L10-s30": "state_corruption", "C5-orig-L5": "no_block", "C6-orig-L10": "no_block"}


def main():
    per = {}
    for cell, truth in CELLS.items():
        d = T3 / cell
        if not (d / "observations.jsonl").exists():
            continue
        pos = truth == "state_corruption"
        c = Counter()
        for rep, obs in load(d).items():
            if len(obs) < 8:
                c["incomplete"] += 1
            seen = any(blocked(o.probe_id, o.symbols) for o in obs if o.probe_id in ("P_CORRUPT", "P_CORRUPT_CTR"))
            c["n"] += 1
            c["block_observed"] += int(seen)
            for arm, v in (("FS", attribute(obs, PARAMS).verdict),
                           ("R4", r4_aggregate(episode_verdicts(obs)["v2 규칙"]))):
                c[f"{arm}:{v}"] += 1
                c[f"{arm}_fp"] += int(not pos and v == "state_corruption")
                c[f"{arm}_miss"] += int(pos and v in ("normal_policy", "no_block"))
                c[f"{arm}_miss_observed"] += int(pos and seen and v in ("normal_policy", "no_block"))
                c[f"{arm}_hit"] += int(pos and v == "state_corruption")
                c[f"{arm}_und"] += int(v == "undetermined")
        per[cell] = {"truth": truth, **dict(c)}
    g = lambda cell, k: per.get(cell, {}).get(k, 0)
    crit = {
        "a_FS_miss_lt_R4_C2C3": (g("C2-fs2-L5", "FS_miss") + g("C3-fs2-L10", "FS_miss"))
                                < (g("C2-fs2-L5", "R4_miss") + g("C3-fs2-L10", "R4_miss")),
        "b_FS_fp0_C5C6": g("C5-orig-L5", "FS_fp") + g("C6-orig-L10", "FS_fp") == 0,
        "c_C4_le_half_C3": (g("C4-fs2-L10-s30", "FS_miss") + g("C4-fs2-L10-s30", "FS_fp")) * 2
                           <= (g("C3-fs2-L10", "FS_miss") + g("C3-fs2-L10", "FS_fp")),
    }
    crit["all"] = all(crit.values())
    (T3 / "summary.json").write_text(json.dumps({"per_cell": per, "criteria": crit}, ensure_ascii=False, indent=1),
                                     encoding="utf-8")
    L = ["# T3 실서버 결과: 읽기 복제본 지연 (사전 등록 docs/round8_t3_prereg.md)", "",
         "| 칸 | 정답 | 시행 | 차단 관측 | FS 탐지 | FS 놓침(관측된 차단) | FS 오탐 | FS 유보 | R4 탐지 | R4 놓침(관측된 차단) | R4 오탐 | R4 유보 |",
         "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for cell, r in per.items():
        L.append(f"| {cell} | {r['truth']} | {r.get('n',0)} | {r.get('block_observed',0)} | {r.get('FS_hit',0)} | "
                 f"{r.get('FS_miss',0)}({r.get('FS_miss_observed',0)}) | {r.get('FS_fp',0)} | {r.get('FS_und',0)} | "
                 f"{r.get('R4_hit',0)} | {r.get('R4_miss',0)}({r.get('R4_miss_observed',0)}) | {r.get('R4_fp',0)} | {r.get('R4_und',0)} |")
    L += ["", f"사전 기준: {crit}"]
    (T3 / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
