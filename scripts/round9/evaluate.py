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
CELLS = [("R1-fs2-improved", "round9", "state_corruption"), ("R2-orig-improved", "round9", "no_block"),
         ("R3-rep-base", "round9", "normal_policy"), ("R4-rep-improved", "round9", "normal_policy"),
         ("C3-fs2-L10", "round8/t3", "state_corruption"), ("C6-orig-L10", "round8/t3", "no_block")]
OUT = ROOT / "results" / "round9"


def main():
    per = {}
    for cell, sub, truth in CELLS:
        pos = truth == "state_corruption"
        c = Counter()
        for rep, obs in load(ROOT / "results" / sub / cell).items():
            seen = any(blocked(o.probe_id, o.symbols) for o in obs if o.probe_id in ("P_CORRUPT", "P_CORRUPT_CTR"))
            c["n"] += 1
            c["block_observed"] += int(seen)
            c["incomplete"] += int(len(obs) < 8)
            for arm, v in (("FS", attribute(obs, PARAMS).verdict),
                           ("R4", r4_aggregate(episode_verdicts(obs)["v2 규칙"]))):
                c[f"{arm}:{v}"] += 1
                c[f"{arm}_fp"] += int(not pos and v == "state_corruption")
                c[f"{arm}_miss"] += int(pos and v in ("normal_policy", "no_block"))
                c[f"{arm}_miss_observed"] += int(pos and seen and v in ("normal_policy", "no_block"))
                c[f"{arm}_conf_err"] += int((pos and v in ("normal_policy", "no_block"))
                                            or (not pos and v != "undetermined" and v != truth))
                c[f"{arm}_und"] += int(v == "undetermined")
        per[cell] = {"truth": truth, **dict(c)}
    g = lambda cell, k: per[cell].get(k, 0)
    crit = {
        "a_R1_miss_le6_and_rate_below_C3": g("R1-fs2-improved", "FS_miss") <= 6 and
            g("R1-fs2-improved", "FS_miss") / g("R1-fs2-improved", "n") < g("C3-fs2-L10", "FS_miss") / g("C3-fs2-L10", "n"),
        "b_FS_fp0_R2R3R4": sum(g(c, "FS_fp") for c in ("R2-orig-improved", "R3-rep-base", "R4-rep-improved")) == 0,
        "c_R4_conf_err_le_R3": g("R4-rep-improved", "FS_conf_err") <= g("R3-rep-base", "FS_conf_err"),
    }
    crit["all"] = all(crit.values())
    (OUT / "summary.json").write_text(json.dumps({"per_cell": per, "criteria": crit}, ensure_ascii=False, indent=1),
                                      encoding="utf-8")
    L = ["# 9차 채점 (사전 등록 docs/round9_plan.md)", "",
         "| 칸 | 정답 | 시행 | 차단 관측 | FS 판정 분포 | FS 확신 오류 | R4 판정 분포 | R4 확신 오류 |", "|---|---|---:|---:|---|---:|---|---:|"]
    for cell, r in per.items():
        fs = ", ".join(f"{k[3:]} {v}" for k, v in sorted(r.items()) if k.startswith("FS:"))
        r4 = ", ".join(f"{k[3:]} {v}" for k, v in sorted(r.items()) if k.startswith("R4:"))
        L.append(f"| {cell} | {r['truth']} | {r['n']} | {r['block_observed']} | {fs} | {r['FS_conf_err']} | {r4} | {r['R4_conf_err']} |")
    L += ["", f"사전 기준: {crit}"]
    (OUT / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()
