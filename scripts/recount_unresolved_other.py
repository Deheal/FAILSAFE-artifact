import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from evaluate_round5_a import PARAMS, load
from failsafe.inference.block_cause import attribute

SETS = ["results/round5_b/q0.01", "results/round5_b/q0.05", "results/round7/obs", "results/round7b/obs",
        "results/round8/t3", "results/round9"]


def label(bc):
    return "unresolved_block" if (bc.verdict == "normal_policy" and bc.note == "unmodeled_policy") else bc.verdict


out = {}
for s in SETS:
    for d in sorted((ROOT / s).iterdir()):
        if not (d / "observations.jsonl").exists() or "smoke" in d.name or d.name == "polcheck":
            continue
        c = Counter(label(attribute(o, PARAMS)) for o in load(d).values())
        out[f"{s}/{d.name}"] = dict(c)
        print(s, d.name, dict(c))
(ROOT / "results" / "recount_unresolved" / "other.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
