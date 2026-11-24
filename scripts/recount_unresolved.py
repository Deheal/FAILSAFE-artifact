import json
import random
import sys
from collections import Counter, defaultdict
from multiprocessing import Pool
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_round5_a import DRAWS, PARAMS, SEED_A, conditions, load, noisy_real
from failsafe.inference.block_cause import attribute

OUT = ROOT / "results" / "recount_unresolved"


def label(bc):
    if bc.verdict == "normal_policy" and bc.note == "unmodeled_policy":
        return "unresolved_block"
    return bc.verdict


def judge(args):
    idx, rp_dir, q = args
    rng = random.Random(SEED_A + idx)
    c = Counter()
    for rep, obs in load(Path(rp_dir)).items():
        for _ in range(DRAWS if q > 0 else 1):
            o = obs if q == 0 else noisy_real(obs, q, rng)
            c[label(attribute(o, PARAMS))] += 1
    return Path(rp_dir).name, q, dict(c)


def main():
    conds = conditions()
    jobs = [(i, str(d), q) for q in (0.0, 0.01, 0.05) for i, d in enumerate(conds)]
    with Pool() as pool:
        res = pool.map(judge, jobs)
    out = defaultdict(dict)
    for name, q, c in res:
        out[str(q)][name] = c
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    for q in ("0.0", "0.01", "0.05"):
        tot = Counter()
        for name, c in sorted(out[q].items()):
            tot.update(c)
            if c.get("unresolved_block") or q == "0.0":
                print(q, name, c)
        print("TOTAL", q, dict(tot))


if __name__ == "__main__":
    main()
