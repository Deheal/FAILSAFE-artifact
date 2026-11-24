import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT / "src", ROOT / "scripts", ROOT / "scripts" / "round8"):
    sys.path.insert(0, str(p))

import failsafe.probe.catalog as C
from evaluate_round7_r4 import r4_aggregate
from failsafe.inference.baselines import episode_verdicts
from failsafe.inference.block_cause import attribute
from failsafe.inference.hypotheses import policy_from_hypothesis
from failsafe.probe import PROBE_IDS
from failsafe.probe.catalog import ProbeObservation, Step, _request, _script
from failsafe.probe.targets import SimSession
from failsafe.simulator.attribution import DEVICE_BOUND
from failsafe.simulator.rp_model import ACCEPT, REJECT, Request
from t3_sim import CONDS, PARAMS

W = 120.0
OUT = ROOT / "results" / "round8" / "t1_sim"


class Outages:
    def __init__(self, rng, D, f, horizon=4500.0):
        self.win = []
        if D <= 0 or f <= 0:
            return
        G = D * (1 - f) / f
        t = -rng.expovariate(1 / G) if G > 0 else 0
        while t < horizon:
            t += rng.expovariate(1 / G)
            self.win.append((t, t + D))
            t += D

    def down(self, t):
        return any(a <= t < b for a, b in self.win)


class Sess:
    def __init__(self, policy, out, offset):
        self.s = SimSession(policy, DEVICE_BOUND)
        self.out, self.off = out, offset

    def next_counter(self):
        return self.s.next_counter()

    def send(self, req, at):
        if self.out.down(self.off + at):
            return REJECT
        return self.s.send(req, at)


def _times(steps):
    t, ts = 0.0, []
    for st in steps:
        t += W if st.after_wait else C.STEP_SEC
        ts.append(t)
    return ts, t


def _confirm(probe_id, symbols, session, t):
    if probe_id == "P_CORRUPT" and symbols[1] == REJECT and symbols[-1] == REJECT:
        symbols.append(session.send(_request(Step("valid", flags="tampered"), session, DEVICE_BOUND), at=t))
    if probe_id == "P_CORRUPT_CTR" and symbols[1] == REJECT and symbols[-1] == REJECT:
        symbols.append(session.send(Request("valid", be=False, bs=False, uv=True, counter=C.HIGH_COUNTER + 1), at=t))


def probe(policy, out, probe_id, mode, start):
    steps = _script(probe_id)
    normal = [s for s in steps if not s.abnormal]
    if mode in ("seq", "none"):
        cs = Sess(policy, out, start)
        cts, cend = _times(normal)
        ctrl = [cs.send(_request(st, cs, DEVICE_BOUND), at=t) for st, t in zip(normal, cts)]
        ps = Sess(policy, out, start + cend + 1.0)
        pts, pend = _times(steps)
        syms = [ps.send(_request(st, ps, DEVICE_BOUND), at=t) for st, t in zip(steps, pts)]
        _confirm(probe_id, syms, ps, pend)
        if mode == "none":
            ctrl = [ACCEPT] * len(ctrl)
        return ProbeObservation(probe_id, tuple(ctrl), tuple(syms), DEVICE_BOUND)
    cs, ps = Sess(policy, out, start), Sess(policy, out, start)
    pts, pend = _times(steps)
    ctrl, syms, j = [], [], 0
    for st, t in zip(steps, pts):
        if not st.abnormal:
            ctrl.append(cs.send(_request(normal[j], cs, DEVICE_BOUND), at=t - 0.5))
            j += 1
        syms.append(ps.send(_request(st, ps, DEVICE_BOUND), at=t))
    _confirm(probe_id, syms, ps, pend)
    return ProbeObservation(probe_id, tuple(ctrl), tuple(syms), DEVICE_BOUND)


def run(trials=300, Ds=(10.0, 60.0, 180.0), f=0.05, seed=20261116):
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, (h, truth) in CONDS.items():
        pol = policy_from_hypothesis(h)
        for D in Ds:
            c = {m: Counter() for m in ("seq", "aligned", "none")}
            rng = random.Random(f"{seed}-{name}-{D}")
            for _ in range(trials):
                out = Outages(rng, D, f)
                starts = {p: rng.uniform(0, 3600) for p in PROBE_IDS}
                obs_seq = [probe(pol, out, p, "seq", starts[p]) for p in PROBE_IDS]
                obs_none = [ProbeObservation(o.probe_id, tuple([ACCEPT] * len(o.control_symbols)), o.symbols, o.victim)
                            for o in obs_seq]
                obs_al = [probe(pol, out, p, "aligned", starts[p]) for p in PROBE_IDS]
                for m, obs in (("seq", obs_seq), ("aligned", obs_al), ("none", obs_none)):
                    for arm, v in (("FS", attribute(obs, PARAMS).verdict),
                                   ("R4", r4_aggregate(episode_verdicts(obs)["v2 규칙"]))):
                        pos = truth == "state_corruption"
                        c[m][f"{arm}_fp"] += int(not pos and v == "state_corruption")
                        c[m][f"{arm}_miss"] += int(pos and v in ("normal_policy", "no_block"))
                        c[m][f"{arm}_hit"] += int(pos and v == "state_corruption")
                        c[m][f"{arm}_und"] += int(v == "undetermined")
                        c[m][f"{arm}_label_wrong"] += int(not pos and v in ("normal_policy", "no_block") and v != truth)
            for m in c:
                row = {"cond": name, "truth": truth, "D": D, "f": f, "mode": m, "n": trials, **dict(c[m])}
                rows.append(row)
                print(json.dumps(row, ensure_ascii=False), flush=True)
    (OUT / "sim.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    run()
