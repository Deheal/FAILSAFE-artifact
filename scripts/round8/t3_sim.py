import copy
import json
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in (ROOT / "src", ROOT / "scripts"):
    sys.path.insert(0, str(p))

from evaluate_round7_r4 import r4_aggregate
from failsafe.inference.baselines import episode_verdicts
from failsafe.inference.block_cause import attribute, blocked
from failsafe.inference.hypotheses import policy_from_hypothesis
from failsafe.inference.policy_mapper import EngineParams
from failsafe.probe import PROBE_IDS
from failsafe.probe.catalog import run_probe
from failsafe.simulator.attribution import DEVICE_BOUND
from failsafe.simulator.rp import RPSessionState, rp_register_credential
from failsafe.simulator.rp_model import Request, rp_handle

PARAMS = EngineParams(eps=0.1, tau=0.99, m=2, per_probe_a1=True)
import os
MODE = os.environ.get("T3_MODE", "exp")
RESUME_GAP = 0.3
W_REAL = 120.0
OUT = ROOT / "results" / "round8" / "t3_sim"

BASE = dict(verify_before_store=1, store_counter_before_verify=0, check_uv=0, check_bebs=1, check_signcount=1,
            count_normal=0, count_tamper=0, revoke_on_tamper=0)
CONDS = {
    "T_bebs (VW 1.35.4형)": ({**BASE, "verify_before_store": 0}, "state_corruption"),
    "T_ctr (FS-2·M_C형)": ({**BASE, "store_counter_before_verify": 1}, "state_corruption"),
    "N_clean (VW 1.35.5형)": (dict(BASE), "no_block"),
    "N_templock (Keycloak 보호 켬형)": ({**BASE, "check_bebs": 0, "check_signcount": 0, "count_tamper": 1}, "normal_policy"),
    "N_revoke (지속 정책형)": ({**BASE, "revoke_on_tamper": 1}, "normal_policy"),
}


class ReplicatedSession:
    def __init__(self, policy, victim, rng, p_replica, mean_lag):
        self.policy, self.rng, self.p, self.L = policy, rng, p_replica, mean_lag
        st = RPSessionState()
        self._counter = st.last_sign_count
        rp_register_credential(policy, st, *victim.registered)
        self.history = [(-1e9, copy.deepcopy(st))]
        self.primary = st
        self.stale_reads = 0
        self.pauses = []
        if MODE == "pause" and mean_lag > 0:
            t = -rng.uniform(0, mean_lag + RESUME_GAP) - 10.0
            while t < 1000.0:
                d = rng.expovariate(1.0 / mean_lag)
                self.pauses.append((t, t + d))
                t += d + RESUME_GAP

    def next_counter(self):
        self._counter += 1
        return self._counter

    def _view(self, t):
        if self.L > 0 and self.rng.random() < self.p:
            if MODE == "pause":
                start = next((a for a, b in self.pauses if a <= t <= b), None)
                if start is None:
                    return copy.deepcopy(self.primary)
                snap = [s for (c, s) in self.history if c <= start][-1]
            else:
                lag = self.rng.expovariate(1.0 / self.L)
                snap = [s for (c, s) in self.history if c <= t - lag][-1]
            if snap is not self.history[-1][1]:
                self.stale_reads += 1
            return copy.deepcopy(snap)
        return copy.deepcopy(self.primary)

    def send(self, request: Request, at: float) -> str:
        read = self._view(at)
        before = copy.deepcopy(read)
        symbol, new = rp_handle(self.policy, read, request, at)
        if new != before:
            self.primary = copy.deepcopy(new)
            self.history.append((at, copy.deepcopy(new)))
        return symbol


class ReplicatedTarget:
    def __init__(self, policy, rng, p_replica, mean_lag):
        self.policy, self.rng, self.p, self.L = policy, rng, p_replica, mean_lag
        self.victim = DEVICE_BOUND
        self.wait_horizon = W_REAL

    def new_session(self):
        return ReplicatedSession(self.policy, self.victim, self.rng, self.p, self.L)


def run(trials=300, lags=(0.0, 0.5, 1.0, 2.0, 4.0, 8.0), p_replica=0.5, seed=20261116):
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, (h, truth) in CONDS.items():
        pol = policy_from_hypothesis(h)
        for L in lags:
            rng = random.Random(f"{seed}-{name}-{L}")
            c = Counter()
            for _ in range(trials):
                tgt = ReplicatedTarget(pol, rng, p_replica, L)
                obs = [run_probe(tgt, p) for p in PROBE_IDS]
                fs = attribute(obs, PARAMS).verdict
                seen = any(blocked(o.probe_id, o.symbols) for o in obs if o.probe_id in ("P_CORRUPT", "P_CORRUPT_CTR"))
                c["block_observed"] += int(seen)
                r4 = r4_aggregate(episode_verdicts(obs)["v2 규칙"])
                for arm, v in (("FS", fs), ("R4", r4)):
                    pos = truth == "state_corruption"
                    c[f"{arm}_fp"] += int(not pos and v == "state_corruption")
                    c[f"{arm}_miss"] += int(pos and v in ("normal_policy", "no_block"))
                    c[f"{arm}_miss_observed"] += int(pos and seen and v in ("normal_policy", "no_block"))
                    c[f"{arm}_hit"] += int(pos and v == "state_corruption")
                    c[f"{arm}_und"] += int(v == "undetermined")
                    c[f"{arm}_label_ok"] += int(not pos and v == truth)
            row = {"mode": MODE, "cond": name, "truth": truth, "mean_lag_s": L, "p_replica": p_replica, "n": trials, **dict(c)}
            rows.append(row)
            print(json.dumps(row, ensure_ascii=False), flush=True)
    (OUT / f"sim_{MODE}.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    run()
