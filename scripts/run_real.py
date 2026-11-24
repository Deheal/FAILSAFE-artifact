import argparse
import json
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from failsafe.probe import PROBE_IDS, run_probe
from failsafe.probe.real import make_target

LOCK = threading.Lock()


def _append(path, row):
    with LOCK, open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rp", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--workers", type=int, default=40)
    ap.add_argument("--wait", type=float, default=None, help="W 초 (기본: REAL_WAIT_HORIZON_SEC)")
    ap.add_argument("--probes", default=",".join(PROBE_IDS))
    ap.add_argument("--out", default=None)
    ap.add_argument("--seed", type=int, default=20261112)
    ap.add_argument("--victim", default=None, help="사용자 유형 이름 (기본: 기기 종속). 3차 B 조건은 '동기화 완료'")
    args = ap.parse_args()

    out = Path(args.out) if args.out else ROOT / "results" / "real" / args.rp
    out.mkdir(parents=True, exist_ok=True)
    obs_path, log_path, acc_path = out / "observations.jsonl", out / "logs.jsonl", out / "accounts.jsonl"

    done = set()
    if obs_path.exists():
        for line in obs_path.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            done.add((r["rep"], r["probe_id"]))
    tasks = [(rep, p) for rep in range(args.reps) for p in args.probes.split(",") if (rep, p) not in done]
    random.Random(args.seed).shuffle(tasks)
    print(f"{args.rp}: 할 일 {len(tasks)}개 (이미 {len(done)}개)", flush=True)

    kw = {"url": args.url}
    if args.victim:
        from failsafe.simulator.attribution import VICTIMS
        kw["victim"] = {v.name: v for v in VICTIMS}[args.victim]
    if args.wait is not None:
        kw["wait_horizon"] = args.wait

    def work(rep, probe_id):
        target = make_target(args.rp, **kw)
        t0 = time.time()
        obs = run_probe(target, probe_id)
        ctrl, probe = target.sessions[0], target.sessions[1]
        _append(obs_path, {"rp": args.rp, "rep": rep, "probe_id": probe_id,
                           "control_symbols": list(obs.control_symbols), "symbols": list(obs.symbols),
                           "victim": obs.victim.name, "wait_horizon": target.wait_horizon,
                           "started": round(t0, 1), "finished": round(time.time(), 1)})
        _append(log_path, {"rp": args.rp, "rep": rep, "probe_id": probe_id,
                           "control": ctrl.log, "probe": probe.log})
        _append(acc_path, {"rp": args.rp, "rep": rep, "probe_id": probe_id,
                           "control_account": ctrl.account_id, "probe_account": probe.account_id})
        return rep, probe_id, obs

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(work, rep, p) for rep, p in tasks]
        for i, f in enumerate(as_completed(futs), 1):
            try:
                rep, p, obs = f.result()
                print(f"[{i}/{len(tasks)}] rep{rep:02d} {p:<13} ctrl={'/'.join(s[0] for s in obs.control_symbols)} "
                      f"probe={'/'.join(s[0] for s in obs.symbols)}", flush=True)
            except Exception as exc:
                print(f"[{i}/{len(tasks)}] 실패: {type(exc).__name__}: {exc}", flush=True)


if __name__ == "__main__":
    main()
