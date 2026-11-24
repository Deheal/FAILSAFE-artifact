from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from ..simulator.attribution import DEVICE_BOUND, VictimProfile
from ..simulator.rp_model import REJECT, Request

PROBE_IDS = ("P_UV0", "P_BEBS", "P_SC_DEC", "P_WRONG_CRED", "P_TAMPER_K", "P_REVOKE",
             "P_CORRUPT", "P_CORRUPT_CTR")

PROBE_K = 3
WAIT_HORIZON_SEC = 3600.0
import os as _os
STEP_SEC = float(_os.environ.get("FAILSAFE_STEP_SEC", "2.0"))
HIGH_COUNTER = 100000


@dataclass(frozen=True)
class ProbeObservation:
    probe_id: str
    control_symbols: Tuple[str, ...]
    symbols: Tuple[str, ...]
    victim: VictimProfile = DEVICE_BOUND


@dataclass(frozen=True)
class Step:
    kind: str
    flags: str = "current"
    uv: bool = True
    counter: str = "next"
    abnormal: bool = False
    after_wait: bool = False


LOGIN = Step("valid")
LOGIN_AFTER_WAIT = Step("valid", after_wait=True)
TAIL = [LOGIN, LOGIN, LOGIN_AFTER_WAIT]
TAIL_LEN = len(TAIL)


def _script(probe_id: str) -> List[Step]:
    k = PROBE_K
    if probe_id == "P_UV0":
        return [Step("valid", uv=False, abnormal=True)] + TAIL
    if probe_id == "P_BEBS":
        return [Step("valid", flags="bebs", abnormal=True)] + TAIL
    if probe_id == "P_SC_DEC":
        return [LOGIN, LOGIN, Step("valid", counter="low", abnormal=True)] + TAIL
    if probe_id == "P_WRONG_CRED":
        return [Step("wrong_cred", abnormal=True)] * k + TAIL
    if probe_id == "P_TAMPER_K":
        return [Step("forged", abnormal=True)] * k + TAIL
    if probe_id == "P_REVOKE":
        return [Step("forged", abnormal=True)] + TAIL
    if probe_id == "P_CORRUPT":
        return [Step("forged", flags="tampered", abnormal=True)] + TAIL
    if probe_id == "P_CORRUPT_CTR":
        return [Step("forged", counter="high", abnormal=True)] + TAIL
    raise ValueError(f"알 수 없는 프로브: {probe_id}")


def tail_symbols(obs: "ProbeObservation") -> Tuple[str, str, str]:
    n = len(_script(obs.probe_id))
    return tuple(obs.symbols[n - TAIL_LEN:n])


def tampered_flags(victim: VictimProfile) -> Tuple[bool, bool]:
    return (True, True) if tuple(victim.current) != (True, True) else (True, False)


def _flags(step: Step, victim: VictimProfile) -> Tuple[bool, bool]:
    if step.flags == "current":
        return tuple(victim.current)
    if step.flags == "bebs":
        return (False, True)
    if step.flags == "tampered":
        return tampered_flags(victim)
    raise ValueError(step.flags)


def _request(step: Step, session, victim: VictimProfile) -> Request:
    be, bs = _flags(step, victim)
    if step.counter == "low":
        counter = 1
    elif step.counter == "high":
        counter = HIGH_COUNTER
    elif step.kind == "valid":
        counter = session.next_counter()
    else:
        counter = 0
    return Request(step.kind, be=be, bs=bs, uv=step.uv, counter=counter)


def _run_steps(session, steps: List[Step], victim: VictimProfile, wait: float):
    t, symbols = 0.0, []
    for step in steps:
        t += wait if step.after_wait else STEP_SEC
        symbols.append(session.send(_request(step, session, victim), at=t))
    return symbols, t


def _run_aligned(target, steps: List[Step], victim: VictimProfile, wait: float):
    import time as _time
    ctrl_s, probe_s = target.new_session(), target.new_session()
    real = hasattr(probe_s, "_wait_until")
    normal = [s for s in steps if not s.abnormal]
    t, ctrl, syms, j, t0 = 0.0, [], [], 0, _time.monotonic()

    def _sleep_to(at):
        if real:
            d = t0 + at - _time.monotonic()
            if d > 0:
                _time.sleep(d)

    for step in steps:
        t += wait if step.after_wait else STEP_SEC
        if not step.abnormal:
            _sleep_to(t - 0.5)
            ctrl.append(ctrl_s.send(_request(normal[j], ctrl_s, victim), at=t - 0.5))
            j += 1
        _sleep_to(t)
        syms.append(probe_s.send(_request(step, probe_s, victim), at=t))
    return ctrl, syms, t, probe_s


def run_probe(target, probe_id: str) -> ProbeObservation:
    victim = getattr(target, "victim", None) or DEVICE_BOUND
    wait = getattr(target, "wait_horizon", WAIT_HORIZON_SEC)
    steps = _script(probe_id)

    if _os.environ.get("FAILSAFE_CONTROL") == "aligned":
        control_symbols, symbols, t, session = _run_aligned(target, steps, victim, wait)
    else:
        control_symbols, _ = _run_steps(target.new_session(),
                                        [s for s in steps if not s.abnormal], victim, wait)
        session = target.new_session()
        symbols, t = _run_steps(session, steps, victim, wait)
    if probe_id == "P_CORRUPT" and symbols[1] == REJECT and symbols[-1] == REJECT:
        probe = Step("valid", flags="tampered")
        symbols.append(session.send(_request(probe, session, victim), at=t))
    if probe_id == "P_CORRUPT_CTR" and symbols[1] == REJECT and symbols[-1] == REJECT:
        req = Request("valid", be=victim.current[0], bs=victim.current[1], uv=True, counter=HIGH_COUNTER + 1)
        symbols.append(session.send(req, at=t))

    return ProbeObservation(probe_id, tuple(control_symbols), tuple(symbols), victim)
