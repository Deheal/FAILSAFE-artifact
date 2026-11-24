from __future__ import annotations

import hashlib
import random

from ...simulator.rp_model import Request

SEED_B = 20261116


def task_rng(rp: str, q: float, rep: int, probe_id: str) -> random.Random:
    key = f"{SEED_B}|{rp}|{q}|{rep}|{probe_id}".encode()
    return random.Random(int.from_bytes(hashlib.sha256(key).digest()[:8], "big"))


def is_normal_login(session, request: Request, at: float) -> bool:
    return (at >= 0 and request.kind == "valid"
            and (request.be, request.bs) == tuple(session.victim.current)
            and request.uv is True
            and request.counter == session._counter)


def wrap_session(session, q: float, rng: random.Random):
    orig = session.send

    def send(request: Request, at: float) -> str:
        if is_normal_login(session, request, at):
            if rng.random() < q:
                faulted = Request("forged", be=request.be, bs=request.bs, uv=True, counter=request.counter)
                symbol = orig(faulted, at)
                session.log[-1]["fault"] = True
                return symbol
            symbol = orig(request, at)
            session.log[-1]["fault"] = False
            return symbol
        return orig(request, at)

    session.send = send
    return session


class FaultTarget:

    def __init__(self, inner, q: float, rng: random.Random):
        self.inner = inner
        self.q = q
        self.rng = rng

    @property
    def victim(self):
        return self.inner.victim

    @property
    def wait_horizon(self):
        return self.inner.wait_horizon

    @property
    def sessions(self):
        return self.inner.sessions

    def new_session(self):
        return wrap_session(self.inner.new_session(), self.q, self.rng)
