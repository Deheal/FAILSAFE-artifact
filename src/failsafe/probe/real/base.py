from __future__ import annotations

import os
import sys
import time
import traceback
from pathlib import Path
from typing import List, Optional

from ...simulator.attribution import DEVICE_BOUND, VictimProfile
from ...simulator.rp_model import ERROR, Request

PPL_SCRIPTS = Path(os.environ.get(
    "PPL_SCRIPTS", "external/vaultwarden_repro/scripts"))
if str(PPL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(PPL_SCRIPTS))

REAL_WAIT_HORIZON_SEC = 120.0


class RealSession:

    def __init__(self, victim: VictimProfile):
        self.victim = victim
        self._counter = 0
        self.log: List[dict] = []
        self._last_at: Optional[float] = None
        self._last_sent: Optional[float] = None
        self.account_id: Optional[str] = None
        self._register(*victim.registered)
        if tuple(victim.current) != tuple(victim.registered):
            self.send(Request("valid", *victim.current, counter=self.next_counter()), at=-1.0)

    def next_counter(self) -> int:
        self._counter += 1
        return self._counter

    def _wait_until(self, at: float) -> None:
        if self._last_at is not None and at > self._last_at:
            target = self._last_sent + (at - self._last_at)
            delay = target - time.monotonic()
            if delay > 0:
                time.sleep(delay)
        self._last_at = at

    def send(self, request: Request, at: float) -> str:
        self._wait_until(at)
        self._last_sent = time.monotonic()
        try:
            if request.kind == "valid":
                symbol, detail = self._valid(request.be, request.bs, request.uv, request.counter)
            elif request.kind == "forged":
                symbol, detail = self._forged(request.be, request.bs, request.counter)
            elif request.kind == "wrong_cred":
                symbol, detail = self._wrong_cred(request.be, request.bs)
            else:
                raise ValueError(request.kind)
        except Exception as exc:
            symbol, detail = ERROR, f"{type(exc).__name__}: {exc} | {traceback.format_exc(limit=2)[-300:]}"
        self.log.append({"at": at, "t": round(self._last_sent, 3), "kind": request.kind,
                         "be": request.be, "bs": request.bs, "uv": request.uv, "counter": request.counter,
                         "symbol": symbol, "detail": str(detail)[:300]})
        return symbol

    def _register(self, be: bool, bs: bool) -> None:
        raise NotImplementedError

    def _valid(self, be, bs, uv, counter):
        raise NotImplementedError

    def _forged(self, be, bs, counter):
        raise NotImplementedError

    def _wrong_cred(self, be, bs):
        raise NotImplementedError


class RealTarget:
    session_class = RealSession

    def __init__(self, victim: VictimProfile = DEVICE_BOUND, wait_horizon: float = REAL_WAIT_HORIZON_SEC, **kw):
        self.victim = victim
        self.wait_horizon = wait_horizon
        self.kw = kw
        self.sessions: List[RealSession] = []

    def new_session(self) -> RealSession:
        s = self.session_class(self.victim, **self.kw)
        self.sessions.append(s)
        return s
