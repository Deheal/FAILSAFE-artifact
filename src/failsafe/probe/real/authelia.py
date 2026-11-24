from __future__ import annotations

import os
import threading
from pathlib import Path

os.environ.setdefault("AUTHELIA_PORT", "9095")
os.environ.setdefault("AUTHELIA_DIR", os.path.expanduser("~/afs-psm"))

from ...simulator.rp_model import ACCEPT, BLOCKED_PRE, ERROR, REJECT
from .base import RealSession, RealTarget

import authelia_client as ac
from authelia_client import AutheliaSession
from authenticator import SoftAuthenticator
from vw_client import _b64u_decode

_REG_LOCK = threading.Lock()
_USER_LOCK = threading.Lock()
_COUNTER = Path(ac._DIR) / "next_user.txt"


def _next_user() -> str:
    with _USER_LOCK:
        n = int(_COUNTER.read_text()) if _COUNTER.exists() else 0
        _COUNTER.write_text(str(n + 1))
    return f"p{n:04d}"


class AutheliaPSMSession(RealSession):
    def __init__(self, victim, url: str = ""):
        super().__init__(victim)

    def _register(self, be, bs):
        self.user = _next_user()
        with _REG_LOCK:
            s = AutheliaSession()
            if not s.first_factor(self.user):
                raise RuntimeError(f"first factor failed for {self.user}")
            if not s.elevate():
                raise RuntimeError(f"elevation failed for {self.user}")
            self.auth = s.register_credential(be, bs)
        self.other = SoftAuthenticator(rp_id=self.auth.rp_id)
        self._other_counter = 0
        self.account_id = self.user

    def _attempt(self, signer, be, bs, counter, valid=True, uv=True):
        s = AutheliaSession()
        r = s.s.post(f"{ac.BASE}/api/firstfactor",
                     json={"username": self.user, "password": ac.PASSWORD, "keepMeLoggedIn": False})
        if r.status_code != 200:
            return (BLOCKED_PRE if r.status_code < 500 else ERROR), f"1FA {r.status_code} {r.text[:120]}"
        pk = s.assertion_options()
        a = signer.make_assertion(_b64u_decode(pk["challenge"]), ac.ORIGIN, be=be, bs=bs, counter=counter,
                                  valid_signature=valid, rp_id=pk.get("rpId"), uv=uv)
        r2 = s.s.post(f"{ac.BASE}/api/secondfactor/webauthn", json={"response": a})
        if r2.status_code == 200:
            return ACCEPT, "200"
        if r2.status_code in (400, 401, 403):
            return REJECT, f"{r2.status_code} {r2.text[:160]}"
        return ERROR, f"{r2.status_code} {r2.text[:160]}"

    def _valid(self, be, bs, uv, counter):
        return self._attempt(self.auth, be, bs, counter, valid=True, uv=uv)

    def _forged(self, be, bs, counter):
        return self._attempt(self.auth, be, bs, counter, valid=False)

    def _wrong_cred(self, be, bs):
        self._other_counter += 1
        return self._attempt(self.other, be, bs, self._other_counter, valid=True)


class AutheliaTarget(RealTarget):
    session_class = AutheliaPSMSession
