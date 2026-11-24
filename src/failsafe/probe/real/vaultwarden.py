from __future__ import annotations

import os

from ...simulator.rp_model import ACCEPT, BLOCKED_PRE, ERROR, REJECT
from .base import RealSession, RealTarget

from authenticator import SoftAuthenticator
from vw_client import VaultwardenClient

PASSWORD = "Correct-Horse-Battery-Staple-1"


class VaultwardenSession(RealSession):
    def __init__(self, victim, url: str):
        self.c = VaultwardenClient(url)
        super().__init__(victim)

    def _register(self, be, bs):
        email = f"psm_{os.urandom(5).hex()}@example.com"
        self.acc = self.c.register(email, PASSWORD)
        token = self.c.access_token(self.acc)
        self.auth = self.c.register_webauthn(self.acc, token, be=be, bs=bs)
        self.other = SoftAuthenticator(rp_id=self.auth.rp_id)
        self.account_id = email

    def _attempt(self, authenticator, **kw):
        r = self.c.password_login(self.acc)
        if r.status_code == 429:
            return ERROR, "password step 429"
        if r.status_code != 400 or "TwoFactorProviders2" not in r.text:
            return (BLOCKED_PRE if r.status_code < 500 else ERROR), f"password step {r.status_code} {r.text[:120]}"
        chal = self.c.extract_webauthn_challenge(r)
        a = authenticator.make_assertion(chal, self.c.origin, **kw)
        r2 = self.c.login_with_2fa(self.acc, a)
        if r2.status_code == 200 and "access_token" in r2.text:
            return ACCEPT, "200"
        if r2.status_code in (400, 401, 403):
            return REJECT, f"{r2.status_code} {r2.text[:160]}"
        return ERROR, f"{r2.status_code} {r2.text[:160]}"

    def _valid(self, be, bs, uv, counter):
        return self._attempt(self.auth, be=be, bs=bs, uv=uv, counter=counter, valid_signature=True)

    def _forged(self, be, bs, counter):
        return self._attempt(self.auth, be=be, bs=bs, counter=counter, valid_signature=False)

    def _wrong_cred(self, be, bs):
        return self._attempt(self.other, be=be, bs=bs, valid_signature=True)


class VaultwardenTarget(RealTarget):
    session_class = VaultwardenSession
