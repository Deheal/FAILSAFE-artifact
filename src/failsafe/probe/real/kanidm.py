from __future__ import annotations

import os
import threading

import json
from base64 import b64decode

from ...simulator.rp_model import ACCEPT, BLOCKED_PRE, ERROR, REJECT
from .base import RealSession, RealTarget

from authenticator import SoftAuthenticator
import kanidm_oracle as ko


def _b64u_dec(s):
    s = s.replace("-", "+").replace("_", "/")
    return b64decode(s + "=" * (-len(s) % 4))

_LOCK = threading.Lock()
_COUNTER = [0]
_ADMIN_PW = os.environ.get("KANIDM_ADMIN_PW", "")


def _next_name() -> str:
    with _LOCK:
        _COUNTER[0] += 1
        return f"fs{_COUNTER[0]:05d}"


class KanidmSession(RealSession):
    def __init__(self, victim, url: str = ""):
        self._k = ko.Kanidm(_ADMIN_PW)
        super().__init__(victim)

    def _register(self, be, bs):
        self.name = _next_name()
        self.auth = SoftAuthenticator(rp_id=self._k.rp_id)
        with _LOCK:
            self._k.create_person(self.name)
            k, H, base = self._k, self._k.H, ko.K
            it = k.s.get(f"{base}/v1/person/{self.name}/_credential/_update_intent", headers=H).json()["token"]
            sess = k.s.post(f"{base}/v1/credential/_exchange_intent", headers=H, data=json.dumps(it)).json()[0]
            d = k.s.post(f"{base}/v1/credential/_update", headers=H, data=json.dumps(["passkeyinit", sess])).json()
            status = d[1] if isinstance(d, list) else d
            co = status["mfaregstate"]["Passkey"]["publicKey"]
            att = self.auth.make_registration_resident(
                _b64u_dec(co["challenge"]), self._k.origin,
                user_handle=_b64u_dec(co["user"]["id"]), be=be, bs=bs)
            rpkc = {"id": att["id"], "rawId": att["rawId"], "type": "public-key", "extensions": {},
                    "response": {"attestationObject": att["response"]["attestationObject"],
                                 "clientDataJSON": att["response"]["clientDataJSON"]}}
            r = k.s.post(f"{base}/v1/credential/_update", headers=H,
                         data=json.dumps([{"passkeyfinish": ["softkey", rpkc]}, sess]))
            if r.status_code != 200:
                raise RuntimeError(f"passkeyfinish {r.status_code}: {r.text[:200]}")
            c = k.s.post(f"{base}/v1/credential/_commit", headers=H, data=json.dumps(sess))
            if c.status_code != 200:
                raise RuntimeError(f"commit {c.status_code}: {c.text[:160]}")
        self.other = SoftAuthenticator(rp_id=self._k.rp_id)
        self._other_counter = 0
        self.account_id = self.name

    def _login(self, signer, be, bs, counter, valid):
        try:
            ok, rc = self._k.passkey_login(self.name, signer, be=be, bs=bs, counter=counter, valid=valid)
        except Exception as exc:
            return ERROR, f"{type(exc).__name__}: {exc}"
        if ok:
            return ACCEPT, "success"
        code = rc.status_code
        if code in (401, 403, 400):
            return REJECT, f"{code} {rc.text[:140]}"
        if code < 500:
            return BLOCKED_PRE, f"{code} {rc.text[:140]}"
        return ERROR, f"{code} {rc.text[:140]}"

    def _valid(self, be, bs, uv, counter):
        return self._login(self.auth, be, bs, counter, True)

    def _forged(self, be, bs, counter):
        return self._login(self.auth, be, bs, counter, False)

    def _wrong_cred(self, be, bs):
        self._other_counter += 1
        return self._login(self.other, be, bs, self._other_counter, True)


class KanidmTarget(RealTarget):
    session_class = KanidmSession
