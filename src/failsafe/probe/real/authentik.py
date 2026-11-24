from __future__ import annotations

import json
import os
from base64 import b64decode

import requests

from ...simulator.rp_model import ACCEPT, BLOCKED_PRE, ERROR, REJECT
from .base import RealSession, RealTarget

from authenticator import SoftAuthenticator

AK = os.environ.get("AUTHENTIK_URL", "http://localhost:9400")
LOGIN_FLOW = "default-authentication-flow"
REG_FLOW = "default-authenticator-webauthn-setup"
ADMIN, ADMIN_PASS, USER_PASS = "akadmin", "Repro-Admin-123", "Repro-Pass-123"
VALIDATE = "ak-stage-authenticator-validate"


def b64u_dec(s):
    if isinstance(s, (bytes, bytearray)):
        return bytes(s)
    s = s.replace("-", "+").replace("_", "/")
    return b64decode(s + "=" * (-len(s) % 4))


class _AK:

    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({"Referer": AK + "/", "Origin": AK})

    def _sync(self):
        csrf = self.s.cookies.get("authentik_csrf")
        if csrf:
            self.s.headers["X-authentik-CSRF"] = csrf

    def post(self, url, **kw):
        self._sync()
        return self.s.post(url, **kw)

    def ex_get(self, flow):
        return self.s.get(f"{AK}/api/v3/flows/executor/{flow}/", params={"query": ""})

    def ex_post(self, flow, payload):
        return self.post(f"{AK}/api/v3/flows/executor/{flow}/", params={"query": ""}, json=payload)

    def password(self, username, password):
        self.ex_get(LOGIN_FLOW)
        self.ex_post(LOGIN_FLOW, {"uid_field": username})
        return self.ex_post(LOGIN_FLOW, {"password": password})


class AuthentikSession(RealSession):
    def __init__(self, victim, url: str = ""):
        super().__init__(victim)

    def _register(self, be, bs):
        self.user = f"psm{os.urandom(5).hex()}"
        admin = _AK()
        admin.password(ADMIN, ADMIN_PASS)
        r = admin.post(f"{AK}/api/v3/core/users/", json={
            "username": self.user, "name": self.user, "email": f"{self.user}@example.com",
            "is_active": True, "type": "internal", "path": "users", "groups": []})
        if r.status_code not in (200, 201):
            raise RuntimeError(f"user create {r.status_code} {r.text[:120]}")
        uid = r.json()["pk"]
        r = admin.post(f"{AK}/api/v3/core/users/{uid}/set_password/", json={"password": USER_PASS})
        if r.status_code >= 400:
            raise RuntimeError(f"set_password {r.status_code}")
        g = _AK()
        g.password(self.user, USER_PASS)
        reg = g.ex_get(REG_FLOW).json()["registration"]
        self.auth = SoftAuthenticator(rp_id="localhost")
        att = self.auth.make_registration_resident(b64u_dec(reg["challenge"]), AK,
                                                   user_handle=b64u_dec(reg["user"]["id"]), be=be, bs=bs)
        r = g.ex_post(REG_FLOW, {"response": {
            "id": att["id"], "rawId": att["rawId"], "type": "public-key", "registrationClientExtensions": "{}",
            "response": {"attestationObject": att["response"]["attestationObject"],
                         "clientDataJSON": att["response"]["clientDataJSON"]}}})
        if r.status_code >= 400 or "redirect" not in r.text:
            raise RuntimeError(f"register failed {r.status_code} {r.text[:160]}")
        self.other = SoftAuthenticator(rp_id="localhost")
        self._other_counter = 0
        self.account_id = self.user

    def _attempt(self, signer, be, bs, counter, valid=True, uv=True):
        g = _AK()
        r = g.password(self.user, USER_PASS)
        if r.status_code >= 500:
            return ERROR, f"password step {r.status_code}"
        ch = r.json()
        if ch.get("component") != VALIDATE:
            return BLOCKED_PRE, f"after password: {ch.get('component')}"
        wc = None
        for dc in ch.get("device_challenges") or []:
            if dc.get("device_class") == "webauthn":
                wc = json.loads(dc["challenge"]) if isinstance(dc["challenge"], str) else dc["challenge"]
        if wc is None:
            return ERROR, "no webauthn device challenge"
        a = signer.make_assertion(b64u_dec(wc["challenge"]), AK, be=be, bs=bs, counter=counter,
                                  valid_signature=valid, uv=uv, user_handle=b"")
        rr = g.ex_post(LOGIN_FLOW, {"webauthn": {
            "id": a["id"], "rawId": a["rawId"], "type": "public-key", "assertionClientExtensions": "{}",
            "response": {"clientDataJSON": a["response"]["clientDataJSON"],
                         "authenticatorData": a["response"]["authenticatorData"],
                         "signature": a["response"]["signature"], "userHandle": None}}})
        if rr.status_code >= 500:
            return ERROR, f"{rr.status_code}"
        comp = rr.json().get("component", "")
        if comp == "xak-flow-redirect":
            return ACCEPT, comp
        if comp in (VALIDATE, "ak-stage-flow-error"):
            return REJECT, f"{comp} {json.dumps(rr.json().get('response_errors') or rr.json().get('error') or '')[:120]}"
        return ERROR, f"unexpected component {comp}"

    def _valid(self, be, bs, uv, counter):
        return self._attempt(self.auth, be, bs, counter, valid=True, uv=uv)

    def _forged(self, be, bs, counter):
        return self._attempt(self.auth, be, bs, counter, valid=False)

    def _wrong_cred(self, be, bs):
        self._other_counter += 1
        return self._attempt(self.other, be, bs, self._other_counter, valid=True)


class AuthentikTarget(RealTarget):
    session_class = AuthentikSession
