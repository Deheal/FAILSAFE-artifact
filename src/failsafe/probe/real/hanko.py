from __future__ import annotations

import json
import os
from base64 import urlsafe_b64decode

import requests

from ...simulator.rp_model import ACCEPT, BLOCKED_PRE, ERROR, REJECT
from .base import RealSession, RealTarget

from authenticator import SoftAuthenticator

ORIGIN = "http://localhost"
CAPS = {"webauthn_available": True, "webauthn_conditional_mediation_available": False,
        "webauthn_platform_authenticator_available": False}


def b64u_dec(s: str) -> bytes:
    return urlsafe_b64decode(s + "=" * (-len(s) % 4))


class _Flow:
    def __init__(self, base: str, path: str):
        self.base, self.s = base, requests.Session()
        r = self.s.post(base + path, json={}, headers={"Origin": ORIGIN}, timeout=60)
        self.status = r.status_code
        self.j = r.json() if r.status_code < 500 else {}

    def act(self, name: str, data: dict) -> dict:
        a = (self.j.get("actions") or {}).get(name)
        if a is None:
            raise KeyError(f"action {name} not in state {self.j.get('name')} ({self.j.get('error')})")
        r = self.s.post(self.base + a["href"], json={"input_data": data, "csrf_token": self.j.get("csrf_token")},
                        headers={"Origin": ORIGIN}, timeout=60)
        self.status = r.status_code
        self.j = r.json() if r.status_code < 500 else {"name": "http_error", "status": r.status_code}
        return self.j


class HankoSession(RealSession):
    def __init__(self, victim, url: str):
        self.url = url.rstrip("/")
        super().__init__(victim)

    def _register(self, be, bs):
        f = _Flow(self.url, "/registration")
        f.act("register_client_capabilities", CAPS)
        self.email = f"psm{os.urandom(5).hex()}@example.com"
        f.act("register_login_identifier", {"email": self.email})
        j = f.act("webauthn_generate_creation_options", {})
        pk = j["payload"]["creation_options"]["publicKey"]
        self.auth = SoftAuthenticator(rp_id="localhost")
        att = self.auth.make_registration_resident(b64u_dec(pk["challenge"]), ORIGIN,
                                                   user_handle=b64u_dec(pk["user"]["id"]), be=be, bs=bs)
        j = f.act("webauthn_verify_attestation_response", {"public_key": json.dumps(att)})
        if j.get("name") != "success":
            raise RuntimeError(f"register ended in {j.get('name')} {j.get('error')}")
        self.other = SoftAuthenticator(rp_id="localhost")
        self.other.user_handle = self.auth.user_handle
        self.account_id = self.email

    def _attempt(self, signer, be, bs, counter, valid=True, uv=True):
        f = _Flow(self.url, "/login")
        if f.status >= 500:
            return ERROR, f"login init {f.status}"
        try:
            f.act("register_client_capabilities", CAPS)
            j = f.act("webauthn_generate_request_options", {})
        except KeyError as e:
            return BLOCKED_PRE, str(e)[:160]
        if f.status >= 500:
            return ERROR, f"request options {f.status}"
        opts = (j.get("payload") or {}).get("request_options", {}).get("publicKey")
        if not opts:
            return BLOCKED_PRE, f"no request options in {j.get('name')} {j.get('error')}"
        a = signer.make_assertion(b64u_dec(opts["challenge"]), ORIGIN, be=be, bs=bs, counter=counter,
                                  valid_signature=valid, uv=uv)
        try:
            j = f.act("webauthn_verify_assertion_response", {"assertion_response": json.dumps(a)})
        except KeyError as e:
            return ERROR, str(e)[:160]
        if f.status >= 500:
            return ERROR, f"assert {f.status} {str(j)[:120]}"
        if j.get("name") == "success":
            return ACCEPT, "success"
        if j.get("error"):
            return REJECT, f"{j.get('name')} {j['error'].get('code')} {str(j['error'].get('cause', ''))[:100]}"
        return ERROR, f"unexpected state {j.get('name')}"

    def _valid(self, be, bs, uv, counter):
        return self._attempt(self.auth, be, bs, counter, valid=True, uv=uv)

    def _forged(self, be, bs, counter):
        return self._attempt(self.auth, be, bs, counter, valid=False)

    def _wrong_cred(self, be, bs):
        self.other.sign_count += 1
        return self._attempt(self.other, be, bs, self.other.sign_count, valid=True)


class HankoTarget(RealTarget):
    session_class = HankoSession
