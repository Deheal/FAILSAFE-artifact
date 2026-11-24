from __future__ import annotations

import os
import threading
import time
from base64 import urlsafe_b64decode

import requests

from ...simulator.rp_model import ACCEPT, BLOCKED_PRE, ERROR, REJECT
from .base import RealSession, RealTarget

from authenticator import SoftAuthenticator

ORIGIN = "http://localhost"
PIN = "r7pin"
ADMIN = ("r7admin", "r7adminpass")
_TOKENS: dict = {}
_LOCK = threading.Lock()


def b64u_dec(s: str) -> bytes:
    return urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _admin_token(url: str) -> str:
    with _LOCK:
        tok, t = _TOKENS.get(url, (None, 0.0))
        if tok is None or time.time() - t > 600:
            r = requests.post(url + "/auth", data={"username": ADMIN[0], "password": ADMIN[1]}, timeout=30)
            r.raise_for_status()
            tok = r.json()["result"]["value"]["token"]
            _TOKENS[url] = (tok, time.time())
        return tok


def _ok(r: requests.Response, what: str) -> dict:
    j = r.json()
    if r.status_code >= 400 or not j.get("result", {}).get("status"):
        raise RuntimeError(f"{what} {r.status_code} {r.text[:200]}")
    return j


class PrivacyIdeaSession(RealSession):
    def __init__(self, victim, url: str):
        self.url = url.rstrip("/")
        super().__init__(victim)

    def _register(self, be, bs):
        adm = {"Authorization": _admin_token(self.url)}
        self.user = f"psm{os.urandom(5).hex()}"
        _ok(requests.post(self.url + "/user/", headers=adm, timeout=30, data={
            "resolver": "r7res", "user": self.user, "password": "Unused-Pass-1", "email": f"{self.user}@example.com"}),
            "user create")
        j = _ok(requests.post(self.url + "/token/init", headers=adm, timeout=60, data={
            "type": "webauthn", "user": self.user, "realm": "r7", "pin": PIN}), "token init 1")
        req = j["detail"]["webAuthnRegisterRequest"]
        self.serial = j["detail"]["serial"]
        self.auth = SoftAuthenticator(rp_id="localhost")
        att = self.auth.make_registration(b64u_dec(req["nonce"]), ORIGIN, be=be, bs=bs)
        _ok(requests.post(self.url + "/token/init", headers={**adm, "Origin": ORIGIN}, timeout=60, data={
            "type": "webauthn", "user": self.user, "realm": "r7", "serial": self.serial,
            "transaction_id": req["transaction_id"],
            "clientdata": att["response"]["clientDataJson"], "regdata": att["response"]["attestationObject"]}),
            "token init 2")
        self.other = SoftAuthenticator(rp_id="localhost")
        self.account_id = f"{self.user}/{self.serial}"

    def _attempt(self, signer, be, bs, counter, valid=True, uv=True):
        s = requests.Session()
        r = s.post(self.url + "/validate/check", timeout=60,
                   data={"user": self.user, "realm": "r7", "pass": PIN})
        if r.status_code >= 500:
            return ERROR, f"trigger {r.status_code} {r.text[:120]}"
        j = r.json()
        res, det = j.get("result", {}), j.get("detail") or {}
        chals = det.get("multi_challenge") or []
        if not chals:
            if res.get("status") and res.get("authentication") == "REJECT":
                return BLOCKED_PRE, f"no challenge: {det.get('message', '')[:120]}"
            return ERROR, f"trigger {r.status_code} {r.text[:160]}"
        ch = chals[0]
        chal = ch["attributes"]["webAuthnSignRequest"]["challenge"]
        a = signer.make_assertion(b64u_dec(chal), ORIGIN, be=be, bs=bs, counter=counter, valid_signature=valid, uv=uv)
        resp = a["response"]
        r2 = s.post(self.url + "/validate/check", timeout=60, headers={"Origin": ORIGIN}, data={
            "user": self.user, "realm": "r7", "pass": "", "transaction_id": ch["transaction_id"],
            "credentialid": a["id"], "clientdata": resp["clientDataJSON"],
            "signaturedata": resp["signature"], "authenticatordata": resp["authenticatorData"]})
        if r2.status_code >= 500:
            return ERROR, f"assert {r2.status_code} {r2.text[:120]}"
        j2 = r2.json()
        res2, det2 = j2.get("result", {}), j2.get("detail") or {}
        if res2.get("status") and res2.get("authentication") == "ACCEPT":
            return ACCEPT, "accept"
        if res2.get("status") and res2.get("authentication") == "REJECT":
            return REJECT, f"reject: {det2.get('message', '')[:120]}"
        return ERROR, f"assert {r2.status_code} {r2.text[:160]}"

    def _valid(self, be, bs, uv, counter):
        return self._attempt(self.auth, be, bs, counter, valid=True, uv=uv)

    def _forged(self, be, bs, counter):
        return self._attempt(self.auth, be, bs, counter, valid=False)

    def _wrong_cred(self, be, bs):
        self.other.sign_count += 1
        return self._attempt(self.other, be, bs, self.other.sign_count, valid=True)


class PrivacyIdeaTarget(RealTarget):
    session_class = PrivacyIdeaSession
