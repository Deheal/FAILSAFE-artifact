from __future__ import annotations

import json
import os
import re
from base64 import b64decode

import requests

from ...simulator.rp_model import ACCEPT, BLOCKED_PRE, ERROR, REJECT
from .base import RealSession, RealTarget

from authenticator import SoftAuthenticator

BASE = os.environ.get("GITEA_URL", "http://localhost:8300")
ADMIN = ("testadmin", "Repro-Pass-123")
PASSWORD = "Repro-Pass-123"
CSRF_RE = re.compile(r'name="_csrf"\s+value="([^"]+)"')


def b64u_dec(s):
    s = s.replace("-", "+").replace("_", "/")
    return b64decode(s + "=" * (-len(s) % 4))


class _GiteaHTTP:
    def __init__(self):
        self.s = requests.Session()

    def csrf_cookie(self):
        return self.s.cookies.get("_csrf", "")

    def login(self, username):
        r = self.s.get(BASE + "/user/login")
        m = CSRF_RE.search(r.text)
        return self.s.post(BASE + "/user/login",
                           data={"_csrf": m.group(1) if m else "", "user_name": username, "password": PASSWORD},
                           allow_redirects=False)


class GiteaSession(RealSession):
    def __init__(self, victim, url: str = ""):
        super().__init__(victim)

    def _register(self, be, bs):
        self.user = f"psm{os.urandom(5).hex()}"
        r = requests.post(BASE + "/api/v1/admin/users", auth=ADMIN, json={
            "username": self.user, "email": f"{self.user}@example.com", "password": PASSWORD,
            "must_change_password": False})
        if r.status_code != 201:
            raise RuntimeError(f"user create {r.status_code} {r.text[:120]}")
        g = _GiteaHTTP()
        g.login(self.user)
        g.s.get(BASE + "/user/settings/security")
        csrf = g.csrf_cookie()
        r = g.s.post(BASE + "/user/settings/security/webauthn/request_register",
                     data={"name": f"k{os.urandom(3).hex()}"}, headers={"X-Csrf-Token": csrf}, allow_redirects=False)
        r.raise_for_status()
        opts = r.json()["publicKey"]
        self.auth = SoftAuthenticator(rp_id="localhost")
        att = self.auth.make_registration_resident(b64u_dec(opts["challenge"]), BASE,
                                                   user_handle=b64u_dec(opts["user"]["id"]), be=be, bs=bs)
        r = g.s.post(BASE + "/user/settings/security/webauthn/register", data=json.dumps(att),
                     headers={"Content-Type": "application/json", "X-Csrf-Token": csrf}, allow_redirects=False)
        if r.status_code >= 400:
            raise RuntimeError(f"register failed {r.status_code}: {r.text[:200]}")
        self.other = SoftAuthenticator(rp_id="localhost")
        self._other_counter = 0
        self.account_id = self.user

    def _attempt(self, signer, be, bs, counter, valid=True, uv=True):
        g = _GiteaHTTP()
        r = g.login(self.user)
        if r.status_code >= 500:
            return ERROR, f"password step {r.status_code}"
        loc = r.headers.get("location", "")
        if r.status_code not in (302, 303) or ("two_factor" not in loc and "webauthn" not in loc):
            return BLOCKED_PRE, f"password step {r.status_code} -> {loc}"
        o = g.s.get(BASE + "/user/webauthn/assertion")
        if o.status_code != 200:
            return ERROR, f"assertion options {o.status_code}"
        opts = o.json()["publicKey"]
        a = signer.make_assertion(b64u_dec(opts["challenge"]), BASE, be=be, bs=bs, counter=counter,
                                  valid_signature=valid, uv=uv)
        rr = g.s.post(BASE + "/user/webauthn/assertion", data=json.dumps(a),
                      headers={"Content-Type": "application/json", "X-Csrf-Token": g.csrf_cookie()},
                      allow_redirects=False)
        if rr.status_code == 200 and "redirect" in rr.text:
            return ACCEPT, "200 redirect"
        if rr.status_code in (400, 401, 403):
            return REJECT, f"{rr.status_code}"
        return ERROR, f"{rr.status_code} {rr.text[:120]}"

    def _valid(self, be, bs, uv, counter):
        return self._attempt(self.auth, be, bs, counter, valid=True, uv=uv)

    def _forged(self, be, bs, counter):
        return self._attempt(self.auth, be, bs, counter, valid=False)

    def _wrong_cred(self, be, bs):
        self._other_counter += 1
        return self._attempt(self.other, be, bs, self._other_counter, valid=True)


class GiteaTarget(RealTarget):
    session_class = GiteaSession
