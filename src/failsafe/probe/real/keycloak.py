from __future__ import annotations

import os
import re

from ...simulator.rp_model import ACCEPT, BLOCKED_PRE, ERROR, REJECT
from .base import RealSession, RealTarget

import json
from base64 import b64decode

import requests

from authenticator import SoftAuthenticator
from kc_setup import KC as KC_ADMIN, admin_token, create_user

KC = "http://localhost:8400"
REALM = "repro"
PASSWORD = "Repro-Pass-123"


def b64u_dec(s):
    s = s.replace("-", "+").replace("_", "/")
    return b64decode(s + "=" * (-len(s) % 4))


def arm_webauthn(username):
    t = admin_token()
    h = {"Authorization": f"Bearer {t}", "Content-Type": "application/json"}
    u = requests.get(f"{KC_ADMIN}/admin/realms/{REALM}/users?username={username}&exact=true", headers=h).json()[0]
    r = requests.put(f"{KC_ADMIN}/admin/realms/{REALM}/users/{u['id']}", headers=h,
                     data=json.dumps({"requiredActions": ["webauthn-register"]}))
    r.raise_for_status()
    return u["id"]


class _InsecureJar(requests.cookies.RequestsCookieJar):
    def set_cookie(self, cookie, *a, **k):
        cookie.secure = False
        return super().set_cookie(cookie, *a, **k)


class KCSession:
    def __init__(self):
        self.s = requests.Session()
        self.s.cookies = _InsecureJar()
        self.origin = KC

    def _auth_url(self):
        return (f"{KC}/realms/{REALM}/protocol/openid-connect/auth?client_id=web"
                f"&redirect_uri=http://localhost:8400/&response_type=code&scope=openid")

    def password_step(self, username):
        r = self.s.get(self._auth_url())
        action = re.search(r'<form[^>]+action="([^"]+)"', r.text).group(1).replace("&amp;", "&")
        return self.s.post(action, data={"username": username, "password": PASSWORD, "credentialId": ""},
                           allow_redirects=True)


def _form_action(text):
    return re.search(r'<form[^>]+action="([^"]+)"', text).group(1).replace("&amp;", "&")


def _challenge(text):
    return b64u_dec(re.search(r'challenge["\']?\s*[:=]\s*["\']([^"\']+)', text).group(1))


class KeycloakSession(RealSession):
    def __init__(self, victim, url: str = ""):
        super().__init__(victim)

    def _register(self, be, bs):
        self.user = f"psm{os.urandom(5).hex()}"
        create_user(admin_token(), self.user)
        arm_webauthn(self.user)
        g = KCSession()
        r = g.password_step(self.user)
        uid = re.search(r'userid["\']?\s*[:=]\s*["\']([^"\']+)', r.text)
        self.auth = SoftAuthenticator(rp_id="localhost")
        att = self.auth.make_registration_resident(_challenge(r.text), g.origin,
                                                   user_handle=b64u_dec(uid.group(1)) if uid else b"uh",
                                                   be=be, bs=bs)
        resp = att["response"]
        rr = g.s.post(_form_action(r.text), data={
            "clientDataJSON": resp["clientDataJSON"], "attestationObject": resp["attestationObject"],
            "publicKeyCredentialId": att["id"], "authenticatorLabel": "softkey", "transports": "usb"},
            allow_redirects=False)
        if not (rr.status_code in (302, 303) and "code=" in rr.headers.get("location", "")):
            raise RuntimeError(f"registration failed {rr.status_code}")
        self.other = SoftAuthenticator(rp_id="localhost")
        self._other_counter = 0
        self.account_id = self.user

    def _attempt(self, signer, be, bs, counter, valid=True, uv=True):
        g = KCSession()
        r = g.password_step(self.user)
        if r.status_code >= 500:
            return ERROR, f"password step {r.status_code}"
        if "challenge" not in r.text:
            return BLOCKED_PRE, "no webauthn challenge after password step"
        a = signer.make_assertion(_challenge(r.text), g.origin, be=be, bs=bs, counter=counter,
                                  valid_signature=valid, uv=uv, user_handle=b"")
        resp = a["response"]
        rr = g.s.post(_form_action(r.text), data={
            "clientDataJSON": resp["clientDataJSON"], "authenticatorData": resp["authenticatorData"],
            "signature": resp["signature"], "credentialId": a["id"], "userHandle": "", "authn_use_chk": ""},
            allow_redirects=False)
        if rr.status_code in (302, 303) and "code=" in rr.headers.get("location", ""):
            return ACCEPT, "302 code"
        if rr.status_code < 500:
            return REJECT, f"{rr.status_code}"
        return ERROR, f"{rr.status_code}"

    def _valid(self, be, bs, uv, counter):
        return self._attempt(self.auth, be, bs, counter, valid=True, uv=uv)

    def _forged(self, be, bs, counter):
        return self._attempt(self.auth, be, bs, counter, valid=False)

    def _wrong_cred(self, be, bs):
        self._other_counter += 1
        return self._attempt(self.other, be, bs, self._other_counter, valid=True)


class KeycloakTarget(RealTarget):
    session_class = KeycloakSession
