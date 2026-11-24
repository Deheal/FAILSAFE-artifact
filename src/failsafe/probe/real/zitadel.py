from __future__ import annotations

from ...simulator.rp_model import ACCEPT, BLOCKED_PRE, ERROR, REJECT
from .base import RealSession, RealTarget

from authenticator import SoftAuthenticator
import zitadel_oracle as zo


class ZitadelSession(RealSession):
    def __init__(self, victim, url: str = ""):
        self._z = zo.ZClient()
        super().__init__(victim)

    def _register(self, be, bs):
        self.name, self.auth = self._z.create_user(be, bs)
        self.other = SoftAuthenticator(rp_id=zo.RP_ID)
        self.other.cred_id = self.auth.cred_id
        self._other_counter = 0
        self.account_id = self.name

    def _attempt(self, signer, be, bs, counter, valid, uv=True):
        s = signer if valid else zo.signer_for(signer, False)

        def build(challenge: bytes) -> dict:
            return s.make_assertion(challenge, zo.ORIGIN, be=be, bs=bs, counter=counter,
                                    valid_signature=valid, rp_id=zo.RP_ID, uv=uv)
        try:
            sess = self._z.new_session(self.name)
            opts = sess["challenges"]["webAuthN"]["publicKeyCredentialRequestOptions"]["publicKey"]
            rp = self._z.call("PATCH", f"/v2/sessions/{sess['sessionId']}", {
                "sessionToken": sess["sessionToken"],
                "checks": {"webAuthN": {"credentialAssertionData": build(zo._b64u_decode(opts["challenge"]))}}})
            code, body = rp.status_code, rp.text
        except Exception as exc:
            return ERROR, f"{type(exc).__name__}: {exc}"
        if code == 200:
            return ACCEPT, "200"
        if code in (400, 401, 403):
            return REJECT, f"{code} {body[:120]}"
        if code == 500 and "WEBAU" in body:
            return REJECT, f"500 {body[:120]}"
        if code < 500:
            return BLOCKED_PRE, f"{code} {body[:120]}"
        return ERROR, f"{code} {body[:120]}"

    def _valid(self, be, bs, uv, counter):
        return self._attempt(self.auth, be, bs, counter, True, uv=uv)

    def _forged(self, be, bs, counter):
        return self._attempt(self.auth, be, bs, counter, False)

    def _wrong_cred(self, be, bs):
        self._other_counter += 1
        return self._attempt(self.other, be, bs, self._other_counter, True)


class ZitadelTarget(RealTarget):
    session_class = ZitadelSession
