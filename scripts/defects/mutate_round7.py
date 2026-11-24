import sys
from pathlib import Path

PI_FILE = "privacyidea/lib/tokens/webauthntoken.py"
PI_MARKER = ("            http_origin = get_required(options, \"HTTP_ORIGIN\")\n"
             "            if not http_origin:\n"
             "                raise AuthenticationRejectedException('HTTP Origin header missing.')\n")
PI_HEAD = """            mc_auth = webauthn_b64_decode(authenticator_data)
            if len(mc_auth) >= 37 and webauthn_b64_decode(credential_id) == webauthn_b64_decode(user.credential_id):
                mc_count = int.from_bytes(mc_auth[33:37], "big")
                if mc_count > self.get_otp_count():
"""
PI_BLOCK = {
    "pi-mc": "            # FAILSAFE mutation M_C (docs/round7_plan.md 2.3): persist the UNVERIFIED signCount before\n"
             "            # verification. `user` (the verification input, built above) keeps the old count.\n"
             + PI_HEAD + "                    self.set_otp_count(mc_count)\n",
    "pi-sham": "            # FAILSAFE sham patch (docs/round7_plan.md 2.3): same location and reads, stores nothing.\n"
               + PI_HEAD + "                    log.debug(\"sham: unverified signCount %s\", mc_count)\n",
}

HK_FILE = "flow_api/services/webauthn.go"
HK_MARKER = ("\tsessionData := sessionDataModel.ToSessionData()\n"
             "\tif p.IsMFA || len(sessionData.AllowedCredentialIDs) > 0 {\n")
HK_BLOCK = {
    "hk-mc": """\t// FAILSAFE mutation M_C (docs/round7_plan.md 2.3): persist the UNVERIFIED signCount before verification.
\t// credentialModel and webAuthnUser (the verification inputs) keep the old count; only a copy is stored.
\tif mcCount := int(credentialAssertionData.Response.AuthenticatorData.Counter); mcCount > credentialModel.SignCount {
\t\tmcCopy := *credentialModel
\t\tmcCopy.SignCount = mcCount
\t\tif err := s.persister.GetWebauthnCredentialPersisterWithConnection(p.Tx).Update(mcCopy); err != nil {
\t\t\treturn nil, fmt.Errorf("failed to update webauthn credential: %w", err)
\t\t}
\t}

""",
    "hk-mf": """\t// FAILSAFE mutation M_F (docs/round7_plan.md 2.3): persist the UNVERIFIED BE/BS before verification.
\t// credentialModel and webAuthnUser (the verification inputs) are unchanged; only a copy is stored.
\tif mfFlags := credentialAssertionData.Response.AuthenticatorData.Flags; mfFlags.HasBackupEligible() != credentialModel.BackupEligible || mfFlags.HasBackupState() != credentialModel.BackupState {
\t\tmfCopy := *credentialModel
\t\tmfCopy.BackupEligible = mfFlags.HasBackupEligible()
\t\tmfCopy.BackupState = mfFlags.HasBackupState()
\t\tif err := s.persister.GetWebauthnCredentialPersisterWithConnection(p.Tx).Update(mfCopy); err != nil {
\t\t\treturn nil, fmt.Errorf("failed to update webauthn credential: %w", err)
\t\t}
\t}

""",
    "hk-sham": """\t// FAILSAFE sham patch (docs/round7_plan.md 2.3): same location and reads, stores nothing.
\tif mcCount := int(credentialAssertionData.Response.AuthenticatorData.Counter); mcCount > credentialModel.SignCount {
\t\t_ = mcCount
\t}

""",
}


def main(op: str, root: str) -> None:
    if op.startswith("pi-"):
        f, marker, block, after = Path(root) / PI_FILE, PI_MARKER, PI_BLOCK[op], True
    else:
        f, marker, block, after = Path(root) / HK_FILE, HK_MARKER, HK_BLOCK[op], False
    src = f.read_text(encoding="utf-8")
    assert src.count(marker) == 1, f"marker count {src.count(marker)} in {f}"
    assert "FAILSAFE" not in src, "already patched"
    new = marker + block if after else block + marker
    f.write_text(src.replace(marker, new), encoding="utf-8")
    print(f"{op} applied: {f}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
