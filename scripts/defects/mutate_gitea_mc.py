import sys
from pathlib import Path

TARGET = "routers/web/auth/webauthn.go"
MARKER = "\tcred, err := wa.WebAuthn.ValidateLogin(webAuthnUser, *sessionData, parsedResponse)\n"
BLOCK = """\t// FAILSAFE mutation M_C (docs/round4_plan.md 3): persist the UNVERIFIED signCount before validation.
\t// webAuthnUser above was built from the stored credentials before this write.
\tif mcCred, mcErr := auth.GetWebAuthnCredentialByCredID(ctx, user.ID, parsedResponse.RawID); mcErr == nil {
\t\tif n := parsedResponse.Response.AuthenticatorData.Counter; n > mcCred.SignCount {
\t\t\tmcCred.SignCount = n
\t\t\tif mcErr = mcCred.UpdateSignCount(ctx); mcErr != nil {
\t\t\t\tlog.Error("M_C: failed to persist sign count: %v", mcErr)
\t\t\t}
\t\t}
\t}

"""


def main(root: str) -> None:
    f = Path(root) / TARGET
    src = f.read_text(encoding="utf-8")
    assert src.count(MARKER) == 1, "검증 호출 위치가 하나가 아님"
    assert "FAILSAFE mutation M_C" not in src, "이미 적용됨"
    f.write_text(src.replace(MARKER, BLOCK + MARKER), encoding="utf-8")
    print(f"M_C applied: {f}")


if __name__ == "__main__":
    main(sys.argv[1])
