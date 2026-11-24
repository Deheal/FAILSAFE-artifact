import sys
from pathlib import Path

TARGET = "internal/handlers/handler_sign_webauthn.go"
MARKER = "\tif c, err = w.ValidateLogin(user, *userSession.WebAuthn.SessionData, response); err != nil {\n"
BLOCK = """\t// FAILSAFE mutation M_C (docs/round4_plan.md 3): persist the UNVERIFIED signCount before validation.
\t// Validation still uses the in-memory credential (value before the write).
\tfor i := range user.Credentials {
\t\tif bytes.Equal(user.Credentials[i].KID.Bytes(), response.RawID) {
\t\t\tif n := response.Response.AuthenticatorData.Counter; n > user.Credentials[i].SignCount {
\t\t\t\tmc := user.Credentials[i]
\t\t\t\tmc.SignCount = n
\t\t\t\tif err = ctx.Providers.StorageProvider.UpdateWebAuthnCredentialSignIn(ctx, mc); err != nil {
\t\t\t\t\tctx.Logger.WithError(err).Error("M_C: failed to persist sign count")
\t\t\t\t}
\t\t\t}

\t\t\tbreak
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
