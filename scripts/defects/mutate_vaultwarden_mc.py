import sys
from pathlib import Path

TARGET = "src/api/core/two_factor/webauthn.rs"
MARKER = "    let authentication_result = WEBAUTHN.finish_passkey_authentication(&rsp, &state)?;\n"
BLOCK = """    // FAILSAFE mutation M_C (docs/round4_plan.md 3): persist the UNVERIFIED signCount before verification.
    // `state` and in-memory `registrations` are untouched; only a serialized copy is changed and saved.
    if let Some(ad) = rsp.response.authenticator_data.get(33..37) {
        let mc_count = u32::from_be_bytes([ad[0], ad[1], ad[2], ad[3]]);
        let mut mc_regs: Vec<WebauthnRegistration> = serde_json::from_str(&serde_json::to_string(&registrations)?)?;
        let mut mc_changed = false;
        for reg in &mut mc_regs {
            if ct_eq(reg.credential.cred_id().as_slice(), rsp.raw_id.as_slice()) {
                let mut cred: Credential = reg.credential.clone().into();
                if mc_count > cred.counter {
                    cred.counter = mc_count;
                    reg.credential = cred.into();
                    mc_changed = true;
                }
                break;
            }
        }
        if mc_changed {
            TwoFactor::new(user_id.clone(), TwoFactorType::Webauthn, serde_json::to_string(&mc_regs)?).save(conn).await?;
        }
    }

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
