WEBAUTHN_RS = "webauthn-rs-core 0.5.4 src/core.rs"
VW = "vaultwarden {v} src/api/core/two_factor/webauthn.rs"

_VW_COMMON = {
    "check_uv": (0, [f"{VW.format(v='1.35.4')}:391,397 인증 정책 discouraged",
                     f"{VW.format(v='1.35.4')}:152,162 등록 정책 discouraged",
                     f"{WEBAUTHN_RS}:853-871 (Discouraged, Discouraged)이면 UV 검사 없음"]),
    "check_bebs": (1, [f"{WEBAUTHN_RS}:893-896 BS=1인데 저장 BE=0이면 CredentialMayNotBeHardwareBound",
                       f"{VW.format(v='1.35.4')}:485 요청 BE=0이면 저장값 갱신 안 함 → BE=0·BS=1 요청은 거부"]),
    "check_signcount": (1, [f"{WEBAUTHN_RS}:215 require_valid_counter_value 기본 true",
                            f"{WEBAUTHN_RS}:1155-1173 counter <= 저장값이면 CredentialPossibleCompromise",
                            "거부 시 update_credential에 도달하지 않음 → 저장 상태 불변(지속 차단 없음)"]),
    "count_normal": (0, ["vaultwarden src/api/identity.rs:177,321,534 로그인 제한은 IP 기준 rate limiter뿐, 계정 잠금 없음",
                         "시험 환경: LOGIN_RATELIMIT_MAX_BURST를 크게 설정(θ와 무관한 IP 제한을 끔)"]),
    "count_tamper": (0, ["위와 같음: 2단계 인증 실패는 이벤트 기록(UserFailedLogIn2fa)만 하고 잠그지 않음"]),
    "revoke_on_tamper": (0, ["webauthn.rs:417-463 실패 시 자격증명 삭제·비활성화 경로 없음"]),
}

GROUND_TRUTH = {
    "vaultwarden-1.35.4": {
        "written": "2026-11-12 (프로브 실행 전)",
        "theta": {"verify_before_store": 0, **{d: v for d, (v, _) in _VW_COMMON.items()}},
        "evidence": {
            "verify_before_store": [
                f"{VW.format(v='1.35.4')}:441 check_and_update_backup_eligible을 443 finish_passkey_authentication(서명 검증) 전에 호출",
                f"{VW.format(v='1.35.4')}:485-498 요청 BE=1이면 BE/BS를 저장값에 반영하고 DB에 저장(.save)",
                "CVE-2026-31835",
            ],
            **{d: e for d, (_, e) in _VW_COMMON.items()},
        },
        "q2": "state_corruption",
        "model_deviations": [],
        "flag_policy": f"{WEBAUTHN_RS}:879-888 BE 변화 거부(업그레이드 허용 기본 false) + VW가 BE=1 요청이면 먼저 저장 → "
                       "실질적으로 BE 0→1 허용, BE 1→0 거부, BS 변화 허용 = 모델 상수(Vaultwarden형)와 같음",
    },
    "vaultwarden-1.35.5": {
        "written": "2026-11-12 (프로브 실행 전)",
        "theta": {"verify_before_store": 1, **{d: v for d, (v, _) in _VW_COMMON.items()}},
        "evidence": {
            "verify_before_store": [
                f"{VW.format(v='1.35.5')}:441 check_and_update_backup_eligible이 DB 저장 없이 플래그 변경 여부만 반환",
                f"{VW.format(v='1.35.5')}:449-450 서명 검증(finish_passkey_authentication) 성공 뒤에만 저장",
            ],
            **{d: e for d, (_, e) in _VW_COMMON.items()},
        },
        "q2": "normal_policy",
        "model_deviations": [],
    },
}

GOWA = "go-webauthn/webauthn v0.18.1 webauthn/login.go"
AUH = "authelia v4.39.28 internal/handlers/handler_sign_webauthn.go"

GROUND_TRUTH["authelia-4.39.28"] = {
    "written": "2026-11-12 (프로브 실행 전)",
    "instance": "regulation 사실상 끔(max_retries 100000), webauthn 설정 기본값",
    "theta": {"verify_before_store": 1, "check_uv": 0, "check_bebs": 1, "check_signcount": 1,
              "count_normal": 0, "count_tamper": 0, "revoke_on_tamper": 0},
    "evidence": {
        "verify_before_store": [f"{GOWA}:384 서명 검증(Verify)이 403 카운터 갱신보다 먼저",
                                f"{AUH}:210-211 ValidateLogin 실패 시 저장 없이 반환, 235 저장은 검증 성공 뒤"],
        "check_uv": ["authelia internal/configuration/schema/webauthn.go:51 user_verification 기본 preferred",
                     f"{GOWA}:371 required일 때만 UV 검사"],
        "check_bebs": [f"{GOWA}:398 BE=0·BS=1이면 거부"],
        "check_signcount": ["go-webauthn webauthn/authenticator.go:59-66 counter <= 저장값이면 CloneWarning",
                            f"{AUH}:235 CloneWarning을 저장한 뒤 257에서 거부"],
        "count_normal": ["authelia internal/regulation/regulator.go:59 1차 인증(1FA) 실패만 집계",
                         f"{GOWA}:309-320 등록되지 않은 자격증명 거부"],
        "count_tamper": ["위와 같음(WebAuthn 실패는 regulation 대상 아님)"],
        "revoke_on_tamper": [f"{AUH}:133-275 실패 시 자격증명 삭제 경로 없음"],
    },
    "q2": "normal_policy",
    "model_deviations": [
        "복제 의심 지속 차단(8.2절 test): CloneWarning이 저장되고 이후 갱신에서 풀리지 않음(authenticator.go:59-66은 "
        "CloneWarning을 다시 false로 만들지 않음) → P_SC_DEC 뒤 정상 인증이 W 후에도 거부될 것으로 예상",
        f"BE 변화 양방향 거부({GOWA}:393) — 모델 상수(BE 0→1 허용)와 다르나, 기기 종속 사용자 + 검증 후 저장이면 "
        "저장 플래그가 바뀌지 않아 프로브에서 드러나지 않음",
    ],
}

KCS = "keycloak 26.0.7 services/src/main/java/org/keycloak"
W4J = "webauthn4j-core 0.21.5 com/webauthn4j/validator/AuthenticationDataValidator.java"
_KC_COMMON = {
    "verify_before_store": (1, [f"{KCS}/credential/WebAuthnCredentialProvider.java:197-225 검증(validate) 성공 뒤에만 "
                                "카운터 갱신, BE/BS는 저장하지 않음"]),
    "check_uv": (0, [f"{KCS}/authentication/authenticators/browser/WebAuthnAuthenticator.java:194 정책이 required일 때만 UV 검사",
                     "realm webAuthnPolicyUserVerificationRequirement = discouraged (kc_setup.py, 실행 전 관리자 API로 확인)"]),
    "check_bebs": (0, [f"{W4J} BE/BS 관련 검사 없음(0.21.5 validator 패키지에 isFlagBE/isFlagBS 사용처 없음)"]),
    "check_signcount": (0, [f"{W4J}:199-218 presented <= stored이면 거부하지만,",
                            f"{KCS}/credential/WebAuthnCredentialProvider.java:223-225 저장 카운터가 0이면 갱신하지 않음 "
                            "→ 등록 카운터 0인 자격증명은 저장 카운터가 계속 0 → 역행 요청(1)도 통과"]),
    "revoke_on_tamper": (0, ["실패 시 자격증명 삭제 경로 없음 (permanentLockout=false)"]),
}

GROUND_TRUTH["keycloak-26.0.7-bf_on"] = {
    "written": "2026-11-12 (프로브 실행 전)",
    "instance": "bruteForceProtected=true, failureFactor=3, waitIncrement=60, maxFailureWait=60, maxDeltaTime=600, "
                "permanentLockout=false, quickLoginCheckMilliSeconds=1",
    "theta": {**{d: v for d, (v, _) in _KC_COMMON.items()}, "count_normal": 0, "count_tamper": 1},
    "corrections": [{
        "date": "2026-11-12",
        "dimension": "count_normal",
        "original": 1,
        "corrected": 0,
        "found_by": "스모크 실행(1회, 평가 제외)에서 P_WRONG_CRED 뒤 잠금이 없음을 관측",
        "verified_by": "화이트박스 — 관리자 API attack-detection: 미등록 자격증명 3회 후 numFailures=0, "
                       "서명 무효 3회 후 numFailures=3·잠금. 소스: WebAuthnAuthenticator.java:235-236 "
                       "isValid=false이면 failure 뒤 cancelLogin(), AuthenticationProcessor.java:644-653 cancelLogin이 "
                       "forceChallenge로 상태를 FAILED에서 FORCE_CHALLENGE로 덮음 → DefaultAuthenticationFlow.java:510-512 "
                       "logFailure 경로를 타지 않음. 처음 정답표는 cancelLogin을 놓쳤다.",
        "note": "Q2 정답(normal_policy)은 바뀌지 않음. 결과는 원래 정답과 수정 정답 모두로 보고한다.",
    }],
    "evidence": {
        **{d: e for d, (_, e) in _KC_COMMON.items()},
        "count_normal": [f"{KCS}/authentication/authenticators/browser/WebAuthnAuthenticator.java:235-236 미등록 자격증명 → "
                         "failure 뒤 cancelLogin()",
                         f"{KCS}/authentication/AuthenticationProcessor.java:644-653 cancelLogin → forceChallenge(상태 덮어씀)",
                         "→ 집계 안 됨(관리자 API numFailures=0으로 확인)"],
        "count_tamper": [f"{KCS}/authentication/authenticators/browser/WebAuthnAuthenticator.java:219,304 검증 예외 → failure"
                         "(cancelLogin 없음)",
                         f"{KCS}/authentication/DefaultAuthenticationFlow.java:510-512 FAILED → logFailure",
                         f"{KCS}/services/managers/DefaultBruteForceProtector.java:68-125 3회째 실패에 60초 잠금",
                         "관리자 API로 확인: 서명 무효 3회 후 numFailures=3, 잠금"],
    },
    "q2": "normal_policy",
    "model_deviations": ["잠금 중 로그인 시도도 실패로 세어 잠금이 연장될 수 있음(60초씩). W=120초 > 마지막 시도 후 60초라 "
                         "W 안에 풀리는 것은 같음", "잠금은 1차 인증(비밀번호) 단계에서 드러남(BLOCKED_PRE, 추론에서는 REJECT)"],
}

GROUND_TRUTH["keycloak-26.0.7-bf_off"] = {
    "written": "2026-11-12 (프로브 실행 전)",
    "instance": "bruteForceProtected=false",
    "theta": {**{d: v for d, (v, _) in _KC_COMMON.items()}, "count_normal": 0, "count_tamper": 0},
    "evidence": {**{d: e for d, (_, e) in _KC_COMMON.items()},
                 "count_normal": [f"{KCS}/authentication/AuthenticationProcessor.java:719-724 무차별 대입 보호가 꺼져 있으면 집계 안 함"],
                 "count_tamper": ["위와 같음"]},
    "q2": "normal_policy",
    "model_deviations": [],
}

GT_GITEA = "gitea v1.24.0"
GOWA12 = "go-webauthn/webauthn v0.12.3 webauthn/login.go"
GROUND_TRUTH["gitea-1.24.0"] = {
    "written": "2026-11-12 (프로브 실행 전)",
    "instance": "내장 sqlite, 계정 잠금 기능 없음(기본)",
    "theta": {"verify_before_store": 1, "check_uv": 0, "check_bebs": 1, "check_signcount": 1,
              "count_normal": 0, "count_tamper": 0, "revoke_on_tamper": 0},
    "evidence": {
        "verify_before_store": [f"{GT_GITEA} routers/web/auth/webauthn.go:235-241 ValidateLogin 실패 시 저장 없이 403",
                                f"{GT_GITEA} models/auth/webauthn.go:69-73 성공 뒤 sign_count 열만 갱신, BE/BS는 저장하지 않음"],
        "check_uv": [f"{GT_GITEA} modules/auth/webauthn/webauthn.go:35 VerificationDiscouraged", f"{GOWA12}:359"],
        "check_bebs": [f"{GOWA12}:382 요청 BE=0·BS=1이면 거부 (요청만 보는 검사)"],
        "check_signcount": ["go-webauthn v0.12.3 webauthn/authenticator.go:51-56 counter <= 저장값이면 CloneWarning",
                            f"{GT_GITEA} routers/web/auth/webauthn.go:245-249 CloneWarning이면 403, 저장 없이 반환 → 지속 차단 없음"],
        "count_normal": [f"{GT_GITEA} routers/web/auth/webauthn.go:208-285 실패 시 403만, 잠금·집계 없음"],
        "count_tamper": ["위와 같음"],
        "revoke_on_tamper": ["실패 시 자격증명 삭제 경로 없음"],
    },
    "q2": "normal_policy",
    "model_deviations": [
        f"{GT_GITEA} models/auth/webauthn.go:108-130 저장 플래그 대신 요청의 플래그로 자격증명을 만듦(\"Gitea doesn't store or "
        "check the flags\") → BE 일관성 검사(login.go:377)가 사실상 꺼짐. 모델 상수(BE 1→0 거부)와 다르나, 검증 후 저장 + "
        "기기 종속 사용자에서는 저장 플래그 변화가 없어 프로브에서 드러나지 않음",
    ],
}

AKS = "authentik 2024.10.5 /authentik/stages/authenticator_validate/challenge.py"
PYW = "py_webauthn 2.2.0 webauthn"
GROUND_TRUTH["authentik-2024.10.5"] = {
    "written": "2026-11-12 (프로브 실행 전)",
    "instance": "docker 기본 흐름(default-authentication-flow): 식별 → 비밀번호 → MFA 검증(webauthn uv=preferred) → 로그인. "
                "관리자 API로 확인: 평판(reputation) 정책 0개, 흐름 정책 바인딩 없음",
    "theta": {"verify_before_store": 1, "check_uv": 0, "check_bebs": 1, "check_signcount": 1,
              "count_normal": 0, "count_tamper": 0, "revoke_on_tamper": 0},
    "evidence": {
        "verify_before_store": [f"{AKS}:167-191 verify_authentication_response 성공 뒤에만 set_sign_count, BE/BS는 저장 안 함"],
        "check_uv": [f"{AKS}:175 stage가 required일 때만 UV 요구; 설정값 preferred(관리자 API)"],
        "check_bebs": [f"{PYW}/helpers/parse_backup_flags.py:26-29 BE=0·BS=1이면 InvalidBackupFlags(서명 검증 뒤)",
                       f"{PYW}/helpers/exceptions.py:65 InvalidAuthenticationResponse가 아니라 challenge.py:177에서 잡히지 않음 → "
                       "authentik/flows/views/executor.py:230-241 FlowErrorChallenge(로그인 실패 화면). 어댑터는 이를 REJECT로 기록(사전 정의)"],
        "check_signcount": [f"{PYW}/authentication/verify_authentication_response.py:147-154 counter <= 저장값이면 거부, 저장 없음"],
        "count_normal": [f"{AKS}:143-145 미등록 자격증명 → ValidationError(login_failed 신호 없음), 잠금 기능 없음"],
        "count_tamper": [f"{AKS}:177-188 login_failed 신호는 평판 점수만 바꿈; 평판 정책이 없어 차단 없음"],
        "revoke_on_tamper": ["실패 시 장치 삭제 경로 없음"],
    },
    "q2": "normal_policy",
    "model_deviations": ["BE=0·BS=1 요청이 일반 거부가 아니라 처리되지 않은 예외(흐름 오류 화면)로 끝남 — 외부 기호는 REJECT"],
}
MODEL_PREDICTED_OUTPUT_EXTRA = {"authentik-2024.10.5": {"q2": "normal_policy",
                                                        "decided": {"verify_before_store": 1, "revoke_on_tamper": 0}}}


MODEL_PREDICTED_OUTPUT = {
    "vaultwarden-1.35.4": {"q2": "state_corruption", "decided": {"verify_before_store": 0, "revoke_on_tamper": 0}},
    "vaultwarden-1.35.5": {"q2": "normal_policy", "decided": {"verify_before_store": 1, "revoke_on_tamper": 0}},
    "authelia-4.39.28": {"q2": "normal_policy", "decided": {"verify_before_store": 1, "revoke_on_tamper": 0}},
    "keycloak-26.0.7-bf_on": {"q2": "normal_policy", "decided": {"verify_before_store": 1, "revoke_on_tamper": 0}},
    "keycloak-26.0.7-bf_off": {"q2": "normal_policy", "decided": {"verify_before_store": 1, "revoke_on_tamper": 0}},
    "gitea-1.24.0": {"q2": "normal_policy", "decided": {"verify_before_store": 1, "revoke_on_tamper": 0}},
}

MODEL_PREDICTED_OUTPUT.update(MODEL_PREDICTED_OUTPUT_EXTRA)

import copy as _copy

GROUND_TRUTH["authelia-src-4.39.28"] = _copy.deepcopy(GROUND_TRUTH["authelia-4.39.28"])
GROUND_TRUTH["authelia-src-4.39.28"]["written"] = "2026-11-12 (빌드 후, 프로브 전)"
GROUND_TRUTH["authelia-src-4.39.28"]["instance"] = ("같은 소스(v4.39.28)를 go1.27.1로 변이 없이 빌드(빌드 대조). "
                                                    "설정은 afs-psm과 같음(:9096)")

GROUND_TRUTH["authelia-fs1-4.39.28"] = _copy.deepcopy(GROUND_TRUTH["authelia-4.39.28"])
GROUND_TRUTH["authelia-fs1-4.39.28"].update({
    "written": "2026-11-12 (빌드 후, 프로브 전)",
    "instance": "같은 소스 + FS-1 변이(scripts/defects/authelia_fs1.patch), 설정은 afs-psm과 같음(:9097)",
    "q2": "state_corruption",
})
GROUND_TRUTH["authelia-fs1-4.39.28"]["theta"]["verify_before_store"] = 0
GROUND_TRUTH["authelia-fs1-4.39.28"]["evidence"]["verify_before_store"] = [
    "FS-1 변이: handler_sign_webauthn.go ValidateLogin(210행) 직전에 요청 BE=1이면 BE/BS를 저장값에 반영하고 "
    "UpdateWebAuthnCredentialSignIn으로 DB에 저장(sql_provider_queries.go:213-219가 backup_eligible·backup_state 저장)",
    "이후 정상 사용자(BE=0)는 go-webauthn login.go:393(BE 변화 거부)으로 막힘",
]
MODEL_PREDICTED_OUTPUT["authelia-src-4.39.28"] = MODEL_PREDICTED_OUTPUT["authelia-4.39.28"]
MODEL_PREDICTED_OUTPUT["authelia-fs1-4.39.28"] = {"q2": "state_corruption",
                                                  "decided": {"verify_before_store": 0, "revoke_on_tamper": 0}}

import copy as _copy2

GROUND_TRUTH["authentik-fs2-2024.10.5"] = _copy2.deepcopy(GROUND_TRUTH["authentik-2024.10.5"])
GROUND_TRUTH["authentik-fs2-2024.10.5"].update({
    "written": "2026-11-12 (FS-2 주입 후, 본 측정 전)",
    "instance": "authentik-2024.10.5 + FS-2 변이(scripts/defects/authentik_fs2.py): 검증 전 카운터 저장",
    "q2": "state_corruption",
})
GROUND_TRUTH["authentik-fs2-2024.10.5"]["theta"]["store_counter_before_verify"] = 1
GROUND_TRUTH["authentik-fs2-2024.10.5"]["evidence"]["store_counter_before_verify"] = [
    "FS-2 변이: challenge.py verify_authentication_response 직전에 요청 signCount가 device.sign_count보다 크면 "
    "device.set_sign_count(요청값)을 먼저 저장(검증 비교는 옛값으로). OpenOptOut PR #123 회귀와 같은 패턴",
    "이후 정상 사용자의 낮은 카운터는 py_webauthn verify_authentication_response.py:147-154로 거부(복제 의심)",
]
MODEL_PREDICTED_OUTPUT["authentik-fs2-2024.10.5"] = {
    "q2": "state_corruption", "decided": {"store_counter_before_verify": 1, "verify_before_store": 1}}

import copy as _copy3

_SYNCED_NOTE = ("사용자 유형 = 동기화 완료(등록 BE=1·BS=0, 현재 BE=1·BS=1). "
                f"{WEBAUTHN_RS}:879-888 BE 1→0만 거부, BS 변화 허용 → 저장 BE/BS가 위조 요청으로 (1,0)이 돼도 "
                "현재 플래그 (1,1)의 정상 인증은 거부되지 않는다")
for _v in ("1.35.4", "1.35.5"):
    _gt = _copy3.deepcopy(GROUND_TRUTH[f"vaultwarden-{_v}"])
    _gt.update({"written": "2026-11-14 (3차, 프로브 실행 전)", "victim": "동기화 완료",
                "q2_note": _SYNCED_NOTE + (" — 결함은 있으나 이 사용자에게 차단을 만들지 않음" if _v == "1.35.4" else "")})
    GROUND_TRUTH[f"vaultwarden-{_v}-synced"] = _gt

KC26 = "keycloak 26.0.7 lib/lib/main/org.keycloak.keycloak-services-26.0.7.jar DefaultBruteForceProtector (javap로 확인)"
GROUND_TRUTH["keycloak-26.0.7-bf_perm"] = _copy3.deepcopy(GROUND_TRUTH["keycloak-26.0.7-bf_on"])
GROUND_TRUTH["keycloak-26.0.7-bf_perm"].update({
    "written": "2026-11-14 (3차, 프로브 실행 전)",
    "instance": "bf_on 설정 + permanentLockout=true, maxTemporaryLockouts=0",
    "q2": "normal_policy",
    "model_deviations": ["영구 잠금: isPermanentLockout && getMaxTemporaryLockouts()==0 && 실패 >= failureFactor이면 "
                         f"permanentUserLockOut → UserModel.setEnabled(false) ({KC26}). 잠금이 W 안에 풀리지 않음 = 모델 밖(잠금 > W)"],
})

BLOCK_CAUSE_TRUTH = {
    "vaultwarden-1.35.4": "state_corruption",
    "vaultwarden-1.35.5": "no_block",
    "authelia-4.39.28": "normal_policy",
    "authelia-src-4.39.28": "normal_policy",
    "authelia-fs1-4.39.28": "state_corruption",
    "keycloak-26.0.7-bf_on": "normal_policy",
    "keycloak-26.0.7-bf_off": "no_block",
    "gitea-1.24.0": "no_block",
    "authentik-2024.10.5": "no_block",
    "authentik-fs2-2024.10.5": "state_corruption",
    "vaultwarden-1.35.4-synced": "no_block",
    "vaultwarden-1.35.5-synced": "no_block",
    "keycloak-26.0.7-bf_perm": "normal_policy",
}

BLOCK_CAUSE_PREDICTED = {
    **{rp: v for rp, v in BLOCK_CAUSE_TRUTH.items()},
    "authelia-4.39.28": "normal_policy(unmodeled_policy)",
    "authelia-src-4.39.28": "normal_policy(unmodeled_policy)",
}


import copy as _copy4

_MC_NOTE = ("M_C 변이(round4_plan.md 3절): 검증 호출 직전에 요청 signCount가 저장값보다 크면 저장소에만 쓰고 "
            "검증 입력은 그대로 둔다. 저자는 연산자 정의만 고정, 삽입 위치는 '검증 호출 직전'으로 기계적 결정.")

GROUND_TRUTH["authelia-mc-4.39.28"] = {
    "written": "2026-11-14 (4차, 프로브 실행 전)",
    "instance": "afs-src 설정 복사, 포트 9098, M_C 변이 빌드(build/authelia-mc)",
    "theta": {**_copy4.deepcopy(GROUND_TRUTH["authelia-src-4.39.28"]["theta"]), "store_counter_before_verify": 1},
    "evidence": {"store_counter_before_verify": [
        f"{AUH} ValidateLogin 호출 직전에 UpdateWebAuthnCredentialSignIn(사본)으로 요청 카운터 저장 "
        "(scripts/defects/authelia_mc.patch). go-webauthn은 저장된 카운터 역행을 CloneWarning으로 거부."]},
    "q2": "state_corruption",
    "model_deviations": [],
    "mutation": "M_C", "mutation_note": _MC_NOTE,
}

GROUND_TRUTH["vaultwarden-mc-1.35.5"] = {
    "written": "2026-11-14 (4차, 프로브 실행 전)",
    "instance": "1.35.5 소스 + M_C 변이 빌드(build/vw-mc), 포트 8006",
    "theta": {**_copy4.deepcopy(GROUND_TRUTH["vaultwarden-1.35.5"]["theta"]), "store_counter_before_verify": 1},
    "evidence": {"store_counter_before_verify": [
        "validate_webauthn_login의 finish_passkey_authentication 호출 직전에 TwoFactor::new(...).save로 요청 카운터 저장 "
        "(scripts/defects/vaultwarden_mc.patch). webauthn-rs는 저장된 카운터보다 낮은 카운터를 복제 의심으로 거부."]},
    "q2": "state_corruption",
    "model_deviations": [],
    "mutation": "M_C", "mutation_note": _MC_NOTE,
}

GROUND_TRUTH["kanidm-1.12.0"] = {
    "written": "2026-11-14 (4차, 프로브 실행 전)",
    "instance": "kanidm 1.12.0, https://localhost:8443, 주 인증(webauthn-rs)",
    "theta": {"verify_before_store": 1, "store_counter_before_verify": 0,
              "check_uv": 0, "check_bebs": 1, "check_signcount": 1,
              "count_normal": 0, "count_tamper": 0, "revoke_on_tamper": 0},
    "evidence": {
        "check_bebs": ["스모크: 등록 BE/BS와 다른 플래그를 서명 검증 전에 거부('invalid webauthn authentication'). "
                       "어댑터는 피해자 등록 플래그로 등록(round4_plan.md 11절)."],
        "check_signcount": ["스모크: P_SC_DEC(카운터 역행) 거부."],
        "verify_before_store": ["finish_passkey_authentication 성공 뒤 비동기 큐(DelayedAction::WebauthnCounterIncrement)로만 "
                                "카운터 갱신 = 검증 후 저장. 결함 없음."],
    },
    "q2": "normal_policy",
    "model_deviations": [],
}

GROUND_TRUTH["zitadel-4.20.1"] = {
    "written": "2026-11-14 (4차, 프로브 실행 전)",
    "instance": "zitadel 4.20.1, http://localhost:8080, 세션 API v2(go-webauthn). 새 DB zitadel2.",
    "theta": {"verify_before_store": 1, "store_counter_before_verify": 0,
              "check_uv": 1, "check_bebs": 0, "check_signcount": 0,
              "count_normal": 0, "count_tamper": 0, "revoke_on_tamper": 0},
    "evidence": {
        "check_uv": ["스모크: P_UV0(UV=0) 거부."],
        "check_bebs": ["스모크: P_BEBS(BE=0·BS=1) 수락 → BE·BS 미검사."],
        "check_signcount": ["스모크: P_SC_DEC(카운터 역행) 전부 수락 → 카운터 미검사. "
                            "이 때문에 M_C를 넣어도 드러나지 않음(동치 변이, 변이 보류)."],
        "verify_before_store": ["FinishLogin(ValidateLogin) 뒤 WebAuthNChecked로 카운터 이벤트 저장 = 검증 후 저장. 결함 없음."],
    },
    "q2": "normal_policy",
    "model_deviations": [],
}

BLOCK_CAUSE_TRUTH_V4 = {
    "authelia-mc-4.39.28": "state_corruption",
    "vaultwarden-mc-1.35.5": "state_corruption",
    "kanidm-1.12.0": "no_block",
    "zitadel-4.20.1": "no_block",
}
BLOCK_CAUSE_PREDICTED_V4 = dict(BLOCK_CAUSE_TRUTH_V4)

Q3_PREDICTED_V4 = {
    "authelia-mc-4.39.28": "state_corruption",
    "vaultwarden-mc-1.35.5": "state_corruption",
    "kanidm-1.12.0": "undetermined",
    "zitadel-4.20.1": "undetermined",
}

_PI = "privacyidea v3.13.4 privacyidea/lib"
_HK = "hanko backend v3.1.2"
TRUTH_V7_EVIDENCE = {
    "PI-orig": [f"{_PI}/tokens/webauthntoken.py:1220 검증(WebAuthnAssertionResponse.verify) 뒤 set_otp_count = 검증 후 저장.",
                f"{_PI}/tokens/webauthn.py:1728 카운터 역행 거부(검사함). BE·BS는 저장하지 않음.",
                f"{_PI}/tokenclass.py:1030 실패마다 failcount+1, maxfail 기본 10. 어느 프로브도 10회에 이르지 않음 "
                "(성공 시 token.py:2627 이후 초기화) → 차단 없음."],
    "PI-lockP": ["DefaultMaxFailCount=3, failcounter_clear_timeout=0.",
                 f"{_PI}/tokenclass.py:1030·1387 failcount==maxfail이면 이후 정상 응답도 'Failcounter exceeded'로 거부. "
                 "해제 시간 0이면 check_reset_failcount(1363)가 초기화하지 않음 → P_TAMPER_K 뒤 W 이후에도 지속 차단.",
                 f"{_PI}/token.py:2717·2736·2744 응답 실패(무효 서명·미등록 자격증명 모두)마다 inc_failcount → "
                 "P_WRONG_CRED 3회도 같은 지속 잠금(모델의 count_normal은 W 이내 해제라 모델 밖 동작일 수 있음)."],
    "PI-lockT": ["DefaultMaxFailCount=3, failcounter_clear_timeout=1(분).",
                 f"{_PI}/tokenclass.py:1363 잠금 시각(FAILCOUNTER_EXCEEDED)+1분이 지나면 다음 인증 때 초기화 → "
                 "W=120초 뒤 정상 인증 수락. P_TAMPER_K·P_WRONG_CRED 모두 W 이내 해제 잠금."],
    "PI-C": ["M_C: webauthntoken.py check_otp의 HTTP_ORIGIN 확인 직후(검증 전), 요청 자격증명이 토큰의 것이고 "
             "요청 카운터 > 저장값이면 set_otp_count(요청값). 검증 입력 user.sign_count는 옛 값.",
             "P_CORRUPT_CTR: 무효 서명이라도 100000 저장(token.save 커밋) → 정상 카운터 1·2·3은 webauthn.py:1728로 거부"
             "(실패 4회 < maxfail 10이라 잠금 아님) → 지속 차단, 100001 유효 서명 확인은 수락 → 상태 오염."],
    "PI-S": ["위약: 같은 위치에서 같은 값을 읽고 비교만, 저장 없음 → 원본과 같은 동작 → 차단 없음."],
    "HK-orig": [f"{_HK} flow_api/services/webauthn.go:224-256 ValidateLogin/ValidateDiscoverableLogin 성공 뒤에만 "
                "BE·BS·SignCount 저장, 246에서 카운터 역행 거부. 패스키 경로에 잠금·속도 제한 없음 → 차단 없음."],
    "HK-C": ["M_C: 같은 파일 검증 호출 직전, 요청 카운터 > 저장값이면 credentialModel 사본의 SignCount를 저장(Update). "
             "무효 서명 시 액션은 실패 감사 로그를 쓰고 c.Continue로 정상 종료하므로 트랜잭션 커밋"
             "(credential_usage/action_webauthn_verify_assertion_response.go:61-81, handler.go:319).",
             "P_CORRUPT_CTR: 100000 저장 → 정상 카운터 1은 246 검사로 거부(지속) → 100001 유효 서명은 수락 → 상태 오염."],
    "HK-F": ["M_F: 검증 직전 요청 BE·BS를 사본으로 저장(커밋). 그러나 persistence/models/user.go:258-270이 만드는 "
             "webauthn.Credential에 Flags가 없고, go-webauthn v0.10.2 login.go:285-292는 BE 일관성을 검사하지 않음 "
             "→ 저장된 BE·BS가 이후 인증에 쓰이지 않음 → 결함은 있으나 차단 없음."],
    "HK-S": ["위약: 같은 위치에서 카운터를 읽고 비교만, 저장 없음 → 차단 없음."],
}
BLOCK_CAUSE_TRUTH_V7 = {
    "PI-orig": "no_block", "PI-lockP": "normal_policy", "PI-lockT": "normal_policy",
    "PI-C": "state_corruption", "PI-S": "no_block",
    "HK-orig": "no_block", "HK-C": "state_corruption", "HK-F": "no_block", "HK-S": "no_block",
}
DEFECT_PRESENT_V7 = {"PI-C": True, "HK-C": True, "HK-F": True}
PREDICTED_RISK_V7 = {"PI-lockP": "normal_policy or undetermined", "PI-lockT": "normal_policy (some undetermined)",
                     "HK-F": "no_block (defect-presence undetermined)"}

TRUTH_V7B_EVIDENCE = {
    "PI-amf10": ["auth_max_fail=3/10m: lib/policies/helper.py:34 check_max_auth_fail이 사용자의 /validate/check 실패(챌린지 제외)를 "
                 "10분 창에서 셈 → 3회 이상이면 check_user_pass(token.py:2348) 단계에서 거부. 사전 확인: 무효 서명 3회 뒤 "
                 "정상·재시도·W 이후 모두 거부, 저장 카운터·failcount 불변 → 정책성 차단(지속)."],
    "PI-amf1": ["auth_max_fail=3/1m: 같은 정책, 1분 창. 사전 확인: 정상·재시도 거부, W(120초) 이후 수락 → 정책성 차단(W 이내 해제)."],
    "PI-orig2": ["원본, 정책 없음. 7차 PI-orig와 같은 동작 → 차단 없음."],
    "PI-C2": ["7차 PI-C와 같은 M_C 패치, 정책 없음. DB 확인(db_check.txt): 위조 요청 뒤 저장 카운터 100000, 정상 카운터 거부 → 상태 오염."],
}
BLOCK_CAUSE_TRUTH_V7B = {"PI-amf10": "normal_policy", "PI-amf1": "normal_policy",
                         "PI-orig2": "no_block", "PI-C2": "state_corruption"}
