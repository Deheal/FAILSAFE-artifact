# 7차 2절 — 미사용 RP 블라인드 독립 검증 결과

계획: docs/round7_plan.md 2절. 판정 파일을 커밋한 뒤 대응표를 공개하고 정답과 결합했다.

| 조건 | 코드 | 정답 | FAILSAFE 차단 원인 | 결함 유무 출력 | R4 규칙 |
|---|---|---|---|---|---|
| HK-C | hk-X01 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} | {'state_corruption': 30} |
| HK-F | hk-X02 | no_block | {'no_block': 30} | {'undetermined': 30} | {'no_block': 30} |
| HK-S | hk-X05 | no_block | {'no_block': 30} | {'undetermined': 30} | {'no_block': 30} |
| HK-orig | hk-X09 | no_block | {'no_block': 30} | {'undetermined': 30} | {'no_block': 30} |
| PI-lockT | pi-X03 | normal_policy | {'no_block': 29, 'undetermined(defect_probe_missing)': 1} | {'undetermined': 30} | {'no_block': 30} |
| PI-orig | pi-X04 | no_block | {'no_block': 29, 'undetermined(defect_probe_missing)': 1} | {'undetermined': 30} | {'no_block': 30} |
| PI-S | pi-X06 | no_block | {'no_block': 29, 'undetermined(defect_probe_missing)': 1} | {'undetermined': 30} | {'no_block': 30} |
| PI-C | pi-X07 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} | {'state_corruption': 30} |
| PI-lockP | pi-X08 | normal_policy | {'no_block': 29, 'undetermined(defect_probe_missing)': 1} | {'undetermined': 30} | {'no_block': 30} |

## 방식별 합계

| 방식 | 오탐(시행) | 확신 놓침 | 대상 탐지 | 유보 | 비대상 표지 일치 |
|---|---:|---:|---:|---:|---:|
| FAILSAFE | 0/210 | 0/60 | 60/60 | 4/270 | 148/210 |
| R4 규칙 | 0/210 | 0/60 | 60/60 | 0/270 | 150/210 |
| v2 규칙 | 0/210 | 0/60 | 60/60 | 0/270 | 60/210 |
| 복구만 | 0/210 | 0/60 | 60/60 | 0/270 | 60/210 |
| 단순 재시도 | 0/210 | 0/60 | 60/60 | 0/270 | 60/210 |
| 단일 응답 | 0/210 | 60/60 | 0/60 | 0/270 | 60/210 |

## 사전 성공 기준(2.6절)

{"a_detect_majority": true, "b_no_false_corruption": true, "c_no_confident_miss": true, "passed": true}

## 판정 커밋·공개 뒤 정답 확인 (계획 2.4절, scripts/round7/db_check.py → db_check.txt)

- PI-C·HK-C: 위조 요청(카운터 100000) 직후 저장 카운터 100000, 이후 정상 카운터 1 거부 → **상태 오염 정답 확인**.
- HK-F: 위조 요청 직후 저장 BE·BS = t|t(주입 작동), 그러나 정상 로그인(BE=0·BS=0) 수락 → **결함 있음·차단 없음 확인**.
- PI-orig, HK-orig, HK-S: 저장값 변화 없음.
- **PI-lockP, PI-lockT: 사전 정답(정책성 차단)이 틀렸다.** maxfail=3은 토큰에 적용되었지만 무효 서명 3회 뒤에도 failcount=0.
  v3.13.4는 credential_id가 있는 /validate/check 요청을 FIDO2 전용 경로(api/validate.py `_handle_fido2_auth` → lib/fido2/challenge.py
  `verify_fido2_challenge` → `check_otp`)로 처리하며, 이 경로는 실패 횟수를 올리는 lib/token.py `check_token_list`(2714-2717행)를
  거치지 않는다. 사전 정답은 일반 경로만 보고 작성했다. → 실제 서버 동작 기준 정답은 **차단 없음**.

## 두 정답 기준의 채점

| 기준 | FAILSAFE 오탐 | 확신 놓침 | 대상 탐지 | 비대상 표지 일치 |
|---|---:|---:|---:|---:|
| 사전 정답(잠금 2조건 = 정책성 차단) | 0/210 | 0/60 | 60/60 | 148/210 |
| 확인 정답(잠금 2조건 = 차단 없음) | 0/210 | 0/60 | 60/60 | 206/210 (유보 4) |

사전 성공 기준(a·b·c)은 두 기준 모두에서 충족. 다만 계획 2.1절 질문 (2) "미사용 RP의 원래 잠금과 구분하는가"는
**잠금이 실제로 발생하지 않아 검증하지 못했다.** 유보 4건은 모두 대조 실행 중 서버 500 오류로 결함 프로브가 제외된 경우(A0).
