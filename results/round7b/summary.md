# 7b — 미사용 RP의 실제 정책 차단: 블라인드 검증 결과

계획: docs/round7_plan.md 3절. 판정 파일을 커밋(764b85d)한 뒤 대응표를 공개(해시 a3a5bc1d… 일치)하고 정답과 결합했다.

| 조건 | 코드 | 정답 | FAILSAFE 차단 원인 | 결함 유무 출력 | R4 규칙 |
|---|---|---|---|---|---|
| PI-orig2 | pi-Y01 | no_block | {'no_block': 30} | {'undetermined': 30} | {'no_block': 30} |
| PI-amf1 | pi-Y02 | normal_policy | {'normal_policy': 30} | {'undetermined': 30} | {'normal_policy': 30} |
| PI-amf10 | pi-Y03 | normal_policy | {'normal_policy': 30} | {'undetermined': 30} | {'undetermined': 30} |
| PI-C2 | pi-Y04 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} | {'state_corruption': 30} |

## 방식별 합계

| 방식 | 오탐(시행) | 확신 놓침 | 대상 탐지 | 유보 | 비대상 표지 일치 |
|---|---:|---:|---:|---:|---:|
| FAILSAFE | 0/90 | 0/30 | 30/30 | 0/120 | 90/90 |
| R4 규칙 | 0/90 | 0/30 | 30/30 | 30/120 | 60/90 |
| v2 규칙 | 0/90 | 0/30 | 30/30 | 30/120 | 30/90 |
| 복구만 | 30/90 | 0/30 | 30/30 | 0/120 | 30/90 |
| 단순 재시도 | 60/90 | 0/30 | 30/30 | 0/120 | 0/90 |
| 단일 응답 | 0/90 | 30/30 | 0/30 | 0/120 | 60/90 |

## 사전 성공 기준(2.6절)

{"a_detect_majority": true, "b_no_false_corruption": true, "c_no_confident_miss": true, "passed": true}

## 판정 뒤 서버 쪽 원인 확인

- PI-amf10(pi-Y03): `P_TAMPER_K`·`P_WRONG_CRED` 30시행 모두 R/R/R/B/B/B(1차 단계 차단이 W 이후에도 지속). 감사 로그의 정책 거부
  "Only 3 failed authentications per 0:10:00 allowed." 180건(= 2프로브 × 30시행 × 3요청). 토큰 480개 중 저장 카운터 ≥100000인 것 0, failcount>0인 것 0
  → 차단 원인은 정책이고 보호 상태는 변하지 않았다.
- PI-amf1(pi-Y02): 같은 두 프로브 R/R/R/B/B/A(W 이후 해제). 정책 거부 120건. 저장 상태 변화 없음.
- PI-C2(pi-Y04): 저장 카운터 ≥100000인 토큰 30개(= `P_CORRUPT_CTR` 프로브 세션 30개) → 상태 오염 확인.
- 사전 예상 위험(PI-amf10에서 `P_WRONG_CRED` 지속 차단 때문에 유보 가능)은 일어나지 않았다. FAILSAFE 표지에 모델 밖 정책(unmodeled_policy)
  표시가 없으므로 3차에 추가한 사후 규칙이 아니라 모델 안에서(허용 불일치 m 이내) 설명된 판정이다.

## 비교 방식

지속 차단 조건(PI-amf10)에서 "W 후 복구만 확인"은 30/30, "즉시 재시도만 확인"은 두 정책 조건 60/60을 상태 오염으로 오판했다.
같은 프로브의 4범주 규칙은 오판하지 않았으나 PI-amf10을 30/30 유보했다.
