# 4차 실서버 평가 (자동 생성: scripts/evaluate_real_v4.py)

엔진 v2.2 동결. 보고 단위=조건. ε=0.1 τ=0.99 m=2.

## 차단 원인(Q2)

| 조건 | 변이 | 정답 | 예상 | 판정 | 예상 일치 | 오탐 | 확신 놓침 | 유보 |
|---|---|---|---|---|---|---|---|---|
| authelia-mc-4.39.28 | M_C | state_corruption | state_corruption | {'state_corruption': 30} | 30/30 | 0 | 0 | 0 |
| kanidm-1.12.0 | (없음/원본) | no_block | no_block | {'no_block': 30} | 30/30 | 0 | 0 | 0 |
| vaultwarden-mc-1.35.5 | M_C | state_corruption | state_corruption | {'state_corruption': 30} | 30/30 | 0 | 0 | 0 |
| zitadel-4.20.1 | (없음/원본) | no_block | no_block | {'no_block': 30} | 30/30 | 0 | 0 | 0 |

- 오탐이 난 정상(원본) 조건: 0 / 2 (시행 0 / 60)
- 모든 시행을 변조로 판정한 변이 조건: 2 / 2
- 예상과 전부 일치한 조건: 4 / 4

## 결함 유무(Q3)

| 조건 | 정답 | 예상 | 관측 요약 | 분포 |
|---|---|---|---|---|
| authelia-mc-4.39.28 | state_corruption | state_corruption | state_corruption ✓ | {'state_corruption': 30} |
| kanidm-1.12.0 | normal_policy | undetermined | undetermined ✓ | {'undetermined': 30} |
| vaultwarden-mc-1.35.5 | state_corruption | state_corruption | state_corruption ✓ | {'state_corruption': 30} |
| zitadel-4.20.1 | normal_policy | undetermined | undetermined ✓ | {'undetermined': 30} |

## W1 (선택 편향) — 변이 분석

서로 다른 라이브러리에 동일 연산자 M_C(검증 전 카운터 저장)를 기계적으로 주입한 결과:

- **authelia-mc-4.39.28** (afs-src 설정 복사, 포트 9098, M_C 변이 빌드(build/authelia-mc)): M_C → state_corruption 30/30, store_counter_before_verify 확정
- **vaultwarden-mc-1.35.5** (1.35.5 소스 + M_C 변이 빌드(build/vw-mc), 포트 8006): M_C → state_corruption 30/30, store_counter_before_verify 확정

## 비교군 (조건별 판정 분포)

| 조건 | 정답 | v2 규칙 | 복구만 | 단순 재시도 | 단일 응답 |
|---|---|---|---|---|---|
| authelia-mc-4.39.28 | state_corruption | {'undetermined': 30} | {'state_corruption': 30} | {'state_corruption': 30} | {'normal_policy': 30} |
| kanidm-1.12.0 | no_block | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} |
| vaultwarden-mc-1.35.5 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} | {'state_corruption': 30} | {'normal_policy': 30} |
| zitadel-4.20.1 | no_block | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} |
