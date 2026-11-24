# 5차 실험 B — 실서버 일시 실패 주입 (자동 생성: scripts/evaluate_round5_b.py)

엔진 v2.2 동결. 정상 로그인을 확률 q로 서명 무효 요청으로 바꿔 실제 서버에 전송. 조건당 30시행.

## q = 0.01

| 방식 | 오탐 (조건/시행) | 확신 놓침 (조건/시행) | 확신 오류 합 | 상태 오염 탐지 | 유보 |
|---|---|---|---|---|---|
| FAILSAFE | 0 / 0 (of 120) | 0 / 0 (of 60) | **0** | 57/60 | 19 |
| v2 규칙 | 0 / 0 (of 120) | 0 / 0 (of 60) | **0** | 30/60 | 82 |
| 복구만 | 2 / 31 (of 120) | 0 / 0 (of 60) | **31** | 60/60 | 0 |
| 단순 재시도 | 2 / 60 (of 120) | 0 / 0 (of 60) | **60** | 60/60 | 0 |
| 단일 응답 | 0 / 0 (of 120) | 2 / 60 (of 60) | **60** | 0/60 | 0 |

| 조건 | 정답 | 주입 수 | 대조 실행 실패 프로브 | 확인 단계 수행 | FAILSAFE 실측 | 짝 예상 | 일치 | v2 규칙 실측 | 짝 예상 | 일치 |
|---|---|---|---|---|---|---|---|---|---|---|
| authelia-4.39.28 | normal_policy | 16 (16프로브) | 7 | 0 | {'undetermined': 4, 'normal_policy': 25, 'no_block': 1} | {'undetermined': 4, 'normal_policy': 25, 'no_block': 1} | 30/30 | {'undetermined': 30} | {'undetermined': 30} | 30/30 |
| authelia-mc-4.39.28 | state_corruption | 15 (14프로브) | 8 | P_CORRUPT_CTR 30 | {'undetermined': 3, 'state_corruption': 27} | {'undetermined': 3, 'state_corruption': 27} | 30/30 | {'undetermined': 30} | {'undetermined': 30} | 30/30 |
| gitea-1.24.0 | no_block | 12 (12프로브) | 6 | 0 | {'no_block': 23, 'normal_policy': 2, 'undetermined': 5} | {'no_block': 23, 'normal_policy': 2, 'undetermined': 5} | 30/30 | {'normal_policy': 25, 'undetermined': 5} | {'normal_policy': 25, 'undetermined': 5} | 30/30 |
| keycloak-26.0.7-bf_on | normal_policy | 19 (19프로브) | 11 | 0 | {'normal_policy': 27, 'undetermined': 3} | {'normal_policy': 27, 'undetermined': 3} | 30/30 | {'normal_policy': 20, 'undetermined': 10} | {'normal_policy': 20, 'undetermined': 10} | 30/30 |
| vaultwarden-1.35.4 | state_corruption | 9 (9프로브) | 3 | P_CORRUPT 30 | {'state_corruption': 30} | {'state_corruption': 30} | 30/30 | {'state_corruption': 30} | {'state_corruption': 30} | 30/30 |
| vaultwarden-1.35.5 | no_block | 13 (12프로브) | 7 | 0 | {'no_block': 26, 'undetermined': 4} | {'no_block': 26, 'undetermined': 4} | 30/30 | {'normal_policy': 23, 'undetermined': 7} | {'normal_policy': 23, 'undetermined': 7} | 30/30 |

짝 예상과 달라진 시행 (예상→실측):


## q = 0.05

| 방식 | 오탐 (조건/시행) | 확신 놓침 (조건/시행) | 확신 오류 합 | 상태 오염 탐지 | 유보 |
|---|---|---|---|---|---|
| FAILSAFE | 0 / 0 (of 120) | 0 / 0 (of 60) | **0** | 51/60 | 58 |
| v2 규칙 | 0 / 0 (of 120) | 0 / 0 (of 60) | **0** | 25/60 | 131 |
| 복구만 | 3 / 36 (of 120) | 0 / 0 (of 60) | **36** | 60/60 | 0 |
| 단순 재시도 | 2 / 60 (of 120) | 0 / 0 (of 60) | **60** | 60/60 | 0 |
| 단일 응답 | 0 / 0 (of 120) | 2 / 60 (of 60) | **60** | 0/60 | 0 |

| 조건 | 정답 | 주입 수 | 대조 실행 실패 프로브 | 확인 단계 수행 | FAILSAFE 실측 | 짝 예상 | 일치 | v2 규칙 실측 | 짝 예상 | 일치 |
|---|---|---|---|---|---|---|---|---|---|---|
| authelia-4.39.28 | normal_policy | 81 (70프로브) | 39 | P_CORRUPT 1 | {'normal_policy': 13, 'undetermined': 16, 'no_block': 1} | {'normal_policy': 13, 'undetermined': 16, 'no_block': 1} | 30/30 | {'undetermined': 30} | {'undetermined': 30} | 30/30 |
| authelia-mc-4.39.28 | state_corruption | 68 (59프로브) | 26 | P_CORRUPT_CTR 30 | {'state_corruption': 26, 'undetermined': 4} | {'state_corruption': 26, 'undetermined': 4} | 30/30 | {'undetermined': 30} | {'undetermined': 30} | 30/30 |
| gitea-1.24.0 | no_block | 86 (74프로브) | 41 | 0 | {'no_block': 16, 'undetermined': 14} | {'no_block': 16, 'undetermined': 14} | 30/30 | {'undetermined': 24, 'normal_policy': 6} | {'undetermined': 24, 'normal_policy': 6} | 30/30 |
| keycloak-26.0.7-bf_on | normal_policy | 72 (57프로브) | 29 | P_CORRUPT_CTR 1 | {'normal_policy': 21, 'undetermined': 7, 'no_block': 2} | {'normal_policy': 21, 'undetermined': 7, 'no_block': 2} | 30/30 | {'normal_policy': 10, 'undetermined': 20} | {'normal_policy': 10, 'undetermined': 20} | 30/30 |
| vaultwarden-1.35.4 | state_corruption | 67 (57프로브) | 31 | P_CORRUPT 30 | {'state_corruption': 25, 'undetermined': 5} | {'state_corruption': 25, 'undetermined': 5} | 30/30 | {'state_corruption': 25, 'undetermined': 5} | {'state_corruption': 25, 'undetermined': 5} | 30/30 |
| vaultwarden-1.35.5 | no_block | 83 (68프로브) | 35 | P_CORRUPT 1 | {'no_block': 16, 'normal_policy': 2, 'undetermined': 12} | {'no_block': 16, 'normal_policy': 2, 'undetermined': 12} | 30/30 | {'undetermined': 22, 'normal_policy': 8} | {'undetermined': 22, 'normal_policy': 8} | 30/30 |

짝 예상과 달라진 시행 (예상→실측):


## 사전 고정 판정 규칙 (round5_plan.md 4.4절, 5.5절)

- q=0.01: FAILSAFE 확신 오류 0 vs v2 규칙 0 → 미충족
- q=0.05: FAILSAFE 확신 오류 0 vs v2 규칙 0 → 미충족
- 결론: B에서는 우위 미확인 (그대로 보고)
