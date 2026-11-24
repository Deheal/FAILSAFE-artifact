# 5차 B 수집 전 예상 (자동 생성: scripts/predict_round5_b.py, 수집 전 커밋)

3·4차 실관측에 한 방향 실패(정상 로그인 ACCEPT→REJECT)를 재생. 서버 상태 변화·프로브 분기 미반영.
짝지은 예상 = 실측과 같은 난수열(같은 요청 위치가 바뀜), 30시행. 분포 예상 = 시행당 30추첨, 900.

## q = 0.01

| 조건 | 정답 | 주입 수(짝) | 방식 | 짝지은 예상 분포 | 오탐/놓침(짝) | 분포 예상 오탐/놓침/유보 (900) |
|---|---|---|---|---|---|---|
| vaultwarden-1.35.4 | state_corruption | 9 (8시행) | FAILSAFE | {'state_corruption': 30} | 0/0 | 0/0/27 |
| vaultwarden-1.35.4 | state_corruption | 9 (8시행) | v2 규칙 | {'state_corruption': 30} | 0/0 | 0/0/27 |
| authelia-mc-4.39.28 | state_corruption | 15 (11시행) | FAILSAFE | {'undetermined': 3, 'state_corruption': 27} | 0/0 | 0/0/41 |
| authelia-mc-4.39.28 | state_corruption | 15 (11시행) | v2 규칙 | {'undetermined': 30} | 0/0 | 0/0/900 |
| vaultwarden-1.35.5 | no_block | 13 (12시행) | FAILSAFE | {'no_block': 26, 'undetermined': 4} | 0/0 | 0/0/108 |
| vaultwarden-1.35.5 | no_block | 13 (12시행) | v2 규칙 | {'normal_policy': 23, 'undetermined': 7} | 0/0 | 0/0/212 |
| keycloak-26.0.7-bf_on | normal_policy | 19 (16시행) | FAILSAFE | {'normal_policy': 27, 'undetermined': 3} | 0/0 | 0/0/69 |
| keycloak-26.0.7-bf_on | normal_policy | 19 (16시행) | v2 규칙 | {'normal_policy': 20, 'undetermined': 10} | 0/0 | 0/0/207 |
| authelia-4.39.28 | normal_policy | 16 (14시행) | FAILSAFE | {'undetermined': 4, 'normal_policy': 25, 'no_block': 1} | 0/0 | 0/0/112 |
| authelia-4.39.28 | normal_policy | 16 (14시행) | v2 규칙 | {'undetermined': 30} | 0/0 | 0/0/900 |
| gitea-1.24.0 | no_block | 12 (11시행) | FAILSAFE | {'no_block': 23, 'normal_policy': 2, 'undetermined': 5} | 0/0 | 0/0/120 |
| gitea-1.24.0 | no_block | 12 (11시행) | v2 규칙 | {'normal_policy': 25, 'undetermined': 5} | 0/0 | 0/0/187 |

확신 오류 합(오탐+확신 놓침): FAILSAFE 짝 0 / 분포 0, v2 규칙 짝 0 / 분포 0

## q = 0.05

| 조건 | 정답 | 주입 수(짝) | 방식 | 짝지은 예상 분포 | 오탐/놓침(짝) | 분포 예상 오탐/놓침/유보 (900) |
|---|---|---|---|---|---|---|
| vaultwarden-1.35.4 | state_corruption | 67 (25시행) | FAILSAFE | {'state_corruption': 25, 'undetermined': 5} | 0/0 | 0/0/123 |
| vaultwarden-1.35.4 | state_corruption | 67 (25시행) | v2 규칙 | {'state_corruption': 25, 'undetermined': 5} | 0/0 | 0/0/122 |
| authelia-mc-4.39.28 | state_corruption | 68 (28시행) | FAILSAFE | {'state_corruption': 26, 'undetermined': 4} | 0/0 | 0/0/255 |
| authelia-mc-4.39.28 | state_corruption | 68 (28시행) | v2 규칙 | {'undetermined': 30} | 0/0 | 0/0/900 |
| vaultwarden-1.35.5 | no_block | 83 (29시행) | FAILSAFE | {'no_block': 16, 'normal_policy': 2, 'undetermined': 12} | 0/0 | 0/0/439 |
| vaultwarden-1.35.5 | no_block | 83 (29시행) | v2 규칙 | {'undetermined': 22, 'normal_policy': 8} | 0/0 | 0/0/683 |
| keycloak-26.0.7-bf_on | normal_policy | 72 (27시행) | FAILSAFE | {'normal_policy': 21, 'undetermined': 7, 'no_block': 2} | 0/0 | 0/0/335 |
| keycloak-26.0.7-bf_on | normal_policy | 72 (27시행) | v2 규칙 | {'normal_policy': 10, 'undetermined': 20} | 0/0 | 0/0/687 |
| authelia-4.39.28 | normal_policy | 81 (29시행) | FAILSAFE | {'normal_policy': 13, 'undetermined': 16, 'no_block': 1} | 0/0 | 0/0/418 |
| authelia-4.39.28 | normal_policy | 81 (29시행) | v2 규칙 | {'undetermined': 30} | 0/0 | 0/0/900 |
| gitea-1.24.0 | no_block | 86 (27시행) | FAILSAFE | {'no_block': 16, 'undetermined': 14} | 0/0 | 0/0/375 |
| gitea-1.24.0 | no_block | 86 (27시행) | v2 규칙 | {'undetermined': 24, 'normal_policy': 6} | 0/0 | 0/0/672 |

확신 오류 합(오탐+확신 놓침): FAILSAFE 짝 0 / 분포 0, v2 규칙 짝 0 / 분포 0

