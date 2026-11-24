# 7차 1절 — R4(같은 범주 규칙) 재적용 결과

계획: docs/round7_plan.md 1절 (커밋 e3f8c60, 실행 전)

## 실서버 17개 조건 / 기호 반전 재생

| q | 방식 | 오탐 | 확신 놓침 | 탐지 | 유보 | 비대상 표지 일치 | 대상 조건 전부 탐지 | 비대상 조건 과반 표지 일치 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 0.0 | FAILSAFE | 0/360 | 0/150 | 150/150 | 1/510 | 359/360 | 5/5 | 12/12 |
| 0.0 | R4 규칙 | 0/360 | 0/150 | 120/150 | 116/510 | 274/360 | 4/5 | 9/12 |
| 0.0 | v2 규칙 | 0/360 | 0/150 | 120/150 | 116/510 | 34/360 | 4/5 | 1/12 |
| 0.01 | FAILSAFE | 0/10800 | 0/4500 | 4231/4500 | 1303/15300 | 9344/10800 | 0/5 | 12/12 |
| 0.01 | R4 규칙 | 0/10800 | 19/4500 | 3398/4500 | 5552/15300 | 5868/10800 | 0/5 | 9/12 |
| 0.01 | v2 규칙 | 0/10800 | 19/4500 | 3398/4500 | 5552/15300 | 787/10800 | 0/5 | 1/12 |
| 0.05 | FAILSAFE | 0/10800 | 2/4500 | 3158/4500 | 5538/15300 | 5416/10800 | 0/5 | 6/12 |
| 0.05 | R4 규칙 | 0/10800 | 75/4500 | 2661/4500 | 10465/15300 | 1482/10800 | 0/5 | 0/12 |
| 0.05 | v2 규칙 | 0/10800 | 75/4500 | 2661/4500 | 10465/15300 | 299/10800 | 0/5 | 0/12 |

## 5차 B 실서버 실패 주입 6개 조건

| q | 방식 | 오탐 | 확신 놓침 | 탐지 | 유보 | 비대상 표지 일치 | 대상 조건 전부 탐지 | 비대상 조건 과반 표지 일치 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 0.01 | FAILSAFE | 0/120 | 0/60 | 57/60 | 19/180 | 101/120 | 1/2 | 4/4 |
| 0.01 | R4 규칙 | 0/120 | 0/60 | 30/60 | 82/180 | 62/120 | 1/2 | 3/4 |
| 0.01 | v2 규칙 | 0/120 | 0/60 | 30/60 | 82/180 | 20/120 | 1/2 | 1/4 |
| 0.05 | FAILSAFE | 0/120 | 0/60 | 51/60 | 58/180 | 66/120 | 0/2 | 3/4 |
| 0.05 | R4 규칙 | 0/120 | 0/60 | 25/60 | 131/180 | 21/120 | 0/2 | 0/4 |
| 0.05 | v2 규칙 | 0/120 | 0/60 | 25/60 | 131/180 | 10/120 | 0/2 | 0/4 |

## 잡음 없는 실서버 조건별 분포

| 조건 | 정답 | FAILSAFE | R4 규칙 |
|---|---|---|---|
| authelia-4.39.28 | normal_policy | {'normal_policy': 30} | {'undetermined': 30} |
| authelia-fs1-4.39.28 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} |
| authelia-mc-4.39.28 | state_corruption | {'state_corruption': 30} | {'undetermined': 30} |
| authelia-src-4.39.28 | normal_policy | {'normal_policy': 30} | {'undetermined': 30} |
| authentik-2024.10.5 | no_block | {'no_block': 29, 'undetermined': 1} | {'no_block': 30} |
| authentik-fs2-2024.10.5 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} |
| gitea-1.24.0 | no_block | {'no_block': 30} | {'no_block': 30} |
| kanidm-1.12.0 | no_block | {'no_block': 30} | {'no_block': 30} |
| keycloak-26.0.7-bf_off | no_block | {'no_block': 30} | {'no_block': 30} |
| keycloak-26.0.7-bf_on | normal_policy | {'normal_policy': 30} | {'normal_policy': 30} |
| keycloak-26.0.7-bf_perm | normal_policy | {'normal_policy': 30} | {'undetermined': 26, 'normal_policy': 4} |
| vaultwarden-1.35.4 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} |
| vaultwarden-1.35.4-synced | no_block | {'no_block': 30} | {'no_block': 30} |
| vaultwarden-1.35.5 | no_block | {'no_block': 30} | {'no_block': 30} |
| vaultwarden-1.35.5-synced | no_block | {'no_block': 30} | {'no_block': 30} |
| vaultwarden-mc-1.35.5 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} |
| zitadel-4.20.1 | no_block | {'no_block': 30} | {'no_block': 30} |
