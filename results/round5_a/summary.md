# 5차 실험 A — 실관측 잡음 재생 (자동 생성: scripts/evaluate_round5_a.py)

엔진 v2.2 동결, ε=0.1 τ=0.99 m=2. 17개 조건 × 30 실시행 × 30 추첨. SEED_A=20261115. q=0은 잡음 없는 재현 점검(추첨 1회).

## q = 0.0

| 방식 | 오탐 조건 | 오탐 시행 | 확신 놓침 조건 | 확신 놓침 시행 | 확신 오류 합 | 변조 탐지 | 유보 | 표지 정답(비변조) |
|---|---|---|---|---|---|---|---|---|
| FAILSAFE | 0/12 | 0/360 | 0/5 | 0/150 | **0** | 150/150 | 1 | 359/360 |
| v2 규칙 | 0/12 | 0/360 | 0/5 | 0/150 | **0** | 120/150 | 116 | 34/360 |
| 복구만 | 3/12 | 86/360 | 0/5 | 0/150 | **86** | 150/150 | 0 | 34/360 |
| 단순 재시도 | 4/12 | 120/360 | 0/5 | 0/150 | **120** | 150/150 | 0 | 0/360 |
| 단일 응답 | 0/12 | 0/360 | 5/5 | 150/150 | **150** | 0/150 | 0 | 120/360 |

조건별 (FAILSAFE / v2 규칙):

| 조건 | 정답 | FAILSAFE 분포 | v2 규칙 분포 |
|---|---|---|---|
| authelia-4.39.28 | normal_policy | {'normal_policy': 30} | {'undetermined': 30} |
| authentik-2024.10.5 | no_block | {'no_block': 29, 'undetermined': 1} | {'normal_policy': 30} |
| authentik-fs2-2024.10.5 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} |
| kanidm-1.12.0 | no_block | {'no_block': 30} | {'normal_policy': 30} |
| keycloak-26.0.7-bf_off | no_block | {'no_block': 30} | {'normal_policy': 30} |
| authelia-fs1-4.39.28 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} |
| authelia-mc-4.39.28 | state_corruption | {'state_corruption': 30} | {'undetermined': 30} |
| authelia-src-4.39.28 | normal_policy | {'normal_policy': 30} | {'undetermined': 30} |
| gitea-1.24.0 | no_block | {'no_block': 30} | {'normal_policy': 30} |
| keycloak-26.0.7-bf_on | normal_policy | {'normal_policy': 30} | {'normal_policy': 30} |
| keycloak-26.0.7-bf_perm | normal_policy | {'normal_policy': 30} | {'undetermined': 26, 'normal_policy': 4} |
| vaultwarden-1.35.4 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} |
| vaultwarden-mc-1.35.5 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} |
| vaultwarden-1.35.5 | no_block | {'no_block': 30} | {'normal_policy': 30} |
| zitadel-4.20.1 | no_block | {'no_block': 30} | {'normal_policy': 30} |
| vaultwarden-1.35.4-synced | no_block | {'no_block': 30} | {'normal_policy': 30} |
| vaultwarden-1.35.5-synced | no_block | {'no_block': 30} | {'normal_policy': 30} |

## q = 0.01

| 방식 | 오탐 조건 | 오탐 시행 | 확신 놓침 조건 | 확신 놓침 시행 | 확신 오류 합 | 변조 탐지 | 유보 | 표지 정답(비변조) |
|---|---|---|---|---|---|---|---|---|
| FAILSAFE | 0/12 | 0/10800 | 0/5 | 0/4500 | **0** | 4231/4500 | 1303 | 9344/10800 |
| v2 규칙 | 0/12 | 0/10800 | 3/5 | 19/4500 | **19** | 3398/4500 | 5552 | 787/10800 |
| 복구만 | 7/12 | 2543/10800 | 3/5 | 30/4500 | **2573** | 4470/4500 | 0 | 1063/10800 |
| 단순 재시도 | 10/12 | 3533/10800 | 3/5 | 40/4500 | **3573** | 4460/4500 | 0 | 76/10800 |
| 단일 응답 | 0/12 | 0/10800 | 5/5 | 4500/4500 | **4500** | 0/4500 | 0 | 3600/10800 |

조건별 (FAILSAFE / v2 규칙):

| 조건 | 정답 | FAILSAFE 분포 | v2 규칙 분포 |
|---|---|---|---|
| authelia-fs1-4.39.28 | state_corruption | {'state_corruption': 847, 'undetermined': 53} | {'state_corruption': 843, 'undetermined': 57} |
| authelia-4.39.28 | normal_policy | {'normal_policy': 751, 'undetermined': 85, 'no_block': 64} | {'undetermined': 882, 'normal_policy': 18} |
| keycloak-26.0.7-bf_on | normal_policy | {'normal_policy': 792, 'no_block': 24, 'undetermined': 84} | {'undetermined': 238, 'normal_policy': 662} |
| kanidm-1.12.0 | no_block | {'no_block': 767, 'normal_policy': 40, 'undetermined': 93} | {'normal_policy': 696, 'undetermined': 204} |
| authentik-fs2-2024.10.5 | state_corruption | {'state_corruption': 849, 'undetermined': 51} | {'state_corruption': 843, 'undetermined': 54, 'normal_policy': 3} |
| authelia-src-4.39.28 | normal_policy | {'normal_policy': 762, 'no_block': 44, 'undetermined': 94} | {'undetermined': 892, 'normal_policy': 8} |
| keycloak-26.0.7-bf_off | no_block | {'no_block': 799, 'undetermined': 67, 'normal_policy': 34} | {'normal_policy': 691, 'undetermined': 209} |
| authelia-mc-4.39.28 | state_corruption | {'state_corruption': 837, 'undetermined': 63} | {'undetermined': 892, 'state_corruption': 8} |
| gitea-1.24.0 | no_block | {'no_block': 769, 'undetermined': 95, 'normal_policy': 36} | {'normal_policy': 720, 'undetermined': 180} |
| authentik-2024.10.5 | no_block | {'no_block': 738, 'undetermined': 128, 'normal_policy': 34} | {'normal_policy': 701, 'undetermined': 199} |
| vaultwarden-1.35.4 | state_corruption | {'state_corruption': 850, 'undetermined': 50} | {'state_corruption': 855, 'undetermined': 37, 'normal_policy': 8} |
| vaultwarden-1.35.5-synced | no_block | {'no_block': 816, 'normal_policy': 35, 'undetermined': 49} | {'undetermined': 200, 'normal_policy': 700} |
| vaultwarden-1.35.4-synced | no_block | {'no_block': 819, 'normal_policy': 28, 'undetermined': 53} | {'normal_policy': 680, 'undetermined': 220} |
| keycloak-26.0.7-bf_perm | normal_policy | {'normal_policy': 801, 'undetermined': 77, 'no_block': 22} | {'undetermined': 801, 'normal_policy': 99} |
| vaultwarden-1.35.5 | no_block | {'undetermined': 120, 'no_block': 748, 'normal_policy': 32} | {'undetermined': 224, 'normal_policy': 676} |
| vaultwarden-mc-1.35.5 | state_corruption | {'state_corruption': 848, 'undetermined': 52} | {'state_corruption': 849, 'undetermined': 43, 'normal_policy': 8} |
| zitadel-4.20.1 | no_block | {'undetermined': 89, 'no_block': 782, 'normal_policy': 29} | {'normal_policy': 680, 'undetermined': 220} |

## q = 0.05

| 방식 | 오탐 조건 | 오탐 시행 | 확신 놓침 조건 | 확신 놓침 시행 | 확신 오류 합 | 변조 탐지 | 유보 | 표지 정답(비변조) |
|---|---|---|---|---|---|---|---|---|
| FAILSAFE | 0/12 | 0/10800 | 2/5 | 2/4500 | **2** | 3158/4500 | 5538 | 5416/10800 |
| v2 규칙 | 0/12 | 0/10800 | 5/5 | 75/4500 | **75** | 2661/4500 | 10465 | 299/10800 |
| 복구만 | 12/12 | 2517/10800 | 5/5 | 266/4500 | **2783** | 4234/4500 | 0 | 1212/10800 |
| 단순 재시도 | 12/12 | 3374/10800 | 5/5 | 246/4500 | **3620** | 4254/4500 | 0 | 350/10800 |
| 단일 응답 | 0/12 | 0/10800 | 5/5 | 4500/4500 | **4500** | 0/4500 | 0 | 3600/10800 |

조건별 (FAILSAFE / v2 규칙):

| 조건 | 정답 | FAILSAFE 분포 | v2 규칙 분포 |
|---|---|---|---|
| authelia-mc-4.39.28 | state_corruption | {'state_corruption': 552, 'undetermined': 347, 'normal_policy': 1} | {'undetermined': 862, 'state_corruption': 36, 'normal_policy': 2} |
| authelia-fs1-4.39.28 | state_corruption | {'state_corruption': 640, 'undetermined': 260} | {'state_corruption': 661, 'undetermined': 237, 'normal_policy': 2} |
| authelia-4.39.28 | normal_policy | {'normal_policy': 374, 'undetermined': 389, 'no_block': 137} | {'undetermined': 879, 'normal_policy': 21} |
| authentik-2024.10.5 | no_block | {'normal_policy': 76, 'undetermined': 409, 'no_block': 415} | {'undetermined': 658, 'normal_policy': 242} |
| authelia-src-4.39.28 | normal_policy | {'undetermined': 385, 'normal_policy': 387, 'no_block': 128} | {'undetermined': 877, 'normal_policy': 23} |
| authentik-fs2-2024.10.5 | state_corruption | {'state_corruption': 649, 'undetermined': 251} | {'state_corruption': 647, 'undetermined': 222, 'normal_policy': 31} |
| kanidm-1.12.0 | no_block | {'no_block': 440, 'undetermined': 375, 'normal_policy': 85} | {'normal_policy': 220, 'undetermined': 680} |
| keycloak-26.0.7-bf_off | no_block | {'no_block': 486, 'undetermined': 309, 'normal_policy': 105} | {'normal_policy': 235, 'undetermined': 665} |
| vaultwarden-1.35.4 | state_corruption | {'state_corruption': 657, 'undetermined': 243} | {'state_corruption': 665, 'undetermined': 216, 'normal_policy': 19} |
| gitea-1.24.0 | no_block | {'undetermined': 401, 'no_block': 409, 'normal_policy': 90} | {'normal_policy': 244, 'undetermined': 656} |
| keycloak-26.0.7-bf_on | normal_policy | {'normal_policy': 457, 'undetermined': 357, 'no_block': 86} | {'undetermined': 702, 'normal_policy': 198} |
| keycloak-26.0.7-bf_perm | normal_policy | {'normal_policy': 490, 'no_block': 67, 'undetermined': 343} | {'undetermined': 843, 'normal_policy': 57} |
| vaultwarden-1.35.4-synced | no_block | {'undetermined': 247, 'no_block': 548, 'normal_policy': 105} | {'undetermined': 680, 'normal_policy': 220} |
| vaultwarden-1.35.5 | no_block | {'undetermined': 395, 'no_block': 410, 'normal_policy': 95} | {'undetermined': 683, 'normal_policy': 217} |
| vaultwarden-1.35.5-synced | no_block | {'no_block': 543, 'undetermined': 239, 'normal_policy': 118} | {'undetermined': 693, 'normal_policy': 207} |
| vaultwarden-mc-1.35.5 | state_corruption | {'state_corruption': 660, 'undetermined': 239, 'no_block': 1} | {'state_corruption': 652, 'undetermined': 227, 'normal_policy': 21} |
| zitadel-4.20.1 | no_block | {'undetermined': 349, 'no_block': 457, 'normal_policy': 94} | {'undetermined': 685, 'normal_policy': 215} |

## 사전 고정 판정 규칙 (계획서 4.4절)

- q=0.01: FAILSAFE 확신 오류 0 vs v2 규칙 19 → 충족
- q=0.05: FAILSAFE 확신 오류 2 vs v2 규칙 75 → 충족
- 결론: 실관측 기저에서도 우위 확인

소요 234초
