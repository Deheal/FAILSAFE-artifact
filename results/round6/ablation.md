# 6차 1번 — 구성요소 제거 (자동 생성: scripts/evaluate_round6_ablation.py)

엔진 v2.2 불변. 17개 조건(비대상 12, 대상 5) × 30시행, 잡음은 5차 A와 같은 난수열(DRAWS=30). F와 5차 A 일치 점검: {'0.0': True, '0.01': True, '0.05': True}

## q = 0.0

| 변형 | 오탐 조건 /12 | 오탐 시행 | 확신 놓침 조건 /5 | 확신 놓침 시행 | 확신 오류 합 | 탐지 조건 /5 | 탐지 시행 | 유보 시행 | 비대상 표지 정답 조건 /12 |
|---|---|---|---|---|---|---|---|---|---|
| F 전체 | 0 | 0/360 | 0 | 0/150 | **0** | 5 | 150/150 | 1 | 12 |
| C 대조 실행 제거 | 0 | 0/360 | 0 | 0/150 | **0** | 5 | 150/150 | 0 | 12 |
| K 확인 단계 제거 | 0 | 0/360 | 0 | 0/150 | **0** | 5 | 150/150 | 1 | 12 |
| A 시행 전체 A1 | 0 | 0/360 | 0 | 0/150 | **0** | 3 | 90/150 | 121 | 10 |
| L-P_UV0 | 0 | 0/360 | 0 | 0/150 | **0** | 5 | 150/150 | 1 | 12 |
| L-P_BEBS | 0 | 0/360 | 0 | 0/150 | **0** | 5 | 150/150 | 1 | 12 |
| L-P_SC_DEC | 0 | 0/360 | 0 | 0/150 | **0** | 5 | 150/150 | 1 | 10 |
| L-P_WRONG_CRED | 0 | 0/360 | 0 | 0/150 | **0** | 5 | 150/150 | 1 | 12 |
| L-P_TAMPER_K | 0 | 0/360 | 0 | 0/150 | **0** | 5 | 150/150 | 1 | 10 |
| L-P_REVOKE | 0 | 0/360 | 0 | 0/150 | **0** | 5 | 150/150 | 1 | 12 |
| L-P_CORRUPT | 0 | 0/360 | 0 | 0/150 | **0** | 3 | 90/150 | 420 | 0 |
| L-P_CORRUPT_CTR | 0 | 0/360 | 0 | 0/150 | **0** | 2 | 60/150 | 450 | 0 |
| T 상태 불변 대조 제거 | 0 | 0/360 | 0 | 0/150 | **0** | 4 | 120/150 | 31 | 10 |
| KT 확인+상태 불변 대조 제거 | 0 | 0/360 | 0 | 0/150 | **0** | 3 | 90/150 | 61 | 10 |
| M-BB 무효 서명 대조 전부 제거(BE·BS) | 0 | 0/360 | 0 | 0/150 | **0** | 0 | 0/150 | 510 | 0 |
| M-CTR 무효 서명 대조 전부 제거(카운터) | 0 | 0/360 | 0 | 0/150 | **0** | 0 | 0/150 | 510 | 0 |

## q = 0.01

| 변형 | 오탐 조건 /12 | 오탐 시행 | 확신 놓침 조건 /5 | 확신 놓침 시행 | 확신 오류 합 | 탐지 조건 /5 | 탐지 시행 | 유보 시행 | 비대상 표지 정답 조건 /12 |
|---|---|---|---|---|---|---|---|---|---|
| F 전체 | 0 | 0/10800 | 0 | 0/4500 | **0** | 5 | 4231/4500 | 1303 | 12 |
| C 대조 실행 제거 | 0 | 0/10800 | 0 | 0/4500 | **0** | 5 | 4384/4500 | 534 | 12 |
| K 확인 단계 제거 | 0 | 0/10800 | 0 | 0/4500 | **0** | 5 | 4212/4500 | 1374 | 12 |
| A 시행 전체 A1 | 0 | 0/10800 | 0 | 0/4500 | **0** | 3 | 2630/4500 | 4450 | 10 |
| L-P_UV0 | 0 | 0/10800 | 0 | 0/4500 | **0** | 5 | 4231/4500 | 1302 | 12 |
| L-P_BEBS | 0 | 0/10800 | 0 | 0/4500 | **0** | 5 | 4183/4500 | 1350 | 12 |
| L-P_SC_DEC | 0 | 0/10800 | 0 | 0/4500 | **0** | 5 | 4240/4500 | 1159 | 10 |
| L-P_WRONG_CRED | 0 | 0/10800 | 0 | 0/4500 | **0** | 5 | 4231/4500 | 1302 | 12 |
| L-P_TAMPER_K | 0 | 0/10800 | 0 | 0/4500 | **0** | 5 | 4125/4500 | 1407 | 10 |
| L-P_REVOKE | 0 | 0/10800 | 0 | 0/4500 | **0** | 5 | 4113/4500 | 1419 | 12 |
| L-P_CORRUPT | 0 | 0/10800 | 0 | 0/4500 | **0** | 3 | 2426/4500 | 12874 | 0 |
| L-P_CORRUPT_CTR | 0 | 0/10800 | 0 | 0/4500 | **0** | 2 | 1643/4500 | 13657 | 0 |
| T 상태 불변 대조 제거 | 0 | 0/10800 | 0 | 0/4500 | **0** | 4 | 3373/4500 | 2158 | 10 |
| KT 확인+상태 불변 대조 제거 | 0 | 0/10800 | 1 | 1/4500 | **1** | 3 | 2554/4500 | 3029 | 10 |
| M-BB 무효 서명 대조 전부 제거(BE·BS) | 0 | 0/10800 | 0 | 0/4500 | **0** | 0 | 3/4500 | 15297 | 0 |
| M-CTR 무효 서명 대조 전부 제거(카운터) | 0 | 0/10800 | 0 | 0/4500 | **0** | 0 | 15/4500 | 15285 | 0 |

## q = 0.05

| 변형 | 오탐 조건 /12 | 오탐 시행 | 확신 놓침 조건 /5 | 확신 놓침 시행 | 확신 오류 합 | 탐지 조건 /5 | 탐지 시행 | 유보 시행 | 비대상 표지 정답 조건 /12 |
|---|---|---|---|---|---|---|---|---|---|
| F 전체 | 0 | 0/10800 | 2 | 2/4500 | **2** | 5 | 3158/4500 | 5538 | 11 |
| C 대조 실행 제거 | 0 | 0/10800 | 2 | 2/4500 | **2** | 5 | 3824/4500 | 2652 | 12 |
| K 확인 단계 제거 | 1 | 2/10800 | 3 | 4/4500 | **6** | 5 | 3063/4500 | 5964 | 7 |
| A 시행 전체 A1 | 0 | 0/10800 | 1 | 1/4500 | **1** | 3 | 1863/4500 | 8569 | 3 |
| L-P_UV0 | 0 | 0/10800 | 2 | 2/4500 | **2** | 5 | 3155/4500 | 5541 | 11 |
| L-P_BEBS | 0 | 0/10800 | 2 | 5/4500 | **5** | 5 | 3087/4500 | 5606 | 11 |
| L-P_SC_DEC | 0 | 0/10800 | 0 | 0/4500 | **0** | 5 | 3265/4500 | 5094 | 10 |
| L-P_WRONG_CRED | 0 | 0/10800 | 2 | 2/4500 | **2** | 5 | 3158/4500 | 5538 | 10 |
| L-P_TAMPER_K | 0 | 0/10800 | 2 | 2/4500 | **2** | 4 | 2950/4500 | 5745 | 8 |
| L-P_REVOKE | 0 | 0/10800 | 2 | 6/4500 | **6** | 4 | 2905/4500 | 5777 | 11 |
| L-P_CORRUPT | 0 | 0/10800 | 0 | 0/4500 | **0** | 2 | 1631/4500 | 13669 | 0 |
| L-P_CORRUPT_CTR | 0 | 0/10800 | 0 | 0/4500 | **0** | 2 | 1172/4500 | 14128 | 0 |
| T 상태 불변 대조 제거 | 0 | 0/10800 | 3 | 11/4500 | **11** | 3 | 2381/4500 | 6295 | 8 |
| KT 확인+상태 불변 대조 제거 | 1 | 2/10800 | 3 | 31/4500 | **33** | 3 | 1772/4500 | 7215 | 8 |
| M-BB 무효 서명 대조 전부 제거(BE·BS) | 0 | 0/10800 | 0 | 0/4500 | **0** | 0 | 13/4500 | 15287 | 0 |
| M-CTR 무효 서명 대조 전부 제거(카운터) | 0 | 0/10800 | 0 | 0/4500 | **0** | 0 | 32/4500 | 15268 | 0 |

## q = 0 조건별 다수 판정 (F와 다른 것만)

- **C 대조 실행 제거**: authentik-2024.10.5: no_block→no_block {'no_block': 30}
- **A 시행 전체 A1**: authelia-fs1-4.39.28: state_corruption→undetermined {'undetermined': 30}; authelia-mc-4.39.28: state_corruption→undetermined {'undetermined': 30}; authelia-4.39.28: normal_policy→undetermined {'undetermined': 30}; authelia-src-4.39.28: normal_policy→undetermined {'undetermined': 30}
- **L-P_SC_DEC**: authelia-4.39.28: normal_policy→no_block {'no_block': 30}; authelia-src-4.39.28: normal_policy→no_block {'no_block': 30}
- **L-P_TAMPER_K**: keycloak-26.0.7-bf_on: normal_policy→no_block {'no_block': 30}; keycloak-26.0.7-bf_perm: normal_policy→no_block {'no_block': 30}
- **L-P_CORRUPT**: authelia-fs1-4.39.28: state_corruption→undetermined {'undetermined': 30}; authelia-4.39.28: normal_policy→undetermined {'undetermined': 30}; authelia-src-4.39.28: normal_policy→undetermined {'undetermined': 30}; gitea-1.24.0: no_block→undetermined {'undetermined': 30}; authentik-2024.10.5: no_block→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_off: no_block→undetermined {'undetermined': 30}; kanidm-1.12.0: no_block→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_on: normal_policy→undetermined {'undetermined': 30}; vaultwarden-1.35.5: no_block→undetermined {'undetermined': 30}; vaultwarden-1.35.4: state_corruption→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_perm: normal_policy→undetermined {'undetermined': 30}; zitadel-4.20.1: no_block→undetermined {'undetermined': 30}; vaultwarden-1.35.4-synced: no_block→undetermined {'undetermined': 30}; vaultwarden-1.35.5-synced: no_block→undetermined {'undetermined': 30}
- **L-P_CORRUPT_CTR**: authelia-mc-4.39.28: state_corruption→undetermined {'undetermined': 30}; authelia-4.39.28: normal_policy→undetermined {'undetermined': 30}; authelia-src-4.39.28: normal_policy→undetermined {'undetermined': 30}; gitea-1.24.0: no_block→undetermined {'undetermined': 30}; authentik-2024.10.5: no_block→undetermined {'undetermined': 30}; authentik-fs2-2024.10.5: state_corruption→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_off: no_block→undetermined {'undetermined': 30}; kanidm-1.12.0: no_block→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_on: normal_policy→undetermined {'undetermined': 30}; vaultwarden-1.35.5: no_block→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_perm: normal_policy→undetermined {'undetermined': 30}; zitadel-4.20.1: no_block→undetermined {'undetermined': 30}; vaultwarden-1.35.4-synced: no_block→undetermined {'undetermined': 30}; vaultwarden-mc-1.35.5: state_corruption→undetermined {'undetermined': 30}; vaultwarden-1.35.5-synced: no_block→undetermined {'undetermined': 30}
- **T 상태 불변 대조 제거**: authelia-mc-4.39.28: state_corruption→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_on: normal_policy→no_block {'no_block': 30}; keycloak-26.0.7-bf_perm: normal_policy→no_block {'no_block': 30}
- **KT 확인+상태 불변 대조 제거**: authelia-fs1-4.39.28: state_corruption→undetermined {'undetermined': 30}; authelia-mc-4.39.28: state_corruption→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_on: normal_policy→no_block {'no_block': 30}; keycloak-26.0.7-bf_perm: normal_policy→no_block {'no_block': 30}
- **M-BB 무효 서명 대조 전부 제거(BE·BS)**: authelia-fs1-4.39.28: state_corruption→undetermined {'undetermined': 30}; authelia-mc-4.39.28: state_corruption→undetermined {'undetermined': 30}; authelia-4.39.28: normal_policy→undetermined {'undetermined': 30}; authelia-src-4.39.28: normal_policy→undetermined {'undetermined': 30}; gitea-1.24.0: no_block→undetermined {'undetermined': 30}; authentik-2024.10.5: no_block→undetermined {'undetermined': 30}; authentik-fs2-2024.10.5: state_corruption→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_off: no_block→undetermined {'undetermined': 30}; kanidm-1.12.0: no_block→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_on: normal_policy→undetermined {'undetermined': 30}; vaultwarden-1.35.5: no_block→undetermined {'undetermined': 30}; vaultwarden-1.35.4: state_corruption→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_perm: normal_policy→undetermined {'undetermined': 30}; zitadel-4.20.1: no_block→undetermined {'undetermined': 30}; vaultwarden-1.35.4-synced: no_block→undetermined {'undetermined': 30}; vaultwarden-mc-1.35.5: state_corruption→undetermined {'undetermined': 30}; vaultwarden-1.35.5-synced: no_block→undetermined {'undetermined': 30}
- **M-CTR 무효 서명 대조 전부 제거(카운터)**: authelia-fs1-4.39.28: state_corruption→undetermined {'undetermined': 30}; authelia-mc-4.39.28: state_corruption→undetermined {'undetermined': 30}; authelia-4.39.28: normal_policy→undetermined {'undetermined': 30}; authelia-src-4.39.28: normal_policy→undetermined {'undetermined': 30}; gitea-1.24.0: no_block→undetermined {'undetermined': 30}; authentik-2024.10.5: no_block→undetermined {'undetermined': 30}; authentik-fs2-2024.10.5: state_corruption→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_off: no_block→undetermined {'undetermined': 30}; kanidm-1.12.0: no_block→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_on: normal_policy→undetermined {'undetermined': 30}; vaultwarden-1.35.5: no_block→undetermined {'undetermined': 30}; vaultwarden-1.35.4: state_corruption→undetermined {'undetermined': 30}; keycloak-26.0.7-bf_perm: normal_policy→undetermined {'undetermined': 30}; zitadel-4.20.1: no_block→undetermined {'undetermined': 30}; vaultwarden-1.35.4-synced: no_block→undetermined {'undetermined': 30}; vaultwarden-mc-1.35.5: state_corruption→undetermined {'undetermined': 30}; vaultwarden-1.35.5-synced: no_block→undetermined {'undetermined': 30}

소요 2029초
