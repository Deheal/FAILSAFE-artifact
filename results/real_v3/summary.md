# 3차 실서버 평가 (자동 생성: scripts/evaluate_real_v3.py)

| 조건 | 정답 | 예상 | 판정 | 예상 일치 | 오탐 | 확신 놓침 | 유보 |
|---|---|---|---|---|---|---|---|
| authelia-4.39.28 | normal_policy | normal_policy(unmodeled_policy) | {'normal_policy(unmodeled_policy)': 30} | 30/30 | 0 | 0 | 0 |
| authelia-fs1-4.39.28 | state_corruption | state_corruption | {'state_corruption': 30} | 30/30 | 0 | 0 | 0 |
| authelia-src-4.39.28 | normal_policy | normal_policy(unmodeled_policy) | {'normal_policy(unmodeled_policy)': 30} | 30/30 | 0 | 0 | 0 |
| authentik-2024.10.5 | no_block | no_block | {'no_block': 29, 'undetermined(defect_probe_missing)': 1} | 29/30 | 0 | 0 | 1 |
| authentik-fs2-2024.10.5 | state_corruption | state_corruption | {'state_corruption': 30} | 30/30 | 0 | 0 | 0 |
| gitea-1.24.0 | no_block | no_block | {'no_block': 30} | 30/30 | 0 | 0 | 0 |
| keycloak-26.0.7-bf_off | no_block | no_block | {'no_block': 30} | 30/30 | 0 | 0 | 0 |
| keycloak-26.0.7-bf_on | normal_policy | normal_policy | {'normal_policy': 30} | 30/30 | 0 | 0 | 0 |
| keycloak-26.0.7-bf_perm | normal_policy | normal_policy | {'normal_policy': 30} | 30/30 | 0 | 0 | 0 |
| vaultwarden-1.35.4 | state_corruption | state_corruption | {'state_corruption': 30} | 30/30 | 0 | 0 | 0 |
| vaultwarden-1.35.4-synced | no_block | no_block | {'no_block': 30} | 30/30 | 0 | 0 | 0 |
| vaultwarden-1.35.5 | no_block | no_block | {'no_block': 30} | 30/30 | 0 | 0 | 0 |
| vaultwarden-1.35.5-synced | no_block | no_block | {'no_block': 30} | 30/30 | 0 | 0 | 0 |

- 오탐이 난 정상 조건: 0 / 10 (시행 0 / 300)
- 모든 시행을 변조로 판정한 결함 조건: 3 / 3
- 예상과 전부 일치한 조건: 12 / 13

## 비교군 (조건별 판정 분포)

| 조건 | 정답 | v2 규칙 | 복구만 | 단순 재시도 | 단일 응답 |
|---|---|---|---|---|---|
| authelia-4.39.28 | normal_policy | {'undetermined': 30} | {'state_corruption': 30} | {'state_corruption': 30} | {'normal_policy': 30} |
| authelia-fs1-4.39.28 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} | {'state_corruption': 30} | {'normal_policy': 30} |
| authelia-src-4.39.28 | normal_policy | {'undetermined': 30} | {'state_corruption': 30} | {'state_corruption': 30} | {'normal_policy': 30} |
| authentik-2024.10.5 | no_block | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} |
| authentik-fs2-2024.10.5 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} | {'state_corruption': 30} | {'normal_policy': 30} |
| gitea-1.24.0 | no_block | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} |
| keycloak-26.0.7-bf_off | no_block | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} |
| keycloak-26.0.7-bf_on | normal_policy | {'normal_policy': 30} | {'normal_policy': 30} | {'state_corruption': 30} | {'normal_policy': 30} |
| keycloak-26.0.7-bf_perm | normal_policy | {'undetermined': 26, 'normal_policy': 4} | {'state_corruption': 26, 'normal_policy': 4} | {'state_corruption': 30} | {'normal_policy': 30} |
| vaultwarden-1.35.4 | state_corruption | {'state_corruption': 30} | {'state_corruption': 30} | {'state_corruption': 30} | {'normal_policy': 30} |
| vaultwarden-1.35.4-synced | no_block | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} |
| vaultwarden-1.35.5 | no_block | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} |
| vaultwarden-1.35.5-synced | no_block | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} | {'normal_policy': 30} |

## B 조건: 1.35.4-synced와 1.35.5-synced의 관측 동일성

- 8개 프로브 중 기호 열 분포가 같은 프로브: 8 / 8
