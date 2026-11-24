# 9차 채점 (사전 등록 docs/round9_plan.md)

| 칸 | 정답 | 시행 | 차단 관측 | FS 판정 분포 | FS 확신 오류 | R4 판정 분포 | R4 확신 오류 |
|---|---|---:|---:|---|---:|---|---:|
| R1-fs2-improved | state_corruption | 30 | 27 | no_block 2, state_corruption 26, undetermined 2 | 2 | no_block 1, state_corruption 26, undetermined 3 | 1 |
| R2-orig-improved | no_block | 30 | 0 | no_block 27, undetermined 3 | 0 | no_block 26, undetermined 4 | 0 |
| R3-rep-base | normal_policy | 30 | 0 | no_block 9, normal_policy 19, undetermined 2 | 9 | no_block 9, normal_policy 2, undetermined 19 | 9 |
| R4-rep-improved | normal_policy | 30 | 0 | no_block 2, normal_policy 25, undetermined 3 | 2 | no_block 1, undetermined 29 | 1 |
| C3-fs2-L10 | state_corruption | 60 | 26 | no_block 25, state_corruption 25, undetermined 10 | 25 | no_block 22, normal_policy 7, state_corruption 25, undetermined 6 | 29 |
| C6-orig-L10 | no_block | 30 | 0 | no_block 26, undetermined 4 | 0 | no_block 25, undetermined 5 | 0 |

사전 기준: {'a_R1_miss_le6_and_rate_below_C3': True, 'b_FS_fp0_R2R3R4': True, 'c_R4_conf_err_le_R3': True, 'all': True}
