# FAILSAFE — 재현 자료

석사학위논문 「Passkey 인증 차단의 원인을 구분하기 위한 상태 비교 기반 동적 분석 기법」(세종대학교 정보보호학과, 2027)의 재현 자료이다.
판정 엔진(v2.2)과 실험에서 수집한 관측 기록, 논문의 표와 그림 수치를 다시 계산하는 평가 스크립트를 담았다.

*Reproduction package for the master's thesis "A State-Contrast Dynamic Analysis Technique for Distinguishing Credential State Corruption from Legitimate Policy in Passkey Authentication Blocking". It contains the judgment engine (v2.2), the recorded probe observations, and the scripts that recompute every table and figure from them.*

## 구성

| 경로 | 내용 |
|---|---|
| `src/failsafe/inference/` | 판정 엔진: 256개 동작 가설, 가설별 점수(`policy_mapper.py`), 차단 원인 판정(`block_cause.py`), 비교 방식(`baselines.py`) |
| `src/failsafe/probe/` | 8종 프로브 정의(`catalog.py`)와 시뮬레이션 대상 |
| `src/failsafe/simulator/` | 가설에 따라 동작하는 RP 모델(`rp_model.py`)과 시뮬레이션 도구 |
| `src/failsafe/oracle/real_ground_truth.py` | 각 실험 조건의 정답과 근거(소스 위치). 판정 쪽 코드는 이 모듈을 import하지 않는다(`tests/test_isolation.py`) |
| `scripts/` | 논문 수치를 다시 계산하는 평가 스크립트 |
| `scripts/defects/` | 주입한 결함(FS-1, FS-2, 카운터 변이)의 패치와 생성 스크립트 |
| `results/` | 수집한 관측 기록(`observations.jsonl`)과 평가 결과(`summary.json`, `summary.md`) |

`observations.jsonl`의 한 줄은 한 프로브 실행이다. `symbols`는 비정상 요청 이후의 응답 기호 열(ACCEPT/REJECT 등), `control_symbols`는 같은 시점의 정상 흐름 대조 실행 결과이다. 관측 기록에는 정답이나 결함 주입 여부가 들어 있지 않다.

## 재현 방법

Python 3.9 이상, 패키지는 `numpy`, `pandas`, `cryptography`이다. 스크립트가 `src/`를 직접 불러오므로 설치 없이 저장소 최상위에서 실행한다.

```bash
pip install numpy pandas cryptography
python scripts/evaluate_real_v3.py      # 예: 주 평가 13개 조건(표 8, 표 10)
git diff --stat                         # 기록된 결과와 비교
```

각 스크립트는 `results/` 아래의 결과 파일을 다시 쓴다. 다시 계산한 수치는 기록과 같으나, 조건이 나열되는 순서, `소요 … 초` 줄, 일부 `summary.md`에 나중에 덧붙인 해설은 달라질 수 있으므로 수치는 `summary.json`으로 비교한다.

테스트는 `pip install pytest` 후 `pytest`로 실행한다.

무작위 잡음을 쓰는 평가는 시드가 고정되어 있다. `recount_unresolved.py`는 Python 3.9에서 실행해야 기록과 정확히 같다(3.12 이상에서는 실수 합 계산 방식 차이로 15,300건 중 1건이 달라진다).

## 논문 항목과 스크립트

| 논문 | 스크립트 | 결과 파일 |
|---|---|---|
| 3.3.4 판정 기준값 선택(36개 조합) | `select_params_v2.py` | `results/param_selection_v2.json` |
| 3.3.4 민감도 분석(80개 조합) | `evaluate_round6_sensitivity.py` | `results/round6/sensitivity.md` |
| 표 8, 표 10 (주 평가 13개 조건) | `evaluate_real_v3.py` | `results/real_v3/summary.md` |
| 4.5 카운터 변이, Kanidm, Zitadel | `evaluate_real_v4.py` | `results/real_v4/summary.md` |
| 그림 5 (4범주 규칙 판정과 비교) | `evaluate_round7_r4.py` | `results/round7_r4/summary.md` |
| 표 12 검증 1, 검증 2 (블라인드 독립 검증) | `evaluate_round7.py judge 7` → `evaluate 7`, `judge 7b` → `evaluate 7b` | `results/round7/summary.md`, `results/round7b/summary.md` |
| 표 13, 그림 6 (구성요소 제거) | `evaluate_round6_ablation.py` | `results/round6/ablation.md` |
| 4.6 정상 흐름 대조 실행 시뮬레이션 | `round8/t1_sim.py` (장애 비율 5%), 10%는 아래 참고 | `results/round8/t1_sim/sim_f05.json`, `sim_f10.json` |
| 표 14, 그림 7 (기록된 결과에 잡음 적용) | `evaluate_round5_a.py`, `recount_unresolved.py` | `results/round5_a/summary.md`, `results/recount_unresolved/` |
| 4.7.1 폐기 정책을 포함한 시뮬레이션 | `evaluate_sim_v21.py dev`, `evaluate_sim_v21.py test` | `results/sim_eval_v22_test.json` |
| 4.7.2 (실제 서버에 일시 실패 주입) | `evaluate_round5_b.py` | `results/round5_b/summary.md` |
| 표 15 (읽기 복제본 지연) | `round8/t3_evaluate.py`, `round9/evaluate.py` | `results/round8/t3/summary.md`, `results/round9/summary.md` |
| 원인 미확정 차단 분리 집계(4.5, 4.7) | `recount_unresolved_other.py` | `results/recount_unresolved/other.json` |

`evaluate_round6_ablation.py`는 `results/round5_a/summary.json`을 읽으므로 `evaluate_round5_a.py` 다음에 실행한다.

`round8/t1_sim.py`는 결과를 `results/round8/t1_sim/sim.json`에 쓴다. 기본 실행(장애 비율 5%)의 결과는 `sim_f05.json`과 같고, 10%는 다음과 같이 실행하며 결과는 `sim_f10.json`과 같다.

```bash
python -c "import sys; sys.path.insert(0, 'scripts/round8'); import t1_sim; t1_sim.run(f=0.1)"
```

## 실험 조건

모든 서버는 로컬에 설치하여 시험하였다. 버전과 설정은 논문 4.1절과 `src/failsafe/oracle/real_ground_truth.py`에 있다.
Vaultwarden 1.35.4의 결함은 공개된 취약점 CVE-2026-31835(GHSA-x7g7-cgx5-jhx2)이다. 나머지 결함은 연구자가 로컬 빌드에 주입한 것으로, 배포판의 취약점이 아니다.

## 실서버 수집 코드 (참고용)

`src/failsafe/probe/real/`(서버별 어댑터)과 `scripts/run_real.py`, `scripts/run_real_fault.py`는 관측 기록을 수집할 때 사용한 클라이언트이다. 프로브 절차는 시뮬레이션과 같은 코드(`probe/catalog.py`)가 정하고, 어댑터는 요청 하나를 보내 응답을 기호로 바꾸기만 한다.

이 코드는 소프트웨어 인증기와 일부 서버의 설정 도구를 이전 연구의 별도 코드(`PPL_SCRIPTS` 환경 변수로 지정)에서 불러오며, 그 코드는 이 저장소에 포함하지 않았다. 따라서 이 저장소만으로는 실행되지 않으며, 수집 절차를 확인하기 위한 참고 자료로 제공한다. 코드에 적힌 계정 비밀번호는 로컬 시험 서버에서만 쓴 값이다.

## 라이선스

코드는 MIT 라이선스, 관측 기록과 결과는 CC BY 4.0을 따른다. `scripts/defects/`의 패치와 `authentik_challenge.*.py`는 각 원본 프로젝트의 라이선스를 따른다.
