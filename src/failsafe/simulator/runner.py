from __future__ import annotations
from typing import Any, Dict, List

import numpy as np
import pandas as pd

from ..policies.profiles import POLICY_PROFILES, POLICY_PROFILES_V2, RPPolicy
from .events import generate_failure_event, SCENARIOS
from .rp import RPSessionState, rp_process_failure, rp_process_normal_assertion
from .inference import FailsafeInference


def run_single_trial(policy: RPPolicy, scenario: str,
                     failsafe: FailsafeInference,
                     rng: np.random.Generator) -> Dict[str, Any]:
    state = RPSessionState()
    t = 0.0
    last_event = None

    base = policy.max_failures_before_lock
    n_prior = int(rng.integers(max(1, base - 1), base + 2))

    for _ in range(n_prior):
        event = generate_failure_event(scenario, rng)
        rp_process_failure(policy, event, state, t)
        last_event = event
        t += float(rng.exponential(2.0))

    post = failsafe.posterior(last_event, policy)
    uncertainty = 1.0 - max(post.values())
    risk = uncertainty * policy.lambda_penalty()
    normal_result = rp_process_normal_assertion(policy, state, t + 0.5)

    return {
        "policy": policy.name,
        "scenario": scenario,
        "cause": last_event.cause,
        "n_prior_failures": n_prior,
        "count_normal_failure": policy.count_normal_failure,
        "max_failures_threshold": policy.max_failures_before_lock,
        "lock_duration_sec": policy.lock_duration_sec,
        "lambda_penalty": policy.lambda_penalty(),
        "posterior_normal": post["normal"],
        "posterior_tamper": post["tamper"],
        "uncertainty": uncertainty,
        "risk_score": risk,
        "subsequent_accepted": normal_result["accepted"],
        "shadow_blocked": normal_result["reason"] == "shadow_blocked",
    }


def run_experiment(n_trials_per_cell: int = 200, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    failsafe = FailsafeInference(prior_normal=0.85)
    rows: List[Dict[str, Any]] = []
    for policy in POLICY_PROFILES.values():
        for scenario in SCENARIOS:
            for _ in range(n_trials_per_cell):
                rows.append(run_single_trial(policy, scenario, failsafe, rng))
    return pd.DataFrame(rows)


def run_single_trial_v2(policy: RPPolicy, scenario: str,
                        failsafe: FailsafeInference,
                        rng: np.random.Generator,
                        fixed_prior_failures: int = 3) -> Dict[str, Any]:
    state = RPSessionState()
    t = 0.0
    last_event = None

    for _ in range(fixed_prior_failures):
        event = generate_failure_event(scenario, rng)
        rp_process_failure(policy, event, state, t)
        last_event = event
        t += float(rng.exponential(2.0))

    post = failsafe.posterior(last_event, policy)
    uncertainty = 1.0 - max(post.values())
    risk = uncertainty * policy.lambda_penalty()
    normal_result = rp_process_normal_assertion(policy, state, t + 0.5)

    return {
        "policy": policy.name,
        "scenario": scenario,
        "cause": last_event.cause,
        "fixed_prior_failures": fixed_prior_failures,
        "count_normal_failure": policy.count_normal_failure,
        "max_failures_threshold": policy.max_failures_before_lock,
        "lock_duration_sec": policy.lock_duration_sec,
        "lambda_penalty": policy.lambda_penalty(),
        "posterior_normal": post["normal"],
        "posterior_tamper": post["tamper"],
        "uncertainty": uncertainty,
        "risk_score": risk,
        "subsequent_accepted": normal_result["accepted"],
        "shadow_blocked": normal_result["reason"] == "shadow_blocked",
    }


def run_experiment_v2(n_trials_per_cell: int = 200,
                      seed: int = 42,
                      fixed_prior_failures: int = 3) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    failsafe = FailsafeInference(prior_normal=0.85)
    rows: List[Dict[str, Any]] = []
    for policy in POLICY_PROFILES_V2.values():
        for scenario in SCENARIOS:
            for _ in range(n_trials_per_cell):
                rows.append(run_single_trial_v2(
                    policy, scenario, failsafe, rng,
                    fixed_prior_failures=fixed_prior_failures,
                ))
    return pd.DataFrame(rows)


LAMBDA_USER_DEFAULT: float = 5.0


def run_single_trial_v3(policy: RPPolicy, scenario: str,
                        failsafe: FailsafeInference,
                        rng: np.random.Generator,
                        lambda_user: float = LAMBDA_USER_DEFAULT) -> Dict[str, Any]:
    state = RPSessionState()
    t = 0.0
    last_event = None

    n_prior = int(rng.poisson(lambda_user))
    n_prior = max(1, n_prior)

    for _ in range(n_prior):
        event = generate_failure_event(scenario, rng)
        rp_process_failure(policy, event, state, t)
        last_event = event
        t += float(rng.exponential(2.0))

    post = failsafe.posterior(last_event, policy)
    uncertainty = 1.0 - max(post.values())
    risk = uncertainty * policy.lambda_penalty()
    normal_result = rp_process_normal_assertion(policy, state, t + 0.5)

    return {
        "policy": policy.name,
        "scenario": scenario,
        "cause": last_event.cause,
        "n_prior_failures": n_prior,
        "lambda_user": lambda_user,
        "count_normal_failure": policy.count_normal_failure,
        "max_failures_threshold": policy.max_failures_before_lock,
        "lock_duration_sec": policy.lock_duration_sec,
        "lambda_penalty": policy.lambda_penalty(),
        "posterior_normal": post["normal"],
        "posterior_tamper": post["tamper"],
        "uncertainty": uncertainty,
        "risk_score": risk,
        "subsequent_accepted": normal_result["accepted"],
        "shadow_blocked": normal_result["reason"] == "shadow_blocked",
    }


def run_experiment_v3(n_trials_per_cell: int = 200,
                      seed: int = 42,
                      lambda_user: float = LAMBDA_USER_DEFAULT) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    failsafe = FailsafeInference(prior_normal=0.85)
    rows: List[Dict[str, Any]] = []
    for policy in POLICY_PROFILES_V2.values():
        for scenario in SCENARIOS:
            for _ in range(n_trials_per_cell):
                rows.append(run_single_trial_v3(
                    policy, scenario, failsafe, rng,
                    lambda_user=lambda_user,
                ))
    return pd.DataFrame(rows)