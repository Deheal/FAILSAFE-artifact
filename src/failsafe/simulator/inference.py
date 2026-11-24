from __future__ import annotations
from typing import Dict

from ..policies.profiles import RPPolicy
from .events import FailureEvent


class FailsafeInference:

    def __init__(self, prior_normal: float = 0.85):
        self.prior = {"normal": prior_normal, "tamper": 1.0 - prior_normal}

    def likelihood(self, event: FailureEvent, cause: str,
                   policy: RPPolicy) -> float:
        score = 1.0

        if event.error_name == "SecurityError":
            score *= 3.0 if cause == "tamper" else 0.3

        if event.timing_ms < 1000:
            score *= 1.8 if cause == "tamper" else 0.7
        elif event.timing_ms > 20000:
            score *= 2.0 if cause == "normal" else 0.6

        if (event.assertion_received and policy.observes_uv
                and event.uv_flag == 0):
            score *= 1.5 if cause == "tamper" else 0.9

        if (event.assertion_received and policy.observes_aaguid
                and policy.aaguid_allowlist is not None
                and event.aaguid != b"\x00" * 16
                and event.aaguid not in policy.aaguid_allowlist):
            score *= 1.5 if cause == "tamper" else 0.9

        return max(score, 1e-9)

    def posterior(self, event: FailureEvent,
                  policy: RPPolicy) -> Dict[str, float]:
        unnorm = {c: self.prior[c] * self.likelihood(event, c, policy)
                  for c in ("normal", "tamper")}
        z = sum(unnorm.values())
        return {c: v / z for c, v in unnorm.items()}

    def uncertainty(self, event: FailureEvent, policy: RPPolicy) -> float:
        post = self.posterior(event, policy)
        return 1.0 - max(post.values())

    def risk_score(self, event: FailureEvent, policy: RPPolicy) -> float:
        return self.uncertainty(event, policy) * policy.lambda_penalty()