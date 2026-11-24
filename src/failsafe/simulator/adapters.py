from dataclasses import dataclass
from ..contracts import TargetAdapter, ProbeResult
from ..oracle import ServerStateSnapshot

@dataclass
class SimulatedPolicy:
    label: str; count_normal: bool; check_signcount: bool; require_be_bs: bool; require_uv: bool; revoke_on_tamper: bool; max_failures: int = 5

class SimulatorAdapter(TargetAdapter):
    def __init__(self, policy: SimulatedPolicy):
        self.policy = policy; self.failure_counter = 0; self.is_locked = False; self.is_revoked = False
    def register_credential(self) -> None: pass
    def execute_probe(self, probe_id: str, params: dict) -> ProbeResult:
        if self.is_revoked: return ProbeResult(probe_id, False, "revoked", 10.0, False)
        violation, accepted = False, False
        if probe_id == "P_SC_DEC" and self.policy.check_signcount: violation = True
        elif probe_id == "P_BEBS_FLIP" and self.policy.require_be_bs: violation = True
        elif probe_id == "P_UV0" and self.policy.require_uv: violation = True
        elif probe_id == "P_NORMAL_CANCEL": accepted = False
        else: accepted = True
        if not accepted and not violation:
            if self.policy.count_normal: self.failure_counter += 1
        elif violation:
            if self.policy.revoke_on_tamper: self.is_revoked = True
            self.failure_counter += 1
        if self.failure_counter >= self.policy.max_failures: self.is_locked = True
        return ProbeResult(probe_id, accepted, "NotAllowedError" if not accepted else None, 15.0, not (self.is_locked or self.is_revoked))
    def get_oracle_state(self) -> ServerStateSnapshot:
        return ServerStateSnapshot(self.policy.label, self.failure_counter, self.is_locked, self.is_revoked)
