from __future__ import annotations

from typing import Optional

from ..policies.profiles import RPPolicy
from ..simulator.attribution import DEVICE_BOUND, VictimProfile
from ..simulator.rp import RPSessionState, rp_register_credential
from ..simulator.rp_model import Request, rp_handle


class SimSession:

    def __init__(self, policy: RPPolicy, victim: VictimProfile):
        self.policy = policy
        self.state = RPSessionState()
        self._counter = self.state.last_sign_count
        rp_register_credential(policy, self.state, *victim.registered)
        if tuple(victim.current) != tuple(victim.registered):
            self.send(Request("valid", *victim.current, counter=self.next_counter()), at=-1.0)

    def next_counter(self) -> int:
        self._counter += 1
        return self._counter

    def send(self, request: Request, at: float) -> str:
        symbol, _ = rp_handle(self.policy, self.state, request, at)
        return symbol


class SimTarget:
    def __init__(self, policy: RPPolicy, victim: Optional[VictimProfile] = None):
        self.policy = policy
        self.victim = victim or DEVICE_BOUND

    def new_session(self) -> SimSession:
        return SimSession(self.policy, self.victim)
