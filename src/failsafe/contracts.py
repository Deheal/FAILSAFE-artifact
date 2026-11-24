from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .oracle import ServerStateSnapshot


@dataclass
class ProbeResult:
    probe_id: str; accepted: bool; error_code: Optional[str]; latency_ms: float; subsequent_normal_allowed: bool


class TargetAdapter(ABC):
    @abstractmethod
    def register_credential(self) -> None: ...
    @abstractmethod
    def execute_probe(self, probe_id: str, params: dict) -> ProbeResult: ...
    @abstractmethod
    def get_oracle_state(self) -> "ServerStateSnapshot": ...
