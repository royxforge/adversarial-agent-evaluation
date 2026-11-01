from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime


class AttackTrace(BaseModel):
    """Represents a causal chain of events in an attack."""
    steps: List[Dict[str, Any]] = []
    total_events: int = 0


class Finding(BaseModel):
    id: str
    title: str
    severity: str
    affected_agent: str
    attack_vector: str
    precondition: str
    attack: str
    observed_trace: List[str]
    security_boundary_violated: str
    impact: str
    reproduction: str
    mitigation: str
    regression_test: str
    attack_type: str = "unknown"
    turns_to_compromise: int = 0
    attack_cost: Dict[str, Any] = {}
    timestamp: str = ""
    canary_exfiltrated: bool = False

    def model_post_init(self, __context: Any) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
