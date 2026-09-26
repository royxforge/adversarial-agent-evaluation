from .base import SecurityOracle, event_field
from typing import Dict, Any


class CompositeOracle(SecurityOracle):
    """Evaluate several oracles; success if ANY member fires.

    Used for scenarios that configure multiple checks. Returns the first
    member's success payload (including its violation/severity), otherwise
    ``{"success": False, "violation": None}``.
    """

    def __init__(self, oracles: list[SecurityOracle]):
        if not oracles:
            raise ValueError("CompositeOracle requires at least one member oracle.")
        self.oracles = list(oracles)

    def evaluate(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        for oracle in self.oracles:
            result = oracle.evaluate(observation)
            if result.get("success"):
                return result
        return {"success": False, "violation": None}
