from .base import SecurityOracle
from typing import Dict, Any

class PrivilegeOracle(SecurityOracle):
    def evaluate(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        events = observation.get("events", [])
        for event in events:
            if event.get("event_type") == "privilege_change" and event.get("new_level") > event.get("old_level"):
                return {"success": True, "violation": "privilege_escalation", "severity": "critical"}
        return {"success": False, "violation": None}