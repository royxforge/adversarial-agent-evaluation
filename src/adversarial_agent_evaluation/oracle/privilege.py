from .base import SecurityOracle, event_field
from typing import Dict, Any

class PrivilegeOracle(SecurityOracle):
    def evaluate(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        events = observation.get("events", [])
        for event in events:
            if event.get("event_type") == "privilege_change" and event_field(event, "new_level", 0) > event_field(event, "old_level", 0):
                return {"success": True, "violation": "privilege_escalation", "severity": "critical"}
        return {"success": False, "violation": None}