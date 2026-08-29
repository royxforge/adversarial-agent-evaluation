from .base import SecurityOracle
from typing import Dict, Any

class DatabaseOracle(SecurityOracle):
    def evaluate(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        events = observation.get("events", [])
        for event in events:
            if event.get("event_type") == "database_mutation" and event.get("table") == "billing":
                return {"success": True, "violation": "unauthorized_database_mutation", "severity": "critical"}
        return {"success": False, "violation": None}