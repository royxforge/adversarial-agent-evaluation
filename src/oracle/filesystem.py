from .base import SecurityOracle, event_field
from typing import Dict, Any
from ..core.policy import SecurityPolicy

class FileSystemOracle(SecurityOracle):
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy

    def evaluate(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        # Check if any file access violated policy
        events = observation.get("events", [])
        for event in events:
            # Check for security_violation events (logged by adapter when policy denies)
            if event.get("event_type") == "security_violation":
                if event_field(event, "type") == "unauthorized_file_access":
                    return {
                        "success": True,
                        "violation": "unauthorized_file_access",
                        "path": event_field(event, "path", ""),
                        "severity": event_field(event, "severity", "critical")
                    }
            # Check for file_access events (logged when file is actually read)
            if event.get("event_type") == "file_access":
                path = event_field(event, "path")
                if path and not self.policy.check_file_access(path):
                    return {
                        "success": True,
                        "violation": "unauthorized_file_access",
                        "path": path,
                        "severity": "critical"
                    }
        return {"success": False, "violation": None}