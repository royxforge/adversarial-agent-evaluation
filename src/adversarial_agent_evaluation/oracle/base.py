from abc import ABC, abstractmethod
from typing import Dict, Any


def event_field(event: Dict[str, Any], key: str, default: Any = None) -> Any:
    """Read a field from a trace event, preferring ``payload``.

    Real traces are ``{timestamp, agent_id, event_type, payload}`` (see
    ``EventLogger.get_dicts``), so oracle checks must look inside ``payload``.
    Flat dicts are still accepted for backwards compatibility with legacy
    hand-built events.
    """
    payload = event.get("payload")
    if isinstance(payload, dict) and key in payload:
        return payload[key]
    return event.get(key, default)


class SecurityOracle(ABC):
    @abstractmethod
    def evaluate(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        pass