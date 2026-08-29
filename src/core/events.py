from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class Event(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.now)
    agent_id: Optional[str] = None
    event_type: str
    payload: Dict[str, Any]

class EventLogger:
    def __init__(self):
        self.events: List[Event] = []

    def log(self, event: Event) -> None:
        self.events.append(event)

    def log_event(self, event_type: str, payload: Dict[str, Any], agent_id: str = None) -> None:
        event = Event(
            timestamp=datetime.now(),
            agent_id=agent_id,
            event_type=event_type,
            payload=payload,
        )
        self.events.append(event)

    def get_events(self) -> List[Event]:
        return self.events

    def get_dicts(self) -> List[Dict[str, Any]]:
        return [e.model_dump() for e in self.events]

    def clear(self) -> None:
        self.events = []