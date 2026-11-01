from abc import ABC, abstractmethod
from typing import Dict, Any, List
from ..core.agent import Agent

class AgentAdapter(ABC):
    @abstractmethod
    def invoke(self, prompt: str, context: Dict[str, Any] = None) -> str:
        pass

    @abstractmethod
    def get_tools(self) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_trace(self) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def reset(self) -> None:
        pass

    @abstractmethod
    def get_state(self) -> Dict[str, Any]:
        pass