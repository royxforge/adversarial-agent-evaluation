from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List


class AttackStrategy(ABC):
    """Base class for all attack strategies."""

    def __init__(self, model_provider=None):
        self.model = model_provider
        self._token_count = 0

    @abstractmethod
    def discover(self, target: Any) -> Dict[str, Any]:
        pass

    @abstractmethod
    def generate(self, state: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def evaluate(self, result: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def adapt(self, state: Dict[str, Any]) -> Dict[str, Any]:
        pass

    def get_token_count(self) -> int:
        return self._token_count
