from abc import ABC, abstractmethod
from typing import Dict, Any

class SecurityOracle(ABC):
    @abstractmethod
    def evaluate(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        pass