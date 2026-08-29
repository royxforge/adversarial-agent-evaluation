from abc import ABC, abstractmethod
from typing import Any, Dict

class Environment(ABC):
    @abstractmethod
    def reset(self) -> None:
        pass

    @abstractmethod
    def execute(self, action: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    def observe(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def snapshot(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def restore(self, state: Dict[str, Any]) -> None:
        pass