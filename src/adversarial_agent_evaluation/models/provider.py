from abc import ABC, abstractmethod
from typing import List, Dict, Any

class ModelProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str, system: str = "") -> str:
        pass

    @abstractmethod
    def generate_with_tools(self, prompt: str, tools: List[Dict], system: str = "") -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        pass