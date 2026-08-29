from typing import List, Dict, Any
from .provider import ModelProvider

class MockProvider(ModelProvider):
    def generate(self, prompt: str, system: str = "") -> str:
        # Simulate a successful attack generation
        return "Direct injection attack"

    def generate_with_tools(self, prompt: str, tools: List[Dict], system: str = "") -> Dict[str, Any]:
        return {"content": "Mock tool call"}

    def get_model_name(self) -> str:
        return "mock"