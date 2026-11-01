import anthropic
from typing import List, Dict, Any
from .provider import ModelProvider
from ..config import settings

class AnthropicProvider(ModelProvider):
    def __init__(self):
        self.client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        self.model = "claude-3-opus-20240229"

    def generate(self, prompt: str, system: str = "") -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text

    def generate_with_tools(self, prompt: str, tools: List[Dict], system: str = "") -> Dict[str, Any]:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": prompt}],
            tools=tools
        )
        return response

    def get_model_name(self) -> str:
        return self.model