from .provider import ModelProvider
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .mock_provider import MockProvider
from ..config import settings

def get_model_provider() -> ModelProvider:
    # Use mock if no API key is set for the selected provider
    if settings.model_provider == "openai" and not settings.openai_api_key:
        return MockProvider()
    if settings.model_provider == "anthropic" and not settings.anthropic_api_key:
        return MockProvider()
    provider_map = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
    }
    provider_class = provider_map.get(settings.model_provider)
    if not provider_class:
        return MockProvider()  # fallback
    return provider_class()