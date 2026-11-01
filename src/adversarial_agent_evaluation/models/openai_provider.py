"""
OpenAI model provider with rate limiting and retry logic.
"""
import time
import logging
from typing import List, Dict, Any, Optional
from .provider import ModelProvider
from ..config import settings

logger = logging.getLogger(__name__)


class OpenAIProvider(ModelProvider):
    """OpenAI API provider with automatic retry and rate limit handling."""

    def __init__(
        self,
        max_retries: int = 5,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        temperature: float = 0.7,
    ):
        import openai
        self.client = openai.OpenAI(api_key=settings.openai_api_key)
        self.model = settings.model_name
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.temperature = temperature
        self._call_count = 0
        self._error_count = 0
        self._rate_limit_count = 0

    def generate(self, prompt: str, system: str = "") -> str:
        """Generate text with retry logic for rate limits."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        return self._call_with_retry(messages)

    def generate_with_tools(
        self, prompt: str, tools: List[Dict], system: str = ""
    ) -> Dict[str, Any]:
        """Generate with tool use and retry logic."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        return self._call_with_retry(messages, tools=tools)

    def _call_with_retry(
        self, messages: List[Dict], tools: Optional[List[Dict]] = None
    ) -> Any:
        """Make API call with exponential backoff retry."""
        delay = self.base_delay
        last_error = None

        for attempt in range(self.max_retries):
            try:
                self._call_count += 1
                kwargs = {
                    "model": self.model,
                    "messages": messages,
                    "temperature": self.temperature,
                }
                if tools:
                    kwargs["tools"] = tools
                    kwargs["tool_choice"] = "auto"

                response = self.client.chat.completions.create(**kwargs)
                return response.choices[0].message

            except Exception as e:
                self._error_count += 1
                last_error = e
                error_str = str(e).lower()

                if "rate_limit" in error_str or "429" in error_str:
                    self._rate_limit_count += 1
                    logger.warning(
                        f"Rate limit hit (attempt {attempt + 1}/{self.max_retries}), "
                        f"waiting {delay:.1f}s"
                    )
                    time.sleep(delay)
                    delay = min(delay * 2, self.max_delay)
                elif "timeout" in error_str or "504" in error_str:
                    logger.warning(f"Timeout (attempt {attempt + 1}), retrying...")
                    time.sleep(delay)
                    delay = min(delay * 2, self.max_delay)
                else:
                    logger.error(f"API error: {e}")
                    raise

        raise RuntimeError(
            f"API call failed after {self.max_retries} retries. Last error: {last_error}"
        )

    def get_model_name(self) -> str:
        return self.model

    def get_stats(self) -> Dict[str, int]:
        """Return API usage statistics."""
        return {
            "calls": self._call_count,
            "errors": self._error_count,
            "rate_limits": self._rate_limit_count,
        }
