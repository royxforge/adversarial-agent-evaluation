from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    model_provider: str = "openai"
    model_name: str = "gpt-4"
    max_turns: int = 30
    max_tokens: int = 50000
    max_tool_calls: int = 50
    max_execution_time: int = 300
    log_level: str = "INFO"
    database_url: str = "sqlite:///./red_team.db"

    model_config = {"env_file": ".env"}

settings = Settings()