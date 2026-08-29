"""
Experiment metadata for reproducibility and traceability.

Every benchmark run records:
- Git commit hash
- Python version
- Model name and temperature
- Timestamp
- API costs
- Dependency versions
"""
import os
import sys
import hashlib
import subprocess
from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class ExperimentMetadata(BaseModel):
    """Complete metadata for a single experiment run."""
    experiment_id: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    git_commit: str = "unknown"
    git_dirty: bool = False
    python_version: str = ""
    platform: str = ""
    model_name: str = ""
    model_temperature: float = 0.0
    model_provider: str = ""
    api_calls: int = 0
    api_tokens_input: int = 0
    api_tokens_output: int = 0
    api_errors: int = 0
    api_rate_limits: int = 0
    total_duration_seconds: float = 0.0
    scenario_count: int = 0
    successful_attacks: int = 0
    failed_attacks: int = 0
    dependency_hash: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.experiment_id:
            seed = f"{self.timestamp}-{self.model_name}"
            self.experiment_id = hashlib.sha256(seed.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


def collect_metadata(
    model_name: str = "",
    model_provider: str = "",
    model_temperature: float = 0.0,
) -> ExperimentMetadata:
    """Collect system and environment metadata."""
    meta = ExperimentMetadata(
        model_name=model_name,
        model_provider=model_provider,
        model_temperature=model_temperature,
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        platform=f"{sys.platform}",
    )

    # Git info
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            meta.git_commit = result.stdout.strip()

        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            meta.git_dirty = bool(result.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Dependency hash
    try:
        result = subprocess.run(
            ["pip", "freeze"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            meta.dependency_hash = hashlib.sha256(result.stdout.encode()).hexdigest()[:16]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return meta


class CostTracker:
    """Tracks API costs during an experiment run."""

    def __init__(self):
        self.api_calls = 0
        self.tokens_input = 0
        self.tokens_output = 0
        self.errors = 0
        self.rate_limits = 0
        self._start_time = datetime.now()

    def record_call(self, tokens_input: int = 0, tokens_output: int = 0) -> None:
        self.api_calls += 1
        self.tokens_input += tokens_input
        self.tokens_output += tokens_output

    def record_error(self) -> None:
        self.errors += 1

    def record_rate_limit(self) -> None:
        self.rate_limits += 1

    def get_duration(self) -> float:
        return (datetime.now() - self._start_time).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "api_calls": self.api_calls,
            "api_tokens_input": self.tokens_input,
            "api_tokens_output": self.tokens_output,
            "api_errors": self.errors,
            "api_rate_limits": self.rate_limits,
            "total_duration_seconds": self.get_duration(),
        }
