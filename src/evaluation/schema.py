"""
Pydantic schemas for scenario YAML validation.

Ensures all scenario files conform to the expected structure
before running benchmarks.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator


class ScenarioConfig(BaseModel):
    """Top-level scenario configuration."""
    name: str
    objective: str
    description: str = ""

    @field_validator("name")
    @classmethod
    def name_must_be_alphanumeric(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"Scenario name must be alphanumeric with _ or -, got: {v}")
        return v


class TargetConfig(BaseModel):
    """Target agent configuration."""
    tools: List[str] = Field(default_factory=lambda: ["filesystem"])
    agents: List[str] = Field(default_factory=list)
    model: str = "mock"


class PolicyConfig(BaseModel):
    """Security policy configuration."""
    protected_paths: List[str] = Field(default_factory=lambda: ["/protected"])
    restricted_tools: List[str] = Field(default_factory=list)


class AttackBudget(BaseModel):
    """Attack budget constraints."""
    turns: int = Field(default=10, ge=1, le=100)
    tokens: int = Field(default=30000, ge=100, le=500000)
    tool_calls: int = Field(default=50, ge=1, le=500)
    time_seconds: int = Field(default=300, ge=10, le=3600)


class ScenarioSeverity(BaseModel):
    """Expected severity levels for violations."""
    unauthorized_file_access: str = "critical"
    unauthorized_database_mutation: str = "critical"
    data_exfiltration: str = "critical"
    privilege_escalation: str = "critical"
    cross_agent_authorization_bypass: str = "critical"
    unauthorized_tool_invocation: str = "high"


class ScenarioDefinition(BaseModel):
    """Complete scenario definition matching YAML structure."""
    scenario: ScenarioConfig
    target: TargetConfig = Field(default_factory=TargetConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    attack_budget: AttackBudget = Field(default_factory=AttackBudget)
    oracle: List[str] = Field(default_factory=lambda: ["unauthorized_file_access"])
    severity: ScenarioSeverity = Field(default_factory=ScenarioSeverity)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScenarioDefinition":
        """Parse a scenario from a dictionary (e.g., loaded YAML)."""
        return cls(**data)


# Scenario registry for validation
SCENARIO_REGISTRY: Dict[str, ScenarioDefinition] = {}


def validate_scenario(data: Dict[str, Any]) -> ScenarioDefinition:
    """Validate and register a scenario definition."""
    scenario = ScenarioDefinition.from_dict(data)
    name = scenario.scenario.name
    if name in SCENARIO_REGISTRY:
        raise ValueError(f"Duplicate scenario name: {name}")
    SCENARIO_REGISTRY[name] = scenario
    return scenario


def validate_scenario_file(file_path: str) -> ScenarioDefinition:
    """Validate a YAML scenario file."""
    import yaml
    with open(file_path) as f:
        data = yaml.safe_load(f)
    return validate_scenario(data)
