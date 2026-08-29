"""
Reproducibility protocol for experiment tracking.

Ensures every experiment can be:
1. Identified uniquely
2. Reproduced exactly
3. Verified against expected results
4. Compared across runs
"""
import os
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from pydantic import BaseModel, Field

from .metadata import ExperimentMetadata, collect_metadata


class ExperimentRecord(BaseModel):
    """Complete record of an experiment run."""
    experiment_id: str
    metadata: ExperimentMetadata
    config: Dict[str, Any] = Field(default_factory=dict)
    results: Dict[str, Any] = Field(default_factory=dict)
    attack_graphs: List[Dict[str, Any]] = Field(default_factory=list)
    oracle_metrics: Dict[str, Any] = Field(default_factory=dict)
    comparison: Dict[str, Any] = Field(default_factory=dict)
    ablation: Dict[str, Any] = Field(default_factory=dict)
    checksum: str = ""

    def compute_checksum(self) -> str:
        """Compute checksum of results for verification."""
        data = json.dumps(self.results, sort_keys=True, default=str)
        self.checksum = hashlib.sha256(data.encode()).hexdigest()[:16]
        return self.checksum


class ReproducibilityManager:
    """Manages experiment records for reproducibility."""

    def __init__(self, results_dir: str = "experiments"):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(exist_ok=True)
        self.records: List[ExperimentRecord] = []

    def create_experiment(
        self,
        name: str,
        config: Dict[str, Any] = None,
        model_name: str = "",
        model_provider: str = "",
        model_temperature: float = 0.0,
    ) -> ExperimentRecord:
        """Create a new experiment record with full metadata."""
        metadata = collect_metadata(
            model_name=model_name,
            model_provider=model_provider,
            model_temperature=model_temperature,
        )

        record = ExperimentRecord(
            experiment_id=f"{name}_{metadata.experiment_id}",
            metadata=metadata,
            config=config or {},
        )

        self.records.append(record)
        return record

    def save_experiment(self, record: ExperimentRecord) -> str:
        """Save experiment record to disk."""
        record.compute_checksum()
        filename = f"{record.experiment_id}.json"
        filepath = self.results_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(record.model_dump_json(indent=2))

        return str(filepath)

    def load_experiment(self, experiment_id: str) -> ExperimentRecord:
        """Load an experiment record from disk."""
        filepath = self.results_dir / f"{experiment_id}.json"
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return ExperimentRecord(**data)

    def verify_experiment(self, record: ExperimentRecord) -> bool:
        """Verify experiment integrity via checksum."""
        stored_checksum = record.checksum
        record.compute_checksum()
        return stored_checksum == record.checksum

    def list_experiments(self) -> List[Dict[str, Any]]:
        """List all saved experiments."""
        experiments = []
        for filepath in sorted(self.results_dir.glob("*.json")):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                experiments.append({
                    "id": data.get("experiment_id", "unknown"),
                    "timestamp": data.get("metadata", {}).get("timestamp", "unknown"),
                    "model": data.get("metadata", {}).get("model_name", "unknown"),
                    "checksum": data.get("checksum", "unknown"),
                })
            except (json.JSONDecodeError, KeyError):
                continue
        return experiments

    def generate_reproducibility_report(self, record: ExperimentRecord) -> str:
        """Generate a reproducibility report for an experiment."""
        m = record.metadata
        report = f"""# Experiment Reproducibility Report

## Experiment ID: {record.experiment_id}

### Environment
- Python: {m.python_version}
- Platform: {m.platform}
- Git Commit: {m.git_commit}
- Git Dirty: {m.git_dirty}
- Dependencies Hash: {m.dependency_hash}

### Model Configuration
- Provider: {m.model_provider}
- Model: {m.model_name}
- Temperature: {m.model_temperature}

### Run Statistics
- API Calls: {m.api_calls}
- Tokens (Input): {m.api_tokens_input}
- Tokens (Output): {m.api_tokens_output}
- API Errors: {m.api_errors}
- Rate Limits Hit: {m.api_rate_limits}
- Duration: {m.total_duration_seconds:.1f}s

### Results
- Scenarios: {m.scenario_count}
- Successful Attacks: {m.successful_attacks}
- Failed Attacks: {m.failed_attacks}

### Checksum: {record.checksum}

### Reproduction Command
```bash
pip install -e .
export OPENAI_API_KEY=<your-key>
python src/run_benchmark.py
```
"""
        return report


def save_experiment_results(
    results: Dict[str, Any],
    experiment_name: str = "benchmark",
    output_dir: str = "experiments",
) -> str:
    """Convenience function to save experiment results."""
    manager = ReproducibilityManager(output_dir)
    record = manager.create_experiment(
        name=experiment_name,
        config=results.get("config", {}),
        model_name=results.get("model", ""),
    )
    record.results = results
    return manager.save_experiment(record)
