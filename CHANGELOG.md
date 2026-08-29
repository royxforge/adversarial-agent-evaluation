# Changelog

All notable changes to **Adversarial Agent Evaluation** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-29

### Added - PhD-Grade Research Rigor

- Formal threat model definitions (`src/core/threat_model.py`)
  - Attacker capabilities and constraints
  - Target agent trust boundaries
  - Security level classification (0-6)
  - Attack objective types
  - Trust boundary types
- Experiment metadata tracking (`src/evaluation/metadata.py`)
  - Git commit hash and dirty status
  - Python version and platform
  - Model name, provider, and temperature
  - API call counts, token usage, error rates
  - Dependency hash for exact reproduction
  - Unique experiment IDs
- Scenario YAML schema validation (`src/evaluation/schema.py`)
  - Pydantic models for scenario definitions
  - Budget validation (min/max bounds)
  - Scenario registry to prevent duplicates
- Causal attack graph generation (`src/evaluation/attack_graph.py`)
  - DAG representation of attack traces
  - Graphviz DOT export
  - Mermaid flowchart export
  - JSON export
  - Root cause analysis
  - Trust boundary identification
- Baseline comparison runner (`src/evaluation/comparison.py`)
  - Static prompt injection baseline
  - Random mutation baseline
  - Single-shot LLM baseline
  - Adaptive red-team agent
  - Statistical comparison across runs
  - Markdown table output
- Ablation study runner (`src/evaluation/ablation.py`)
  - Full system configuration
  - No memory ablation
  - No planner ablation (random strategy)
  - No adaptation ablation (static strategy)
  - No oracle ablation (no feedback)
  - Component contribution measurement
- Oracle accuracy metrics (`src/evaluation/oracle_accuracy.py`)
  - True Positives / False Positives
  - True Negatives / False Negatives
  - Precision, Recall, F1 Score
  - Accuracy
  - False Positive Rate, False Negative Rate
  - Ground truth generation from events
- Reproducibility protocol (`src/evaluation/reproducibility.py`)
  - Experiment records with full metadata
  - Checksum verification
  - Experiment listing and loading
  - Reproducibility report generation
  - Reproduction command documentation
- Rate limiting with exponential backoff (`src/models/openai_provider.py`)
  - Configurable max retries
  - Exponential backoff with max delay
  - Rate limit detection and logging
  - API usage statistics tracking
- Pinned dependency versions (`pyproject.toml`)
  - Upper bounds on all dependencies
  - Reproducible builds

### Fixed

- Event timestamp bug (datetime.now at import time -> default_factory)
- Bare except blocks replaced with proper error handling + logging
- OpenAI provider now logs rate limit retries

## [0.1.0] - 2026-08-29

### Added

- Core architecture: Agent, Tool, Environment, SecurityPolicy abstractions
- Attack engine with 7 attack strategies
- Attacker components: Planner, Generator, Memory, Strategist, Baselines
- Security Oracle system (4 oracles)
- Target environments (4 environments)
- Agent adapters
- Model providers (OpenAI, Anthropic, Mock)
- Evaluation metrics (ASR, TTC, Severity)
- Reporting (Findings, Reports)
- API and CLI
- 21 benchmark scenarios
- 249 tests (unit + edge-case + integration)
- Docker support
- GitHub Actions CI
- Documentation (README, LICENSE, CHANGELOG, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, CITATION)
