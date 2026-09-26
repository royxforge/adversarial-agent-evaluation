# Changelog

All notable changes to **Adversarial Agent Evaluation** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-26

### Fixed

- **Oracle trace schema**: database/exfiltration/privilege/filesystem oracles now read nested `EventLogger` payloads (`payload.table`, `payload.destination`, …) with flat-dict backward compatibility, so oracles fire on real benchmark traces instead of only hand-crafted test dicts.
- **Multi-check scenarios**: `build_oracle_for_scenario` returns a `CompositeOracle` covering every configured check; the old `if/elif` chain silently dropped all checks after the first match (e.g. `email_injection.yaml` lost its database-mutation oracle).
- **Scenario validation is now authoritative**: `run_benchmark.py` fails loudly on invalid scenario YAML and runs the validated definition (schema defaults/typos now apply); validation re-runs in one process no longer raise `Duplicate scenario` (`validate_scenario(..., registry=...)`, `clear_scenario_registry()`).
- **Path policy**: `check_file_access` normalises paths and enforces directory boundaries (no `/protected/../…` or `//protected/…` bypass; no `/protected_evil` over-block). `CustomAgentAdapter.write` now enforces the policy and logs `security_violation` like `read`.
- **Attacker memory**: comparison-run memory is recorded via an `on_result` callback with the *current* turn's outcome (was recording `history[-1]`, i.e. the previous turn).

### Changed

- **Packaging**: `pyproject.toml` discovers the `src` package (`where=["."]`, `include=["src*"]`); `pip install -e .` now actually installs the package (previously installed nothing).

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