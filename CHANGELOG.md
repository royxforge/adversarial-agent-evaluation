# Changelog

All notable changes to **Adversarial Agent Evaluation** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Demo output no longer depends on the console encoding**: the defended-comparison report printed two em dashes, which Windows consoles encode as cp1252 `0x97` and render as `0x97`/replacement characters when the report is piped or captured. Both lines now use ASCII punctuation, so the `make demo-defended` transcript is identical on every platform. `docs/demo-defended.gif` was re-recorded from a real run, and the screen's `blocked at L4_sentence_intent` column no longer renders as tofu boxes.
- **`src/experiments/` is gitignored**: `run_benchmark`/`cli benchmark` write reproducibility artefacts next to the package, so running the demo left untracked `benchmark_*.json` files in the working tree.

### Added

- **Defended-target mode**: the harness can now score attacks against a target agent that screens inbound content before tool execution — the only configuration where attacker quality is measurable at all, since against an undefended target every attacker reaches 100% ASR on Turn 1 (the undefended row is the control, not a finding). `core/defense.py` implements a four-layer screen applied in order, first match wins: `L1_keyword` (injection markers), `L2_delimiter` (fake role/format delimiters), `L3_authority` (claimed authorization or urgency) and `L4_sentence_intent` (a read verb and a sensitive path anywhere in the same message). A screened message is rejected before the target parses it and leaves only a `defense_blocked` event, whereas an attack that reaches the policy layer still logs `security_violation` — so blocked and attempted-but-denied are distinguishable in the trace. `DefendedAgentAdapter` wraps the existing adapter with that screen, and `python -m adversarial_agent_evaluation.evaluation.defended_comparison` (or `make demo-defended`) runs static and adaptive attackers against both targets offline, deterministically and with no API key: **all 8 static payloads and all 8 adaptive payloads are blocked — 0% ASR against both**, against Turn 1 for both attackers when the screen is absent. L4 is message-scoped rather than sentence-scoped: it pairs a read verb with a sensitive path anywhere in the message, so the cross-sentence split that previously cleared the layer on Turn 5 (path in one sentence, verb in another) is now screened too, while a benign multi-sentence message with no sensitive path still passes. The trade-off it buys is stated rather than hidden — pairing across the whole message **over-blocks** a message that merely mentions a protected path, and a content filter still is not an authorization boundary: the policy layer remains what actually denies the read. Covered by `tests/test_defense.py`, which asserts both directions (the split is blocked *and* the benign multi-sentence message is allowed); demonstrated in `docs/demo-defended.gif` and the README's *Defended-target mode* section.

## [0.3.0] - 2026-10-13

### Added

- **Attack-success-rate gate for CI**: `python src/cli.py benchmark` and `python src/run_benchmark.py` accept `--fail-on-asr <fraction>` and exit `1` when the measured attack success rate exceeds it, so a prompt/model/scenario change that makes the agent easier to compromise fails a pipeline instead of only being visible in the printed report. The observed ASR is always reported before the gate is applied (`--fail-on-asr 0.25` fails above 25%), and a run that produced no measurable ASR fails the gate rather than passing it silently.

### Fixed

- **Packaging metadata**: `pyproject.toml` had a malformed `version = "0.2.0""` line (stray quote); corrected so the file parses (previously `pip`/`pytest` could not read the project config).
- **Loop-variable closures**: the baseline/adaptive generators in `evaluation/comparison.py` and `evaluation/ablation.py` now bind their loop-scoped collaborators (`baseline`, `planner`, `generator`, `memory`) as default arguments, so each closure captures the instance from its own run rather than relying on late binding.

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