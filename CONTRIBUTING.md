# Contributing to Adversarial Agent Evaluation

Thank you for your interest in contributing. This document provides guidelines and instructions for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch
4. Make your changes
5. Submit a pull request

## Development Setup

```bash
# Clone the repo
git clone https://github.com/royxforge/adversarial-agent-evaluation.git
cd adversarial-agent-evaluation

# Install in development mode
pip install -e ".[test,dev]"

# Run tests
make test

# Run linter
make lint
```

## Code Style

- Follow PEP 8 for Python code
- Use type hints for all function signatures
- Keep functions under 50 lines where possible
- Use descriptive variable names
- Add docstrings to all public classes and methods

## Testing

All contributions must include tests:

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=xml

# Run specific test file
pytest tests/test_unit.py -v
```

### Test Requirements

- Unit tests for all new classes and functions
- Edge-case tests for boundary conditions
- Integration tests for API endpoints
- All tests must pass before merging

## Adding a New Attack Strategy

1. Create a new file in `src/attacks/`
2. Inherit from `AttackStrategy` in `base.py`
3. Implement `discover()`, `generate()`, `evaluate()`, `adapt()`
4. Add the strategy to `src/attacks/__init__.py`
5. Add scenarios in `scenarios/`
6. Add tests in `tests/test_edge_cases.py`

## Adding a New Environment

1. Create a new file in `src/environments/`
2. Inherit from `Environment` in `src/core/environment.py`
3. Implement `reset()`, `execute()`, `observe()`, `snapshot()`, `restore()`
4. Export in `src/environments/__init__.py`
5. Add tests

## Adding a New Oracle

1. Create a new file in `src/oracle/`
2. Inherit from `SecurityOracle` in `base.py`
3. Implement `evaluate()`
4. Export in `src/oracle/__init__.py`
5. Add tests

## Pull Request Process

1. Update documentation if needed
2. Add entries to CHANGELOG.md
3. Ensure all tests pass
4. Request review from maintainers
5. Address review feedback

## Reporting Issues

- Use GitHub Issues for bug reports
- Include steps to reproduce
- Include Python version and OS
- Include relevant log output

## Security

Report security vulnerabilities privately. See SECURITY.md for details.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
