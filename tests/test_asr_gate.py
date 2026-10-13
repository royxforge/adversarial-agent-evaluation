"""Tests for the benchmark attack-success-rate (ASR) CI gate.

The gate turns the adversarial benchmark into a build-time security check:
``run_benchmark --fail-on-asr 0.25`` fails CI when more than a quarter of the
scenarios managed to compromise the target agent.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from src.run_benchmark import asr_gate

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_gate_trips_when_rate_exceeds_limit():
    tripped, asr = asr_gate(successes=5, total=10, limit=0.25)
    assert tripped is True
    assert asr == pytest.approx(0.5)


def test_gate_passes_when_rate_equals_limit():
    # Strictly-greater comparison: a rate exactly at the limit is allowed.
    tripped, asr = asr_gate(successes=1, total=4, limit=0.25)
    assert tripped is False
    assert asr == pytest.approx(0.25)


def test_gate_passes_when_no_attack_succeeded():
    tripped, asr = asr_gate(successes=0, total=21, limit=0.0)
    assert tripped is False
    assert asr == 0.0


def test_gate_treats_empty_run_as_zero_rate():
    tripped, asr = asr_gate(successes=0, total=0, limit=0.0)
    assert tripped is False
    assert asr == 0.0


@pytest.mark.parametrize("limit", [-0.1, 1.5, float("nan")])
def test_gate_rejects_out_of_range_limits(limit):
    with pytest.raises(ValueError):
        asr_gate(successes=1, total=10, limit=limit)


def test_cli_benchmark_exposes_fail_on_asr_option():
    """The gate must be reachable from the documented CLI surface."""
    result = subprocess.run(
        [sys.executable, "src/cli.py", "benchmark", "--help"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0
    assert "--fail-on-asr" in result.stdout


def test_run_benchmark_main_has_gate_parameter():
    import inspect

    from src.run_benchmark import main

    signature = inspect.signature(main)
    assert "fail_on_asr" in signature.parameters
    assert signature.return_annotation in (int, "int")
