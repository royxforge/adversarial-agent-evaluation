from typing import Dict, Any, List
from .planner import AttackPlan, VALID_STRATEGIES
from .memory import AttackerMemory


class Strategist:
    """Selects attack strategies adaptively based on memory of past attempts."""

    def __init__(self, memory: AttackerMemory):
        self.memory = memory

    def choose_strategy(
        self,
        objective: str,
        target_capabilities: Dict[str, Any],
        history: List[Dict],
    ) -> AttackPlan:
        """Choose the best strategy based on past successes and failures."""
        working = set(self.memory.working_strategies)
        failed = set(self.memory.failed_strategies)

        # If a strategy already worked, try it again first
        if working:
            best = list(working)[0]
            return AttackPlan(
                strategy=best,
                steps=[f"Repeat successful {best} attack"],
                tools_to_use=[],
            )

        # Try strategies that haven't failed yet
        untried = [s for s in VALID_STRATEGIES if s not in failed]
        if untried:
            return AttackPlan(
                strategy=untried[0],
                steps=[f"Attempt untried {untried[0]} attack"],
                tools_to_use=[],
            )

        # All strategies tried and failed — pick the least-failed one
        fail_counts = {}
        for h in history:
            stype = h.get("attack", {}).get("type", "direct_injection")
            if not h.get("success", False):
                fail_counts[stype] = fail_counts.get(stype, 0) + 1

        if fail_counts:
            best = min(fail_counts, key=fail_counts.get)
            return AttackPlan(
                strategy=best,
                steps=[f"Retry least-failed {best} with variation"],
                tools_to_use=[],
            )

        # Absolute fallback
        return AttackPlan(
            strategy="direct_injection",
            steps=["Default direct injection attempt"],
            tools_to_use=[],
        )
