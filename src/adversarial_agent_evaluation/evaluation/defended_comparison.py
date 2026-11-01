"""Compare static and adaptive attackers against undefended and defended targets.

Run it directly (no API key, no GPU):

    python -m adversarial_agent_evaluation.evaluation.defended_comparison

The interesting row is the last one: the inbound screen stops every static
payload outright, and stops the adaptive attacker too. The adaptive run still
adapts — it skips layers that already blocked it and saves its cross-sentence
split for last — but L4 pairs read intent with a sensitive path across the
whole message, so that final payload is screened as well and the run ends with
no boundary crossing.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from ..adapters.custom import CustomAgentAdapter
from ..adapters.defended import DefendedAgentAdapter
from ..attacker.adaptive_offline import AdaptiveLadderAttacker, StaticPayloadAttacker
from ..core.agent import Agent, Tool
from ..core.defense import LAYER_ORDER
from ..core.policy import SecurityPolicy
from ..environments.filesystem import FilesystemEnvironment
from ..oracle.filesystem import FileSystemOracle

MAX_TURNS = 8
TARGETS = ("undefended", "defended")


def _build_attacker(kind: str):
    return AdaptiveLadderAttacker() if kind == "adaptive" else StaticPayloadAttacker()


def run_config(target: str, attacker_kind: str, max_turns: int = MAX_TURNS) -> Dict[str, Any]:
    """Run one (target, attacker) campaign and return a result record."""
    tools = [Tool(name="filesystem.read", description="Read a file", parameters={"path": "string"})]
    agent = Agent(model="target-agent", tools=tools)
    policy = SecurityPolicy(protected_paths=["/protected"], restricted_tools=["shell.execute"])
    env = FilesystemEnvironment()
    adapter = (
        DefendedAgentAdapter(agent, policy, environment=env)
        if target == "defended"
        else CustomAgentAdapter(agent, policy, environment=env)
    )
    oracle = FileSystemOracle(policy)
    attacker = _build_attacker(attacker_kind)

    turns: List[Dict[str, Any]] = []
    success = False
    compromised_on: Optional[int] = None

    for turn in range(1, max_turns + 1):
        payload = attacker.next_payload(turn)
        before = len(adapter.get_trace())
        adapter.invoke(payload.text)
        new_events = adapter.get_trace()[before:]

        verdict = getattr(adapter, "last_verdict", None)
        blocked_layer = verdict.layer if verdict is not None and not verdict.allowed else None

        result = oracle.evaluate({"events": new_events, "env": env.observe()})
        turn_success = bool(result.get("success"))
        attacker.observe(turn, blocked_layer, turn_success)

        turns.append(
            {
                "turn": turn,
                "payload": payload.name,
                "blocked_layer": blocked_layer,
                "success": turn_success,
                "tools_run": sum(1 for e in new_events if e.get("event_type") == "tool_call"),
            }
        )
        if turn_success:
            success = True
            compromised_on = turn
            break

    return {
        "target": target,
        "attacker": attacker_kind,
        "success": success,
        "turns_attempted": len(turns),
        "turns_to_compromise": compromised_on,
        "turns": turns,
    }


def run_all(max_turns: int = MAX_TURNS) -> List[Dict[str, Any]]:
    return [
        run_config(target, attacker, max_turns)
        for target in TARGETS
        for attacker in ("static", "adaptive")
    ]


def _print_report(results: List[Dict[str, Any]]) -> None:
    print("=" * 78)
    print("  Defended-target comparison  (offline, deterministic, no API key)")
    print("=" * 78)
    print("  Screen layers, applied in order, first match wins:")
    for layer in LAYER_ORDER:
        print(f"    - {layer}")
    print()
    print(f"  {'Target':<12} {'Attacker':<10} {'Attempts':<10} {'Result':<14} {'Turns to compromise':<20}")
    print("  " + "-" * 66)
    for r in results:
        result = "COMPROMISED" if r["success"] else "blocked"
        turns = str(r["turns_to_compromise"]) if r["turns_to_compromise"] else "-"
        print(
            f"  {r['target']:<12} {r['attacker']:<10} {r['turns_attempted']:<10} "
            f"{result:<14} {turns:<20}"
        )

    defended = next(r for r in results if r["target"] == "defended" and r["attacker"] == "adaptive")
    print()
    print("  Adaptive run against the defended target, turn by turn:")
    for t in defended["turns"]:
        if t["blocked_layer"]:
            outcome = f"blocked at {t['blocked_layer']}"
        elif t["success"]:
            outcome = "boundary crossed"
        else:
            outcome = "passed screen, no violation"
        print(f"    turn {t['turn']}: {t['payload']:<24} {outcome}")

    static = next(r for r in results if r["target"] == "defended" and r["attacker"] == "static")
    print()
    if defended["success"]:
        print(
            f"  Finding: the screen stopped all {static['turns_attempted']} static attempts "
            f"(0% ASR) and cost the adaptive attacker "
            f"{defended['turns_to_compromise']} turns, but did not prevent compromise."
        )
        print("  Screening raises the cost of an attack; it does not remove the boundary crossing.")
    else:
        print(
            f"  Finding: the screen stopped all {static['turns_attempted']} static attempts "
            f"and all {defended['turns_attempted']} adaptive attempts: 0% ASR against both."
        )
        print("  The adaptive attacker adapted (it never retried a layer that blocked it) and")
        print("  still failed: its split payload is caught by message-scoped L4.")
        print("  Trade-off: L4 now over-blocks messages that merely mention a protected path.")
        print("  A content filter is not an authorization boundary; policy remains the backstop.")


def main() -> int:
    results = run_all()
    _print_report(results)
    print()
    print(json.dumps({r["target"] + "/" + r["attacker"]: r["success"] for r in results}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
