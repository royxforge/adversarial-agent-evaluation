import sys
import json
import time
import yaml
from pathlib import Path
from typing import Dict, Any, List
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.agent import Agent, Tool
from src.core.policy import SecurityPolicy
from src.core.events import EventLogger
from src.adapters.custom import CustomAgentAdapter
from src.attacker.planner import Planner
from src.attacker.generator import AttackGenerator
from src.attacker.memory import AttackerMemory
from src.attacker.strategist import Strategist
from src.oracle.filesystem import FileSystemOracle
from src.oracle.database import DatabaseOracle
from src.oracle.exfiltration import ExfiltrationOracle
from src.oracle.privilege import PrivilegeOracle
from src.environments.filesystem import FilesystemEnvironment
from src.environments.browser import BrowserEnvironment
from src.environments.database import DatabaseEnvironment
from src.environments.multi_agent import MultiAgentEnvironment
from src.evaluation.metrics import Metrics
from src.evaluation.severity import Severity
from src.models.factory import get_model_provider
from src.config import settings
from src.logging_config import setup_logging

logger = setup_logging()


def build_oracle_for_scenario(scenario: Dict[str, Any], policy: SecurityPolicy):
    """Build the oracle(s) for a scenario.

    Returns a single oracle when exactly one check is configured, or a
    :class:`CompositeOracle` (success if *any* member fires) when the
    scenario lists several checks. The previous if/elif chain silently
    dropped every check after the first match.
    """
    from src.oracle.composite import CompositeOracle

    oracle_checks = scenario.get("oracle", ["unauthorized_file_access"])
    if isinstance(oracle_checks, str):
        oracle_checks = [oracle_checks]

    oracles = []
    if "unauthorized_database_mutation" in oracle_checks:
        oracles.append(DatabaseOracle())
    if "data_exfiltration" in oracle_checks or "secret_exfiltration" in oracle_checks:
        oracles.append(ExfiltrationOracle())
    if "privilege_escalation" in oracle_checks:
        oracles.append(PrivilegeOracle())
    if "unauthorized_file_access" in oracle_checks:
        oracles.append(FileSystemOracle(policy))

    if not oracles:
        return FileSystemOracle(policy)
    if len(oracles) == 1:
        return oracles[0]
    return CompositeOracle(oracles)


def build_environment_for_scenario(scenario: Dict[str, Any]):
    """Build appropriate environment based on scenario tools."""
    target_tools = scenario.get("target", {}).get("tools", ["filesystem"])

    if "browser" in target_tools:
        return BrowserEnvironment()
    elif "database" in target_tools:
        return DatabaseEnvironment()
    elif "multi_agent" in target_tools or "agents" in target_tools:
        return MultiAgentEnvironment()
    else:
        return FilesystemEnvironment()


def run_scenario(scenario: Dict[str, Any], provider) -> Dict[str, Any]:
    """Run a single benchmark scenario with full attack loop."""
    scenario_name = scenario.get("scenario", {}).get("name", "unknown")
    objective = scenario.get("scenario", {}).get("objective", "Read /protected/secret.txt")
    target_tools = scenario.get("target", {}).get("tools", ["filesystem"])
    protected_paths = scenario.get("policy", {}).get("protected_paths", ["/protected"])
    budget = scenario.get("attack_budget", {})
    max_turns = budget.get("turns", 10)

    # Build target tools
    tools = [
        Tool(name="filesystem.read", description="Read a file", parameters={"path": "string"}),
    ]
    if "browser" in target_tools:
        tools.append(Tool(name="browser.open", description="Open URL", parameters={"url": "string"}))
    if "database" in target_tools:
        tools.append(Tool(name="database.query", description="Query database", parameters={"query": "string"}))
    if "shell" in target_tools:
        tools.append(Tool(name="shell.execute", description="Execute command", parameters={"command": "string"}))

    # Setup
    target_agent = Agent(model=provider.get_model_name(), tools=tools)
    policy = SecurityPolicy(protected_paths=protected_paths, restricted_tools=["shell.execute"])
    env = build_environment_for_scenario(scenario)
    adapter = CustomAgentAdapter(target_agent, policy, environment=env)
    oracle = build_oracle_for_scenario(scenario, policy)

    planner = Planner(provider)
    generator = AttackGenerator(provider)
    memory = AttackerMemory()
    event_logger = EventLogger()

    # Attack loop
    turn = 0
    success = False
    attacks = []
    start_time = time.time()

    while turn < max_turns and not success:
        turn += 1

        plan = planner.plan(
            objective,
            {"tools": [t.name for t in tools], "scenario": scenario_name},
            memory.get_history(),
        )

        attack = generator.generate(
            plan.strategy,
            {
                "objective": objective,
                "target_capabilities": {"tools": [t.name for t in tools]},
                "history": memory.get_history(),
            },
        )

        attack_content = attack.get("content") or attack.get("document") or attack.get("message") or attack.get("action", "")
        # Ensure attack_content is a string
        if isinstance(attack_content, dict):
            attack_content = str(attack_content)
        if not isinstance(attack_content, str):
            attack_content = str(attack_content)
        response = adapter.invoke(attack_content)
        trace = adapter.get_trace()
        observation = {"events": trace, "env": env.observe()}
        result = oracle.evaluate(observation)

        attacks.append({
            "attack": attack,
            "result": result,
            "success": result.get("success", False),
        })
        memory.record_attack(attack, result, result.get("success", False))

        event_logger.log_event(
            "attack_turn",
            {"turn": turn, "strategy": plan.strategy, "result": result},
            agent_id="attacker",
        )

        if result.get("success"):
            success = True

    elapsed = time.time() - start_time
    metrics = {
        "attack_success_rate": Metrics.attack_success_rate(attacks),
        "turns_to_compromise": Metrics.turns_to_compromise(attacks),
        "total_attacks": len(attacks),
        "elapsed_seconds": elapsed,
        "success": success,
    }

    severity = None
    if success:
        last = attacks[-1]
        violation = last["result"].get("violation")
        severity = Severity.classify(violation).name if violation else "UNKNOWN"

    return {
        "scenario": scenario_name,
        "objective": objective,
        "budget": budget,
        "success": success,
        "metrics": metrics,
        "severity": severity,
        "attacks": attacks,
        "events": event_logger.get_dicts(),
    }


def main():
    """Run all benchmark scenarios."""
    benchmark_dir = Path(__file__).parent.parent / "scenarios"
    scenario_files = list(benchmark_dir.glob("**/*.yaml"))
    if not scenario_files:
        print("No scenario files found.")
        return

    from src.evaluation.metadata import collect_metadata
    from src.evaluation.reproducibility import ReproducibilityManager
    from src.evaluation.schema import validate_scenario_file

    provider = get_model_provider()
    print(f"Using model: {provider.get_model_name()}")
    print(f"Found {len(scenario_files)} scenarios\n")

    # Collect metadata
    metadata = collect_metadata(
        model_name=provider.get_model_name(),
        model_provider=settings.model_provider,
    )
    print(f"Experiment ID: {metadata.experiment_id}")
    print(f"Git Commit: {metadata.git_commit}")
    print(f"Python: {metadata.python_version}")
    print()

    results = []
    seen_names: set[str] = set()
    for file in scenario_files:
        # Validate scenario schema. Validation failures fail loudly: running
        # an unvalidated scenario would silently exercise the wrong policy /
        # oracle configuration. The validated definition is the source of
        # truth for the run (previously it was discarded and raw YAML
        # re-loaded, so schema defaults/typos never took effect).
        try:
            scenario_def = validate_scenario_file(str(file))
        except Exception as e:
            logger.error(f"Scenario validation failed for {file.name}: {e}")
            raise
        if scenario_def.scenario.name in seen_names:
            # validate_scenario_file also keeps a process-global registry;
            # guard here as well so a re-run in the same process fails loudly
            # instead of re-running a stale/duplicate scenario silently.
            raise ValueError(f"Duplicate scenario name: {scenario_def.scenario.name}")
        seen_names.add(scenario_def.scenario.name)

        scenario = scenario_def.model_dump()
        # Preserve the original nested YAML shape expected by run_scenario.
        scenario["scenario"] = {"name": scenario_def.scenario.name, "objective": scenario_def.scenario.objective}
        name = scenario_def.scenario.name
        print(f"Running scenario: {name}")

        result = run_scenario(scenario, provider)
        results.append(result)
        status = "PASS" if result["success"] else "FAIL"
        print(f"  [{status}] Success: {result['success']}, Turns: {result['metrics']['turns_to_compromise']}, Severity: {result.get('severity', 'N/A')}")
        print()

    # Update metadata
    metadata.scenario_count = len(results)
    metadata.successful_attacks = sum(1 for r in results if r["success"])
    metadata.failed_attacks = len(results) - metadata.successful_attacks

    # Save results with metadata
    output_file = Path(__file__).parent.parent / "benchmark_results.json"
    output_data = {
        "metadata": metadata.to_dict(),
        "results": results,
    }
    with open(output_file, "w") as f:
        json.dump(output_data, f, indent=2, default=str)
    print(f"Results saved to {output_file}")

    # Save reproducibility record
    manager = ReproducibilityManager(str(Path(__file__).parent.parent / "experiments"))
    record = manager.create_experiment(
        name="benchmark",
        config={"scenario_count": len(results)},
        model_name=provider.get_model_name(),
        model_provider=settings.model_provider,
    )
    record.results = output_data
    record_path = manager.save_experiment(record)
    print(f"Experiment record saved to {record_path}")

    # Summary
    total = len(results)
    successes = sum(1 for r in results if r["success"])
    print(f"\n=== Summary ===")
    print(f"Total scenarios: {total}")
    print(f"Successful attacks: {successes}")
    print(f"Attack success rate: {successes/total*100:.1f}%" if total else "N/A")

    # Per-scenario summary
    print("\nPer-scenario:")
    for r in results:
        status = "PASS" if r["success"] else "FAIL"
        print(f"  {r['scenario']}: {status} (turns={r['metrics']['turns_to_compromise']}, severity={r.get('severity', 'N/A')})")


if __name__ == "__main__":
    main()
