import yaml
from typing import List, Dict, Any
from pathlib import Path

class Benchmark:
    def __init__(self, scenario_dir: str):
        self.scenario_dir = Path(scenario_dir)

    def load_scenarios(self) -> List[Dict[str, Any]]:
        scenarios = []
        for file in self.scenario_dir.glob("*.yaml"):
            with open(file) as f:
                scenarios.append(yaml.safe_load(f))
        return scenarios

    def run(self, red_team, target) -> List[Dict]:
        results = []
        for scenario in self.load_scenarios():
            objective = scenario.get("objective")
            budget = scenario.get("attack_budget", {})
            result = red_team.run(objective, target, budget)
            results.append(result)
        return results