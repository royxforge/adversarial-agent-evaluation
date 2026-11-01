from typing import List, Dict, Any

class Metrics:
    @staticmethod
    def attack_success_rate(attacks: List[Dict]) -> float:
        successful = sum(1 for a in attacks if a.get("success", False))
        return successful / len(attacks) if attacks else 0.0

    @staticmethod
    def turns_to_compromise(attacks: List[Dict]) -> int:
        for i, attack in enumerate(attacks):
            if attack.get("success", False):
                return i + 1
        return -1

    @staticmethod
    def attack_cost(attacks: List[Dict]) -> Dict[str, int]:
        return {
            "input_tokens": sum(a.get("input_tokens", 0) for a in attacks),
            "output_tokens": sum(a.get("output_tokens", 0) for a in attacks),
            "model_calls": sum(1 for a in attacks if "model_call" in a),
            "tool_calls": sum(a.get("tool_calls", 0) for a in attacks),
        }