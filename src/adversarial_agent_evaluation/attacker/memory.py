from typing import List, Dict, Any

class AttackerMemory:
    def __init__(self):
        self.history: List[Dict[str, Any]] = []
        self.working_strategies: List[str] = []
        self.failed_strategies: List[str] = []

    def record_attack(self, attack: Dict[str, Any], result: Dict[str, Any], success: bool) -> None:
        self.history.append({"attack": attack, "result": result, "success": success})
        if success:
            self.working_strategies.append(attack.get("type", "unknown"))
        else:
            self.failed_strategies.append(attack.get("type", "unknown"))

    def get_history(self) -> List[Dict]:
        return self.history