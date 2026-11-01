"""
Oracle accuracy metrics for formal evaluation of the security oracle.

Measures:
- True Positives (TP): Oracle correctly detects violation
- False Positives (FP): Oracle reports violation when none occurred
- True Negatives (TN): Oracle correctly reports no violation
- False Negatives (FN): Oracle misses a real violation

Metrics:
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * (Precision * Recall) / (Precision + Recall)
- Accuracy = (TP + TN) / (TP + TN + FP + FN)
"""
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass


@dataclass
class OracleMetrics:
    """Complete oracle evaluation metrics."""
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        correct = self.true_positives + self.true_negatives
        return correct / total if total > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0

    @property
    def false_negative_rate(self) -> float:
        denom = self.false_negatives + self.true_positives
        return self.false_negatives / denom if denom > 0 else 0.0

    def to_dict(self) -> Dict[str, float]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
        }


def evaluate_oracle(
    oracle_results: List[Dict[str, Any]],
    ground_truth: List[Dict[str, Any]],
) -> OracleMetrics:
    """Evaluate oracle accuracy against ground truth.

    Args:
        oracle_results: List of oracle evaluation results, each with 'success' key
        ground_truth: List of ground truth labels, each with 'has_violation' key

    Returns:
        OracleMetrics with precision, recall, F1, etc.
    """
    metrics = OracleMetrics()

    for oracle_result, truth in zip(oracle_results, ground_truth):
        oracle_says_violation = oracle_result.get("success", False)
        actually_has_violation = truth.get("has_violation", False)

        if oracle_says_violation and actually_has_violation:
            metrics.true_positives += 1
        elif oracle_says_violation and not actually_has_violation:
            metrics.false_positives += 1
        elif not oracle_says_violation and not actually_has_violation:
            metrics.true_negatives += 1
        else:  # not oracle_says_violation and actually_has_violation
            metrics.false_negatives += 1

    return metrics


def create_ground_truth_from_events(
    events: List[Dict[str, Any]],
    policy_protected_paths: List[str] = None,
) -> Dict[str, Any]:
    """Create ground truth label from event trace.

    Ground truth is derived from:
    1. security_violation events (always True)
    2. file_access events on protected paths (True)
    3. No violation events (False)
    """
    protected = policy_protected_paths or ["/protected"]

    for event in events:
        event_type = event.get("event_type", "")
        payload = event.get("payload", {})

        # Security violation is ground truth
        if event_type == "security_violation":
            return {"has_violation": True, "reason": payload.get("type", "unknown")}

        # File access on protected path is ground truth
        if event_type == "file_access":
            path = payload.get("path", "")
            for p in protected:
                if path.startswith(p):
                    return {"has_violation": True, "reason": f"access_to_{path}"}

    return {"has_violation": False, "reason": "no_violation_detected"}


def format_oracle_metrics(metrics: OracleMetrics, oracle_name: str = "Oracle") -> str:
    """Format oracle metrics as a readable string."""
    d = metrics.to_dict()
    return (
        f"{oracle_name} Accuracy Report\n"
        f"{'=' * 40}\n"
        f"True Positives:  {d['true_positives']}\n"
        f"False Positives: {d['false_positives']}\n"
        f"True Negatives:  {d['true_negatives']}\n"
        f"False Negatives: {d['false_negatives']}\n"
        f"{'=' * 40}\n"
        f"Precision:       {d['precision']:.4f}\n"
        f"Recall:          {d['recall']:.4f}\n"
        f"F1 Score:        {d['f1']:.4f}\n"
        f"Accuracy:        {d['accuracy']:.4f}\n"
        f"False Pos Rate:  {d['false_positive_rate']:.4f}\n"
        f"False Neg Rate:  {d['false_negative_rate']:.4f}\n"
    )
