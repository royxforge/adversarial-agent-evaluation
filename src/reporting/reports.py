from typing import List, Dict, Any
from .findings import Finding


class ReportGenerator:
    """Generates comprehensive vulnerability reports from findings."""

    @staticmethod
    def generate(findings: List[Finding]) -> str:
        """Generate a full vulnerability report in Markdown format."""
        report = "# Adversarial Agent Evaluation Security Report\n\n"
        report += f"**Total Findings:** {len(findings)}\n\n"

        # Summary by severity
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        report += "## Severity Summary\n\n"
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = severity_counts.get(sev, 0)
            if count:
                report += f"- **{sev}:** {count}\n"
        report += "\n---\n\n"

        # Individual findings
        for i, finding in enumerate(findings, 1):
            report += f"## Finding {i}: {finding.id}\n\n"
            report += f"**Title:** {finding.title}\n\n"
            report += f"**Severity:** {finding.severity}\n\n"
            report += f"**Attack Type:** {finding.attack_type}\n\n"
            report += f"**Affected Agent:** {finding.affected_agent}\n\n"
            report += f"**Attack Vector:** {finding.attack_vector}\n\n"
            report += f"**Timestamp:** {finding.timestamp}\n\n"

            report += "### Precondition\n\n"
            report += f"{finding.precondition}\n\n"

            report += "### Attack\n\n"
            report += f"```\n{finding.attack}\n```\n\n"

            report += "### Observed Trace\n\n"
            report += "```\n"
            for step in finding.observed_trace:
                report += f"  → {step}\n"
            report += "```\n\n"

            report += "### Security Boundary Violated\n\n"
            report += f"{finding.security_boundary_violated}\n\n"

            report += "### Impact\n\n"
            report += f"{finding.impact}\n\n"

            if finding.turns_to_compromise > 0:
                report += "### Metrics\n\n"
                report += f"- **Turns to Compromise:** {finding.turns_to_compromise}\n"
                if finding.attack_cost:
                    report += f"- **Attack Cost:** {finding.attack_cost}\n"
                if finding.canary_exfiltrated:
                    report += "- **Canary Exfiltrated:** Yes\n"
                report += "\n"

            report += "### Reproduction\n\n"
            report += f"```\n{finding.reproduction}\n```\n\n"

            report += "### Mitigation\n\n"
            report += f"{finding.mitigation}\n\n"

            report += "### Regression Test\n\n"
            report += f"```\n{finding.regression_test}\n```\n\n"

            report += "---\n\n"

        return report

    @staticmethod
    def generate_summary(results: List[Dict[str, Any]]) -> str:
        """Generate a summary report from benchmark results."""
        total = len(results)
        successes = sum(1 for r in results if r.get("success", False))

        report = "# Benchmark Summary\n\n"
        report += f"**Total Scenarios:** {total}\n"
        report += f"**Successful Attacks:** {successes}\n"
        report += f"**Attack Success Rate:** {successes/total*100:.1f}%\n\n" if total else ""

        report += "## Per-Scenario Results\n\n"
        report += "| Scenario | Success | Turns | Severity |\n"
        report += "|----------|---------|-------|----------|\n"
        for r in results:
            name = r.get("scenario", "unknown")
            success = "✅" if r.get("success") else "❌"
            turns = r.get("metrics", {}).get("turns_to_compromise", -1)
            severity = r.get("severity", "N/A") or "N/A"
            report += f"| {name} | {success} | {turns} | {severity} |\n"

        return report
