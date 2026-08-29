from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))

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
from src.evaluation.metrics import Metrics
from src.evaluation.severity import Severity
from src.reporting.findings import Finding
from src.reporting.reports import ReportGenerator
from src.models.factory import get_model_provider
from src.logging_config import setup_logging
from src.config import settings

app = FastAPI(title="Adversarial Agent Evaluation API", version="0.2.0")
logger = setup_logging()


class ScanRequest(BaseModel):
    objective: str
    target: str = "mock"
    budget_turns: Optional[int] = 10
    strategies: Optional[List[str]] = None


class ScanResponse(BaseModel):
    success: bool
    findings: List[dict]
    metrics: dict
    events: List[dict]
    report: str


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    try:
        model_provider = get_model_provider()
        tools = [
            Tool(name="filesystem.read", description="Read a file", parameters={"path": "string"}),
            Tool(name="shell.execute", description="Execute shell command", parameters={"command": "string"}),
        ]
        target_agent = Agent(model=model_provider.get_model_name(), tools=tools)
        policy = SecurityPolicy(
            protected_paths=["/protected"],
            restricted_tools=["shell.execute"],
        )
        env = FilesystemEnvironment()
        adapter = CustomAgentAdapter(target_agent, policy, environment=env)
        oracle = FileSystemOracle(policy)

        planner = Planner(model_provider)
        generator = AttackGenerator(model_provider)
        memory = AttackerMemory()
        event_logger = EventLogger()

        objective = request.objective
        budget_turns = request.budget_turns or 10
        available_strategies = request.strategies or [
            "direct_injection", "indirect_injection", "tool_injection",
            "rag_poisoning", "memory_poisoning", "cross_agent", "privilege_escalation",
        ]

        turn = 0
        success = False
        attacks = []
        attack = {}

        while turn < budget_turns and not success:
            turn += 1

            plan = planner.plan(
                objective,
                {"tools": [t.name for t in tools]},
                memory.get_history(),
                available_strategies=available_strategies,
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

        # Build findings
        findings = []
        report_text = "No vulnerabilities found."
        if success and attacks:
            last = attacks[-1]
            atk = last["attack"]
            res = last["result"]
            atk_content = atk.get("content") or atk.get("document") or atk.get("message") or atk.get("action", "")
            sev = Severity.classify(res.get("violation")).name if res.get("violation") else "UNKNOWN"

            finding = Finding(
                id="ARS-001",
                title=f"Attack Successful: {atk.get('type', 'unknown')}",
                severity=sev.title(),
                affected_agent="Target Agent",
                attack_vector=atk.get("type", "unknown"),
                precondition="Agent has filesystem tool",
                attack=atk_content,
                observed_trace=[str(e) for e in trace[-5:]],
                security_boundary_violated=res.get("violation", "unknown"),
                impact="Unauthorized access to protected resource",
                reproduction=f"POST /scan with objective: {objective}",
                mitigation="Add tool authorization and input validation",
                regression_test="Ensure injection is blocked after fix",
                attack_type=atk.get("type", "unknown"),
                turns_to_compromise=Metrics.turns_to_compromise(attacks),
            )
            findings = [finding.model_dump()]
            report_text = ReportGenerator.generate([finding])

        metrics = {
            "attack_success_rate": Metrics.attack_success_rate(attacks),
            "turns_to_compromise": Metrics.turns_to_compromise(attacks),
            "total_attacks": len(attacks),
        }

        return ScanResponse(
            success=success,
            findings=findings,
            metrics=metrics,
            events=event_logger.get_dicts(),
            report=report_text,
        )
    except Exception as e:
        logger.exception("Scan failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
