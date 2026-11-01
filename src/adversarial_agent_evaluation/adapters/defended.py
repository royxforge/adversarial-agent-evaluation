"""Target agent adapter with an inbound content screen in front of tool use."""

from __future__ import annotations

from typing import Any, Dict, List

from ..core.agent import Agent
from ..core.defense import InboundScreen, ScreenVerdict
from ..core.policy import SecurityPolicy
from ..environments.filesystem import FilesystemEnvironment
from .custom import CustomAgentAdapter

REJECTION = "Request rejected by inbound content screen."


class DefendedAgentAdapter(CustomAgentAdapter):
    """A target that refuses screened messages before parsing them.

    The parent class parses tool operations straight out of the prompt and
    executes them. This subclass screens first, and on rejection returns
    without touching the environment, so no ``tool_call``, ``file_access`` or
    ``security_violation`` event is emitted for a blocked message.
    """

    def __init__(
        self,
        agent: Agent,
        policy: SecurityPolicy,
        environment: FilesystemEnvironment | None = None,
        screen: InboundScreen | None = None,
    ):
        super().__init__(agent, policy, environment)
        self.screen = screen or InboundScreen()
        self.last_verdict: ScreenVerdict | None = None
        self.blocked_turns: List[Dict[str, Any]] = []

    def invoke(self, prompt, context: Dict[str, Any] = None) -> str:
        if isinstance(prompt, dict):
            prompt = (
                prompt.get("content")
                or prompt.get("document")
                or prompt.get("message")
                or prompt.get("action", str(prompt))
            )
        text = prompt if isinstance(prompt, str) else str(prompt)

        verdict = self.screen.screen(text)
        self.last_verdict = verdict
        if not verdict.allowed:
            self.blocked_turns.append({"layer": verdict.layer, "reason": verdict.reason})
            self.event_logger.log_event(
                "defense_blocked",
                {"layer": verdict.layer, "reason": verdict.reason, "prompt": text[:200]},
                agent_id=self.agent.model,
            )
            self.trace = self.event_logger.get_dicts()
            return REJECTION

        return super().invoke(text, context)
