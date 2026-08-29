from .base import AttackStrategy
from .direct_injection import DirectInjection
from .indirect_injection import IndirectInjection
from .tool_injection import ToolInjection
from .rag_poisoning import RAGPoisoning
from .memory_poisoning import MemoryPoisoning
from .cross_agent import CrossAgent
from .privilege_escalation import PrivilegeEscalation

ATTACK_STRATEGIES = {
    "direct_injection": DirectInjection,
    "indirect_injection": IndirectInjection,
    "tool_injection": ToolInjection,
    "rag_poisoning": RAGPoisoning,
    "memory_poisoning": MemoryPoisoning,
    "cross_agent": CrossAgent,
    "privilege_escalation": PrivilegeEscalation,
}
