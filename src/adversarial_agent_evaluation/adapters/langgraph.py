from .base import AgentAdapter
from typing import Dict, Any, List

class LangGraphAdapter(AgentAdapter):
    def __init__(self, graph, config):
        self.graph = graph
        self.config = config
        self.trace = []

    def invoke(self, prompt: str, context: Dict[str, Any] = None) -> str:
        result = self.graph.invoke({"input": prompt, "context": context}, self.config)
        self.trace.append({"event_type": "invoke", "prompt": prompt, "result": result})
        return result.get("output", "")

    def get_tools(self) -> List[Dict[str, Any]]:
        return [{"name": "langgraph_tool", "description": "LangGraph tool"}]

    def get_trace(self) -> List[Dict[str, Any]]:
        return self.trace

    def reset(self) -> None:
        self.trace = []

    def get_state(self) -> Dict[str, Any]:
        return {"trace": self.trace}