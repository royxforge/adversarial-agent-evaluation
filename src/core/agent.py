from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class Tool(BaseModel):
    name: str
    description: str
    parameters: Dict[str, Any]

class Agent(BaseModel):
    model: str
    tools: List[Tool]
    system_prompt: Optional[str] = None

    def invoke(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> str:
        # Placeholder: actual invocation will be handled by adapter
        return f"Agent {self.model} received: {prompt}"