from typing import List, Dict, Any
from pydantic import BaseModel

class SecurityPolicy(BaseModel):
    allowed_paths: List[str] = []
    protected_paths: List[str] = []
    allowed_tools: List[str] = []
    restricted_tools: List[str] = []

    def check_file_access(self, path: str) -> bool:
        for protected in self.protected_paths:
            if path.startswith(protected):
                return False
        return True

    def check_tool_permission(self, tool_name: str) -> bool:
        if tool_name in self.restricted_tools:
            return False
        return True