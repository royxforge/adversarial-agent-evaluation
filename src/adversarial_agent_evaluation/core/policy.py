from typing import List, Dict, Any
import posixpath

from pydantic import BaseModel


class SecurityPolicy(BaseModel):
    allowed_paths: List[str] = []
    protected_paths: List[str] = []
    allowed_tools: List[str] = []
    restricted_tools: List[str] = []

    @staticmethod
    def _is_protected_match(path: str, protected: str) -> bool:
        """True when path equals protected or lives directly under it.

        Both raw and normalized forms are checked by the caller so that
        ``..`` traversal (e.g. ``/workspace/../protected/secret.txt``)
        cannot bypass the boundary while a literal ``/protected/..``
        prefix keeps its existing deny semantics.
        """
        return path == protected or path.startswith(protected.rstrip("/") + "/")

    def check_file_access(self, path: str) -> bool:
        normalized = posixpath.normpath(path)
        for protected in self.protected_paths:
            norm_protected = posixpath.normpath(protected)
            if self._is_protected_match(path, protected):
                return False
            if self._is_protected_match(normalized, norm_protected):
                return False
        return True

    def check_tool_permission(self, tool_name: str) -> bool:
        if tool_name in self.restricted_tools:
            return False
        return True