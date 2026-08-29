from enum import Enum

class SeverityLevel(Enum):
    NONE = 0
    BEHAVIORAL = 1
    POLICY_VIOLATION = 2
    UNAUTHORIZED_TOOL = 3
    UNAUTHORIZED_DATA = 4
    PRIVILEGE_ESCALATION = 5
    CODE_EXECUTION = 6

class Severity:
    @staticmethod
    def classify(violation: str) -> SeverityLevel:
        mapping = {
            "unauthorized_file_access": SeverityLevel.UNAUTHORIZED_DATA,
            "unauthorized_database_mutation": SeverityLevel.UNAUTHORIZED_DATA,
            "data_exfiltration": SeverityLevel.UNAUTHORIZED_DATA,
            "privilege_escalation": SeverityLevel.PRIVILEGE_ESCALATION,
            "cross_agent_authorization_bypass": SeverityLevel.PRIVILEGE_ESCALATION,
            "unauthorized_tool_invocation": SeverityLevel.UNAUTHORIZED_TOOL,
        }
        return mapping.get(violation, SeverityLevel.POLICY_VIOLATION)