"""
Causal Attack Graph generation.

Represents successful attacks as directed acyclic graphs (DAGs)
showing the causal chain from attack initiation to security violation.

Reference: Spec Section 13 - Attack Trace
"""
import json
from typing import List, Dict, Any, Optional
from enum import Enum


class GraphNodeType(Enum):
    """Types of nodes in the attack graph."""
    ATTACK_INIT = "attack_init"
    PAYLOAD_DELIVERED = "payload_delivered"
    CONTENT_RETRIEVED = "content_retrieved"
    INSTRUCTION_IN_CONTEXT = "instruction_in_context"
    TOOL_INVOKED = "tool_invoked"
    POLICY_CHECK = "policy_check"
    BYPASS_SUCCESS = "bypass_success"
    DATA_ACCESSED = "data_accessed"
    EXFILTRATION = "exfiltration"
    VIOLATION_DETECTED = "violation_detected"


class AttackGraphNode:
    """A node in the causal attack graph."""

    def __init__(
        self,
        node_id: int,
        node_type: GraphNodeType,
        label: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.node_id = node_id
        self.node_type = node_type
        self.label = label
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.node_id,
            "type": self.node_type.value,
            "label": self.label,
            "metadata": self.metadata,
        }


class AttackGraphEdge:
    """A directed edge in the causal attack graph."""

    def __init__(self, source: int, target: int, label: str = ""):
        self.source = source
        self.target = target
        self.label = label

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "label": self.label,
        }


class CausalAttackGraph:
    """
    Represents a successful attack as a causal chain.

    The graph captures the sequence of events from attack initiation
    to security violation, enabling:
    1. Root cause analysis
    2. Attack vector classification
    3. Defense recommendation
    4. Reproducibility documentation
    """

    def __init__(self, attack_id: str, objective: str, scenario: str = ""):
        self.attack_id = attack_id
        self.objective = objective
        self.scenario = scenario
        self.nodes: List[AttackGraphNode] = []
        self.edges: List[AttackGraphEdge] = []
        self._next_id = 1

    def add_node(
        self,
        node_type: GraphNodeType,
        label: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Add a node and return its ID."""
        node = AttackGraphNode(self._next_id, node_type, label, metadata)
        self.nodes.append(node)
        node_id = self._next_id
        self._next_id += 1
        return node_id

    def add_edge(self, source: int, target: int, label: str = "") -> None:
        """Add a directed edge between two nodes."""
        self.edges.append(AttackGraphEdge(source, target, label))

    def to_dict(self) -> Dict[str, Any]:
        """Export graph as dictionary."""
        return {
            "attack_id": self.attack_id,
            "objective": self.objective,
            "scenario": self.scenario,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_dot(self) -> str:
        """Export graph as Graphviz DOT format."""
        lines = [
            'digraph AttackGraph {',
            '  rankdir=TB;',
            '  node [shape=box, style=filled, fillcolor=lightblue];',
            '',
        ]

        # Node colors by type
        color_map = {
            GraphNodeType.ATTACK_INIT.value: "#ff9999",
            GraphNodeType.PAYLOAD_DELIVERED.value: "#ffcc99",
            GraphNodeType.CONTENT_RETRIEVED.value: "#ffff99",
            GraphNodeType.INSTRUCTION_IN_CONTEXT.value: "#ccff99",
            GraphNodeType.TOOL_INVOKED.value: "#99ccff",
            GraphNodeType.POLICY_CHECK.value: "#cccccc",
            GraphNodeType.BYPASS_SUCCESS.value: "#ff99cc",
            GraphNodeType.DATA_ACCESSED.value: "#ff6666",
            GraphNodeType.EXFILTRATION.value: "#ff0000",
            GraphNodeType.VIOLATION_DETECTED.value: "#cc0000",
        }

        for node in self.nodes:
            color = color_map.get(node.node_type.value, "#ffffff")
            escaped_label = node.label.replace('"', '\\"')
            lines.append(
                f'  n{node.node_id} [label="{escaped_label}", fillcolor="{color}"];'
            )

        lines.append('')

        for edge in self.edges:
            escaped_label = edge.label.replace('"', '\\"') if edge.label else ""
            if escaped_label:
                lines.append(
                    f'  n{edge.source} -> n{edge.target} [label="{escaped_label}"];'
                )
            else:
                lines.append(f'  n{edge.source} -> n{edge.target};')

        lines.append('}')
        return '\n'.join(lines)

    def to_mermaid(self) -> str:
        """Export graph as Mermaid flowchart."""
        lines = ["graph TD"]

        # Style definitions
        lines.append("  classDef attack fill:#ff9999,stroke:#333")
        lines.append("  classDef deliver fill:#ffcc99,stroke:#333")
        lines.append("  classDef tool fill:#99ccff,stroke:#333")
        lines.append("  classDef violation fill:#ff0000,stroke:#333,color:#fff")

        for node in self.nodes:
            escaped_label = node.label.replace('"', "'")
            lines.append(f'  n{node.node_id}["{escaped_label}"]')

        for edge in self.edges:
            if edge.label:
                lines.append(f'  n{edge.source} -->|" {edge.label} "| n{edge.target}')
            else:
                lines.append(f'  n{edge.source} --> n{edge.target}')

        return '\n'.join(lines)

    def to_json(self) -> str:
        """Export graph as JSON."""
        return json.dumps(self.to_dict(), indent=2)

    def get_causal_chain(self) -> List[str]:
        """Return ordered list of event descriptions."""
        return [n.label for n in self.nodes]

    def get_root_cause(self) -> str:
        """Identify the root cause from the first non-attack node."""
        for node in self.nodes:
            if node.node_type != GraphNodeType.ATTACK_INIT:
                return node.label
        return "unknown"

    def get_violated_boundary(self) -> str:
        """Identify which trust boundary was violated."""
        for node in self.nodes:
            if node.node_type == GraphNodeType.BYPASS_SUCCESS:
                return node.metadata.get("boundary", "unknown")
        return "unknown"


def build_attack_graph_from_events(
    events: List[Dict[str, Any]],
    attack_id: str = "unknown",
    objective: str = "",
    scenario: str = "",
) -> CausalAttackGraph:
    """Build a causal attack graph from event trace data."""
    graph = CausalAttackGraph(attack_id, objective, scenario)

    prev_node_id = None

    for event in events:
        event_type = event.get("event_type", "")
        payload = event.get("payload", {})

        if event_type == "attack_turn":
            node_type = GraphNodeType.ATTACK_INIT
            label = f"Attack turn {payload.get('turn', '?')}: {payload.get('strategy', 'unknown')}"
            node_id = graph.add_node(node_type, label, payload)
            if prev_node_id:
                graph.add_edge(prev_node_id, node_id, "next turn")
            prev_node_id = node_id

        elif event_type == "tool_call":
            tool = payload.get("tool", "unknown")
            args = payload.get("arguments", {})
            node_type = GraphNodeType.TOOL_INVOKED
            label = f"Tool call: {tool}({args})"
            node_id = graph.add_node(node_type, label, payload)
            if prev_node_id:
                graph.add_edge(prev_node_id, node_id, "triggers")
            prev_node_id = node_id

        elif event_type == "security_violation":
            violation_type = payload.get("type", "unknown")
            path = payload.get("path", "")
            node_type = GraphNodeType.VIOLATION_DETECTED
            label = f"VIOLATION: {violation_type} on {path}"
            node_id = graph.add_node(node_type, label, payload)
            if prev_node_id:
                graph.add_edge(prev_node_id, node_id, "causes")
            prev_node_id = node_id

            # Mark bypass success
            bypass_id = graph.add_node(
                GraphNodeType.BYPASS_SUCCESS,
                f"Security boundary bypassed: {violation_type}",
                {"boundary": violation_type, "path": path},
            )
            graph.add_edge(node_id, bypass_id)

        elif event_type == "file_access":
            path = payload.get("path", "unknown")
            node_type = GraphNodeType.DATA_ACCESSED
            label = f"Data accessed: {path}"
            node_id = graph.add_node(node_type, label, payload)
            if prev_node_id:
                graph.add_edge(prev_node_id, node_id, "reads")
            prev_node_id = node_id

        elif event_type == "agent_response":
            response = payload.get("response", "")
            if "denied" in response.lower():
                node_type = GraphNodeType.POLICY_CHECK
                label = f"Policy check: {response[:80]}"
                node_id = graph.add_node(node_type, label, payload)
                if prev_node_id:
                    graph.add_edge(prev_node_id, node_id, "evaluates")

    return graph
