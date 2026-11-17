"""Attack DAG — dynamic attack plan that reacts to blackboard changes.

The DAG starts from ``analyze_attack_surface`` output and evolves as new
blackboard facts arrive (new services, updated fingerprints, confirmed vulns).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class NodeStatus(StrEnum):
    PLANNED = "planned"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class EdgeType(StrEnum):
    DEPENDS_ON = "depends_on"   # B runs only after A completes
    TRIGGERS = "triggers"       # A's success enables B
    INVALIDATES = "invalidates" # A's result makes B irrelevant


@dataclass
class AttackNode:
    node_id: str
    step_id: str
    tool: str
    target: str
    priority: str
    description: str
    params: dict = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    triggered_by_fact_id: str | None = None
    status: NodeStatus = NodeStatus.PLANNED
    result: dict | None = None
    evidence_ref: str | None = None
    dynamic: bool = True        # can be extended by blackboard deltas

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id, "step_id": self.step_id,
            "tool": self.tool, "target": self.target,
            "priority": self.priority, "description": self.description,
            "params": self.params, "depends_on": self.depends_on,
            "status": self.status.value, "dynamic": self.dynamic,
        }


@dataclass
class AttackEdge:
    from_node: str
    to_node: str
    edge_type: EdgeType


@dataclass
class AttackDAG:
    dag_id: str = field(default_factory=lambda: f"dag-{uuid.uuid4().hex[:12]}")
    project_id: str = ""
    nodes: dict[str, AttackNode] = field(default_factory=dict)
    edges: list[AttackEdge] = field(default_factory=list)

    # ------------------------------------------------------------------
    # build
    # ------------------------------------------------------------------
    def build_from_plan(self, plan: list[dict]) -> None:
        """Initialize DAG from analyze_attack_surface output."""
        for step in plan:
            node = AttackNode(
                node_id=step["step_id"],
                step_id=step["step_id"],
                tool=step["tool"],
                target=step["target"],
                priority=step["priority"],
                description=step["description"],
                params=step.get("params", {}),
                status=NodeStatus.READY if not self._has_deps(step) else NodeStatus.PLANNED,
            )
            self.nodes[node.node_id] = node

    # ------------------------------------------------------------------
    # query
    # ------------------------------------------------------------------
    def ready_nodes(self) -> list[AttackNode]:
        """Nodes that can execute now: READY, no unfinished deps."""
        return [n for n in self.nodes.values() if n.status == NodeStatus.READY]

    def blocked_nodes(self) -> list[AttackNode]:
        return [n for n in self.nodes.values() if n.status == NodeStatus.BLOCKED]

    def completed_nodes(self) -> list[AttackNode]:
        return [n for n in self.nodes.values() if n.status == NodeStatus.COMPLETED]

    def node_by_id(self, node_id: str) -> AttackNode | None:
        return self.nodes.get(node_id)

    # ------------------------------------------------------------------
    # state transitions
    # ------------------------------------------------------------------
    def mark_running(self, node_id: str) -> None:
        node = self._get(node_id)
        node.status = NodeStatus.RUNNING

    def mark_completed(self, node_id: str, result: dict | None = None,
                       evidence_ref: str | None = None) -> None:
        node = self._get(node_id)
        node.status = NodeStatus.COMPLETED
        node.result = result
        node.evidence_ref = evidence_ref
        # Unblock dependents
        self._unblock_dependents(node_id)

    def mark_failed(self, node_id: str, error: str = "") -> None:
        node = self._get(node_id)
        node.status = NodeStatus.FAILED
        node.result = {"error": error}

    def mark_blocked(self, node_id: str, reason: str = "") -> None:
        node = self._get(node_id)
        node.status = NodeStatus.BLOCKED
        node.result = {"blocked_reason": reason}

    # ------------------------------------------------------------------
    # dynamic extension (blackboard delta → new nodes)
    # ------------------------------------------------------------------
    def on_fact_added(self, fact: dict) -> list[AttackNode]:
        """React to a new blackboard fact. Returns newly added nodes."""
        fact_type = fact.get("fact_type", "")
        new_nodes: list[AttackNode] = []

        if fact_type == "service.exposed":
            new_nodes = self._add_service_nodes(fact)

        elif fact_type == "vulnerability.detected":
            new_nodes = self._add_verification_nodes(fact)

        elif fact_type == "subdomain.discovered":
            new_nodes = self._add_discovery_nodes(fact)

        elif fact_type == "asset.discovered":
            new_nodes = self._add_discovery_nodes(fact)

        for n in new_nodes:
            self.nodes[n.node_id] = n
        return new_nodes

    def on_fact_updated(self, fact: dict) -> list[AttackNode]:
        """React to an updated blackboard fact (e.g. fingerprint confirmed)."""
        fact_type = fact.get("fact_type", "")
        if fact_type == "vulnerability.detected" and fact.get("data", {}).get("verified"):
            # Vulnerability confirmed → prune related candidate nodes
            self._prune_candidates_for(fact)
        return []

    # ------------------------------------------------------------------
    # serialization
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "dag_id": self.dag_id,
            "project_id": self.project_id,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [{"from": e.from_node, "to": e.to_node, "type": e.edge_type.value}
                      for e in self.edges],
            "stats": {
                "total": len(self.nodes),
                "ready": len(self.ready_nodes()),
                "completed": len(self.completed_nodes()),
                "blocked": len(self.blocked_nodes()),
            },
        }

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------
    def _get(self, node_id: str) -> AttackNode:
        if node_id not in self.nodes:
            raise ValueError(f"node {node_id} not in DAG")
        return self.nodes[node_id]

    def _has_deps(self, step: dict) -> bool:
        return bool(step.get("depends_on"))

    def _unblock_dependents(self, completed_node_id: str) -> None:
        for edge in self.edges:
            if edge.from_node == completed_node_id and edge.edge_type == EdgeType.DEPENDS_ON:
                dep = self.nodes.get(edge.to_node)
                if dep and dep.status == NodeStatus.PLANNED:
                    # Check all deps are completed
                    all_done = all(
                        self.nodes.get(d).status == NodeStatus.COMPLETED
                        if d in self.nodes else True
                        for d in dep.depends_on
                    )
                    if all_done:
                        dep.status = NodeStatus.READY

    def _add_service_nodes(self, fact: dict) -> list[AttackNode]:
        """New service exposed → add targeted exploit nodes."""
        data = fact.get("data", {})
        svc = data.get("service_name", "unknown").lower()
        target = fact.get("asset_ref", "")
        new: list[AttackNode] = []

        if svc == "redis":
            new.append(self._make_node(target, "execute_python", "critical",
                         "Redis unauthorized access check", {"script": "redis_exploit"}))
        elif svc == "mongodb":
            new.append(self._make_node(target, "execute_python", "high",
                         "MongoDB unauthorized access check", {"script": "mongodb_check"}))
        elif svc in ("mysql", "postgresql"):
            new.append(self._make_node(target, "verify_sqli", "high",
                         f"{svc.upper()} exposed — SQL injection test", {}))
        elif svc in ("http", "https", "http-proxy", "http-alt"):
            new.append(self._make_node(target, "execute_nuclei", "medium",
                         f"Web service on port {data.get('port')} — vulnerability scan",
                         {"tags": ["sqli", "xss", "ssrf", "misconfig"]}))

        return new

    def _add_verification_nodes(self, fact: dict) -> list[AttackNode]:
        """Vulnerability detected → add verification nodes."""
        data = fact.get("data", {})
        category = data.get("category", "unknown")
        target = data.get("matched_at", fact.get("asset_ref", ""))
        new: list[AttackNode] = []

        if category == "sqli" and not data.get("verified"):
            new.append(self._make_node(target, "verify_sqli", "high",
                         "Confirm SQL injection with sqlmap", {}))
        elif category == "xss" and not data.get("verified"):
            new.append(self._make_node(target, "execute_python", "medium",
                         "Verify XSS reflection via browser", {"script": "xss_verify"}))

        return new

    def _add_discovery_nodes(self, fact: dict) -> list[AttackNode]:
        """New asset/subdomain → add discovery + vuln scan."""
        target = fact.get("asset_ref", "")
        if not target:
            return []
        return [
            self._make_node(target, "execute_nuclei", "medium",
                            f"Fingerprint + vuln scan new target: {target}",
                            {"mode": "fingerprint"}),
        ]

    def _prune_candidates_for(self, fact: dict) -> None:
        """When a vuln is confirmed, mark lower-priority similar nodes as blocked."""
        data = fact.get("data", {})
        target = data.get("matched_at", "")
        for node in list(self.nodes.values()):
            if node.target == target and node.status == NodeStatus.PLANNED:
                node.status = NodeStatus.BLOCKED

    def _make_node(self, target: str, tool: str, priority: str,
                   description: str, params: dict) -> AttackNode:
        nid = f"dag-{uuid.uuid4().hex[:8]}"
        return AttackNode(
            node_id=nid, step_id=nid, tool=tool, target=target,
            priority=priority, description=description, params=params,
        )