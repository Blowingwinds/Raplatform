"""TopologyService — derive a topology graph from blackboard facts.

Groups facts by ``asset_ref`` and links ``service.exposed`` and endpoint
facts into a graph that planners can walk to find unscanned services or
unverified vulnerabilities.
"""

from dataclasses import dataclass, field

from src.blackboard.service import BlackboardService
from src.domain.models import BlackboardFact


@dataclass
class TopologyNode:
    ref: str            # asset_ref or service_ref
    kind: str           # "asset" | "service" | "endpoint"
    parent_ref: str | None
    fact_type: str
    facts: list[str] = field(default_factory=list)  # fact_ids


@dataclass
class TopologyGraph:
    nodes: dict[str, TopologyNode]
    edges: list[tuple[str, str]]  # (parent_ref, child_ref)
    # Internal lookup of fact_id → fact, populated by TopologyService.build
    # so that graph methods (unverified_vulns) can inspect fact ``data``
    # without a live blackboard handle.
    _fact_index: dict[str, BlackboardFact] = field(default_factory=dict)

    def unscanned_services(self) -> list[TopologyNode]:
        """Return ``service.exposed`` nodes that have no sibling fingerprint.detected fact.

        A service node is "scanned" when at least one ``fingerprint.detected``
        fact exists with the same ``asset_ref`` as the service node. The
        returned list excludes any service that has such a sibling.
        """
        service_nodes = [
            node for node in self.nodes.values()
            if node.kind == "service" and node.fact_type == "service.exposed"
        ]

        # Collect asset_refs that own a fingerprint.detected sibling fact.
        # A fingerprint is a sibling of a service when both share the same
        # asset_ref — so we look up the underlying fact's asset_ref rather
        # than the node's parent_ref (which points at the service, not asset).
        assets_with_fingerprints: set[str] = set()
        for node in self.nodes.values():
            if node.fact_type != "fingerprint.detected":
                continue
            for fact_id in node.facts:
                fact = self._fact_index.get(fact_id)
                if fact is not None:
                    assets_with_fingerprints.add(fact.asset_ref)

        return [
            node for node in service_nodes
            if node.parent_ref not in assets_with_fingerprints
        ]

    def unverified_vulns(self) -> list[TopologyNode]:
        """Return ``vulnerability.detected`` nodes not yet verified."""
        result: list[TopologyNode] = []
        for node in self.nodes.values():
            if node.fact_type != "vulnerability.detected":
                continue
            verified = False
            for fact_id in node.facts:
                fact = self._fact_index.get(fact_id)
                if fact is not None and bool(fact.data.get("verified")):
                    verified = True
                    break
            if not verified:
                result.append(node)
        return result

    def to_dict(self) -> dict:
        """Serialize the graph into a plain dict structure."""
        return {
            "nodes": {
                ref: {
                    "ref": node.ref,
                    "kind": node.kind,
                    "parent_ref": node.parent_ref,
                    "fact_type": node.fact_type,
                    "facts": list(node.facts),
                }
                for ref, node in self.nodes.items()
            },
            "edges": [list(edge) for edge in self.edges],
        }

    def to_mermaid(self) -> str:
        """Render the topology as a Mermaid.js flowchart.

        Returns a Mermaid code block suitable for embedding in Markdown.
        Node labels show kind + fact_type for readability.
        """
        lines = ["```mermaid", "graph TD"]
        # Shorter IDs for Mermaid compatibility (alphanumeric only)
        id_map: dict[str, str] = {}
        for i, ref in enumerate(self.nodes):
            mermaid_id = f"N{i}"
            id_map[ref] = mermaid_id
            node = self.nodes[ref]
            label = f"{node.kind}\\n{node.fact_type}\\n{node.ref[:30]}"
            # Style by kind
            style = {
                "asset": "fill:#e1f5fe",
                "service": "fill:#fff3e0",
                "endpoint": "fill:#e8f5e9",
            }.get(node.kind, "")
            if style:
                lines.append(f'    {mermaid_id}["{label}"]:::{style}')
            else:
                lines.append(f'    {mermaid_id}["{label}"]')
        for parent_ref, child_ref in self.edges:
            if parent_ref in id_map and child_ref in id_map:
                lines.append(f"    {id_map[parent_ref]} --> {id_map[child_ref]}")
        lines.append("```")
        return "\n".join(lines)


class TopologyService:
    """Build and query topology graphs derived from a BlackboardService."""

    def __init__(self, blackboard: BlackboardService) -> None:
        self.blackboard = blackboard

    def build(self, project_id: str) -> TopologyGraph:
        """Build a topology graph from all blackboard facts.

        - Group facts by ``asset_ref``.
        - ``service.exposed`` keyed by ``protocol:port``.
        - Link service→asset edges.
        - Endpoint facts (fingerprint/vulnerability/credential) link to
          their parent service when ``service_ref`` is present, else to
          the asset node directly.
        """
        facts = self.blackboard.snapshot(project_id)

        nodes: dict[str, TopologyNode] = {}
        edges: list[tuple[str, str]] = []
        fact_index: dict[str, BlackboardFact] = {f.fact_id: f for f in facts}

        # Index facts by asset_ref for sibling lookups.
        facts_by_asset: dict[str, list[BlackboardFact]] = {}
        for fact in facts:
            facts_by_asset.setdefault(fact.asset_ref, []).append(fact)

        # First pass: create asset nodes.
        for asset_ref, asset_facts in facts_by_asset.items():
            nodes[asset_ref] = TopologyNode(
                ref=asset_ref,
                kind="asset",
                parent_ref=None,
                fact_type="asset",
                facts=[f.fact_id for f in asset_facts],
            )

        # Second pass: create service / endpoint / vuln nodes and link them.
        for fact in facts:
            if fact.fact_type == "service.exposed":
                protocol = fact.data.get("protocol")
                port = fact.data.get("port")
                service_ref = f"{protocol}:{port}"
                node = nodes.get(service_ref)
                if node is None:
                    node = TopologyNode(
                        ref=service_ref,
                        kind="service",
                        parent_ref=fact.asset_ref,
                        fact_type="service.exposed",
                        facts=[],
                    )
                    nodes[service_ref] = node
                node.facts.append(fact.fact_id)
                edge = (fact.asset_ref, service_ref)
                if edge not in edges:
                    edges.append(edge)
            elif fact.fact_type in (
                "fingerprint.detected",
                "vulnerability.detected",
                "credential.validated",
            ):
                service_ref = fact.data.get("service_ref")
                if service_ref:
                    parent_ref = service_ref
                else:
                    parent_ref = fact.asset_ref

                node_key = f"{fact.fact_type}:{fact.fact_id}"
                kind = "endpoint" if fact.fact_type == "fingerprint.detected" else "service"
                nodes[node_key] = TopologyNode(
                    ref=node_key,
                    kind=kind,
                    parent_ref=parent_ref,
                    fact_type=fact.fact_type,
                    facts=[fact.fact_id],
                )
                edge = (parent_ref, node_key)
                if edge not in edges:
                    edges.append(edge)

        return TopologyGraph(nodes=nodes, edges=edges, _fact_index=fact_index)

    def delta(self, project_id: str, since_sequence: int) -> list[str]:
        """Return new refs (asset_refs / service_refs) since a given event sequence."""
        events = self.blackboard.events_since(project_id, since_sequence)
        refs: list[str] = []
        seen: set[str] = set()
        for event in events:
            if event.observation is None:
                continue
            fact = event.observation
            if fact.fact_type == "service.exposed":
                service_ref = f"{fact.data.get('protocol')}:{fact.data.get('port')}"
                for candidate in (fact.asset_ref, service_ref):
                    if candidate not in seen:
                        seen.add(candidate)
                        refs.append(candidate)
            else:
                if fact.asset_ref not in seen:
                    seen.add(fact.asset_ref)
                    refs.append(fact.asset_ref)
        return refs
