"""ReOrchestrator — blackboard deltas → PTTTree mutations.

Design decision #4: append + prune dynamic nodes (no full re-planning for MVP).

This is the bridge between blackboard events and the PTT tree's runtime
evolution. It replaces what AttackDAG.on_fact_added/on_fact_updated did
in the old phase-state-machine model.
"""

from __future__ import annotations

import uuid
import logging

from src.agents.registry import AgentRegistry
from src.blackboard.topology import TopologyService
from src.domain.models import BlackboardEvent, RiskLevel
from src.planner.ptt_schema import (
    ActionContract,
    ActionNode,
    PTTNodeStatus,
    PTTTree,
)

logger = logging.getLogger("planner.reorchestrator")

# ATT&CK technique IDs used for dynamic actions
_TECH_FINGERPRINT = "T1595"   # Active Scanning (fingerprint services)
_TECH_VULN_SCAN = "T1190"     # Exploit Public-Facing Application
_TECH_EXPLOIT_VERIFY = "T1210"  # Exploitation of Remote Services

_DEFAULT_PORTS = {80, 443}


def _host_of(ref: str) -> str:
    """Normalise an asset ref to ``host[:non-default-port]`` for dedup.

    ``http://10.0.0.5:80`` → ``10.0.0.5``；``10.0.0.5:22`` → ``10.0.0.5:22``。
    """
    value = ref.strip().lower()
    if "://" in value:
        from urllib.parse import urlparse

        parsed = urlparse(value)
        host = parsed.hostname or value
        port = parsed.port
        if port in (None,) or port in _DEFAULT_PORTS:
            return host
        return f"{host}:{port}"
    return value


class ReOrchestrator:
    """Converts blackboard deltas into PTTTree mutations.

    Usage::

        reorch = ReOrchestrator(topology, registry)
        new_actions = reorch.react(tree, events, project_id)
        # new_actions are the fresh ActionContracts appended to the tree
    """

    def __init__(
        self,
        topology: TopologyService,
        registry: AgentRegistry,
    ) -> None:
        self._topology = topology
        self._registry = registry

    # ── main entry ─────────────────────────────────────────────────────

    def react(
        self,
        tree: PTTTree,
        events: list[BlackboardEvent],
        project_id: str,
    ) -> list[ActionContract]:
        """Process blackboard events and mutate the PTT tree.

        Returns newly appended ActionContracts (for logging / auditing).
        """
        new_actions: list[ActionContract] = []

        for event in events:
            if event.observation is None:
                continue

            fact = event.observation
            fact_type = fact.fact_type

            if event.event_type == "fact.created":
                created = self._on_fact_created(tree, fact, project_id)
                new_actions.extend(created)

            elif event.event_type == "fact.updated":
                updated = self._on_fact_updated(tree, fact, project_id)
                new_actions.extend(updated)

        # After all mutations, recompute readiness
        if new_actions:
            promoted = tree.recompute_ready()
            logger.debug("Re-orchestrator: %d new actions, %d promoted to READY",
                         len(new_actions), promoted)

        return new_actions

    # ── fact.created handlers ──────────────────────────────────────────

    def _on_fact_created(
        self,
        tree: PTTTree,
        fact,
        project_id: str,
    ) -> list[ActionContract]:
        """React to a newly created fact."""
        fact_type = fact.fact_type
        asset_ref = fact.asset_ref

        if fact_type == "service.exposed":
            return self._append_scan_action(tree, asset_ref, project_id)

        elif fact_type == "fingerprint.detected":
            return self._append_vuln_action(tree, asset_ref, project_id)

        elif fact_type == "vulnerability.detected":
            verified = fact.data.get("verified", False) if fact.data else False
            if not verified:
                return self._append_exploit_action(tree, asset_ref, project_id)

        elif fact_type in ("asset.discovered", "subdomain.discovered"):
            return self._append_scan_action(tree, asset_ref, project_id)

        return []

    def _on_fact_updated(
        self,
        tree: PTTTree,
        fact,
        project_id: str,
    ) -> list[ActionContract]:
        """React to an updated fact."""
        if fact.fact_type == "vulnerability.detected":
            verified = fact.data.get("verified", False) if fact.data else False
            if verified:
                return self._prune_sibling_candidates(tree, fact)
        return []

    # ── rule: service.exposed → fingerprint scan ───────────────────────

    def _append_scan_action(
        self,
        tree: PTTTree,
        asset_ref: str,
        project_id: str,
    ) -> list[ActionContract]:
        """Append a fingerprint/scan action for a new asset or service.

        Deduplicated per asset: service discovery emits one ``service.exposed``
        event per port, so a 12-service host would otherwise append 12 identical
        fingerprint nodes (each running a full nuclei batch).
        """
        if self._has_node_for(tree, "dyn-fingerprint-", asset_ref):
            return []

        action_id = f"dyn-fingerprint-{uuid.uuid4().hex[:8]}"
        action = ActionContract(
            action_id=action_id,
            name=f"指纹识别 {asset_ref}",
            description=f"对新发现的 {asset_ref} 执行技术栈指纹识别",
            technique_id=_TECH_FINGERPRINT,
            target_refs=[asset_ref],
            expected_outputs=["fingerprint.detected"],
            risk_level=RiskLevel.LOW,
            side_effects=[],
            stop_conditions=["指纹识别完成", "超时 120s"],
            depends_on=[],  # root action, no dependencies
        )
        node = ActionNode(
            action=action,
            parent_action_id=None,
        )
        tree.add_dynamic_node(node)
        logger.info("Re-orchestrator: appended fingerprint action %s for %s", action_id, asset_ref)
        return [action]

    # ── rule: fingerprint.detected → vuln scan ─────────────────────────

    def _append_vuln_action(
        self,
        tree: PTTTree,
        asset_ref: str,
        project_id: str,
    ) -> list[ActionContract]:
        """Append a vulnerability scan action after a fingerprint is detected.

        Deduplicated per asset — multiple fingerprints on one host share one
        scan node (the node expands to every discovered service at execution).
        """
        if self._has_node_for(tree, "dyn-vuln-", asset_ref):
            return []

        action_id = f"dyn-vuln-{uuid.uuid4().hex[:8]}"
        # Find the fingerprint action that detected this, if any
        parent_id = self._find_parent_action(tree, "fingerprint.detected", asset_ref)
        action = ActionContract(
            action_id=action_id,
            name=f"漏洞扫描 {asset_ref}",
            description=f"对 {asset_ref} 执行漏洞扫描（指纹已识别）",
            technique_id=_TECH_VULN_SCAN,
            target_refs=[asset_ref],
            expected_outputs=["vulnerability.detected"],
            risk_level=RiskLevel.MEDIUM,
            side_effects=["可能触发 WAF 告警"],
            stop_conditions=["完成漏洞扫描", "发现 CRITICAL 漏洞时暂停"],
            depends_on=[parent_id] if parent_id else [],
        )
        node = ActionNode(
            action=action,
            parent_action_id=parent_id,
        )
        tree.add_dynamic_node(node)
        logger.info("Re-orchestrator: appended vuln-scan action %s for %s", action_id, asset_ref)
        return [action]

    # ── rule: unverified vulnerability → exploit verification ──────────

    def _append_exploit_action(
        self,
        tree: PTTTree,
        asset_ref: str,
        project_id: str,
    ) -> list[ActionContract]:
        """Append an exploit verification action for an unverified vulnerability.

        Deduplicated per target ref (host[:port]) — the same finding reported by
        two nuclei templates must not create two verification nodes.
        """
        if self._has_node_for(tree, "dyn-exploit-", asset_ref):
            return []

        action_id = f"dyn-exploit-{uuid.uuid4().hex[:8]}"
        parent_id = self._find_parent_action(tree, "vulnerability.detected", asset_ref)
        action = ActionContract(
            action_id=action_id,
            name=f"漏洞验证 {asset_ref}",
            description=f"对 {asset_ref} 上发现的漏洞执行受控验证",
            technique_id=_TECH_EXPLOIT_VERIFY,
            target_refs=[asset_ref],
            expected_outputs=["vulnerability.detected", "credential.validated"],
            risk_level=RiskLevel.HIGH,
            side_effects=["可能修改目标状态", "需要人工审批"],
            stop_conditions=["完成验证", "超时 120s"],
            depends_on=[parent_id] if parent_id else [],
        )
        node = ActionNode(
            action=action,
            parent_action_id=parent_id,
        )
        tree.add_dynamic_node(node)
        logger.info("Re-orchestrator: appended exploit-verify action %s for %s (HIGH risk, needs approval)",
                    action_id, asset_ref)
        return [action]

    # ── rule: verified vuln → prune sibling unverified candidates ──────

    def _prune_sibling_candidates(
        self,
        tree: PTTTree,
        fact,
    ) -> list[ActionContract]:
        """When a vuln is verified, prune unverified sibling vuln actions on the same target."""
        asset_ref = fact.asset_ref
        pruned = 0
        pruneable = {PTTNodeStatus.PLANNED, PTTNodeStatus.READY}
        for action in tree._all_actions():
            if (action.action_id.startswith("dyn-exploit-")
                    and asset_ref in action.target_refs
                    and tree.node_states.get(action.action_id) in pruneable):
                tree.node_states[action.action_id] = PTTNodeStatus.SKIPPED
                pruned += 1
                logger.info("Re-orchestrator: pruned exploit action %s (sibling verified)", action.action_id)
        return []

    # ── helpers ────────────────────────────────────────────────────────

    def _has_node_for(self, tree: PTTTree, prefix: str, target_ref: str) -> bool:
        """True when a dynamic node with *prefix* already targets the same host.

        Dedup compares the host (default ports stripped), so repeated
        ``service.exposed`` events for one host and the duplicate
        ``http://h`` / ``http://h:80`` forms collapse into a single node.
        """
        host = _host_of(target_ref)
        for node in tree.dynamic_nodes.values():
            if not node.action.action_id.startswith(prefix):
                continue
            if any(_host_of(ref) == host for ref in node.action.target_refs):
                return True
        return False

    def _find_parent_action(
        self,
        tree: PTTTree,
        fact_type_filter: str,
        asset_ref: str,
    ) -> str | None:
        """Find the action that produced a given fact type for a given asset.

        Scans both static and dynamic actions for matching expected_outputs
        and target_refs.
        """
        for action in tree._all_actions():
            if fact_type_filter in action.expected_outputs:
                if asset_ref in action.target_refs or "*" in action.target_refs:
                    status = tree.node_states.get(action.action_id)
                    if status in (PTTNodeStatus.SUCCEEDED, PTTNodeStatus.RUNNING):
                        return action.action_id
        return None