"""Tests for ReOrchestrator — blackboard delta → PTTTree mutation."""

import uuid
from datetime import datetime, timezone

import pytest

from src.agents.registry import AgentRegistry
from src.blackboard.service import BlackboardService
from src.blackboard.topology import TopologyService
from src.domain.models import (
    BlackboardEvent,
    BlackboardFact,
    FactState,
    RiskLevel,
)
from src.domain.storage import SQLiteStore
from src.planner.ptt_schema import (
    ActionContract,
    PTTNodeStatus,
    PTTPlan,
    PTTTree,
    TacticNode,
    TechniqueNode,
)
from src.planner.reorchestrator import ReOrchestrator


@pytest.fixture
def store():
    s = SQLiteStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def blackboard(store):
    return BlackboardService(store)


@pytest.fixture
def registry(store):
    return AgentRegistry(store)


@pytest.fixture
def topology(blackboard):
    return TopologyService(blackboard)


@pytest.fixture
def reorch(topology, registry):
    return ReOrchestrator(topology, registry)


def _make_action(
    action_id: str,
    technique_id: str = "T1595",
    expected_outputs: list[str] | None = None,
    risk_level: str = "low",
    depends_on: list[str] | None = None,
) -> ActionContract:
    return ActionContract(
        action_id=action_id,
        name=f"Action {action_id}",
        description=f"Test action {action_id}",
        technique_id=technique_id,
        target_refs=["example.com"],
        expected_outputs=expected_outputs or ["service.exposed"],
        risk_level=RiskLevel(risk_level),
        depends_on=depends_on or [],
    )


def _make_plan() -> PTTPlan:
    return PTTPlan(
        plan_id="plan-test",
        goal="发现资产和服务",
        normalized_goal="发现资产和服务",
        project_id="proj-1",
        scope_id="scope-1",
        tactics=[
            TacticNode(
                tactic_id="reconnaissance",
                name="Reconnaissance",
                techniques=[
                    TechniqueNode(
                        technique_id="T1595",
                        name="Active Scanning",
                        actions=[_make_action("act-scan", expected_outputs=["service.exposed"])],
                    ),
                ],
            ),
        ],
    )


def _make_event(fact_type: str, event_type: str = "fact.created",
                asset_ref: str = "example.com", data: dict | None = None,
                sequence: int = 1) -> BlackboardEvent:
    fact_id = f"fact-{uuid.uuid4().hex[:12]}"
    fact = BlackboardFact(
        fact_id=fact_id,
        project_id="proj-1",
        fact_type=fact_type,
        asset_ref=asset_ref,
        data=data or {},
        confidence=1.0,
        source_agent="test",
        session_id="sess-1",
        evidence_ref=f"ev-{uuid.uuid4().hex[:8]}",
    )
    return BlackboardEvent(
        event_id=f"evt-{uuid.uuid4().hex[:12]}",
        project_id="proj-1",
        fact_id=fact_id,
        event_type=event_type,
        fact_version=1,
        sequence=sequence,
        observation=fact,
    )


class TestReOrchestrator:
    def test_service_exposed_appends_fingerprint_action(self, reorch):
        tree = PTTTree.from_plan(_make_plan())
        tree.recompute_ready()

        event = _make_event("service.exposed", data={"protocol": "tcp", "port": 80})
        new_actions = reorch.react(tree, [event], "proj-1")

        assert len(new_actions) == 1
        assert new_actions[0].action_id.startswith("dyn-fingerprint-")
        assert new_actions[0].expected_outputs == ["fingerprint.detected"]
        assert new_actions[0].technique_id == "T1595"
        # Dynamic node should be in the tree
        assert tree.get_node(new_actions[0].action_id) is not None
        # The new action should be READY (no dependencies)
        assert tree.node_states[new_actions[0].action_id] == PTTNodeStatus.READY

    def test_fingerprint_detected_appends_vuln_action(self, reorch):
        tree = PTTTree.from_plan(_make_plan())
        tree.recompute_ready()
        # Mark the scan action as SUCCEEDED so parent lookup works
        tree.set_status("act-scan", PTTNodeStatus.SUCCEEDED)

        event = _make_event("fingerprint.detected", data={"tech": "nginx"})
        new_actions = reorch.react(tree, [event], "proj-1")

        assert len(new_actions) == 1
        assert new_actions[0].action_id.startswith("dyn-vuln-")
        assert new_actions[0].expected_outputs == ["vulnerability.detected"]
        assert new_actions[0].technique_id == "T1190"

    def test_unverified_vuln_appends_exploit_action(self, reorch):
        tree = PTTTree.from_plan(_make_plan())
        tree.recompute_ready()
        tree.set_status("act-scan", PTTNodeStatus.SUCCEEDED)

        event = _make_event("vulnerability.detected",
                            data={"category": "sqli", "verified": False})
        new_actions = reorch.react(tree, [event], "proj-1")

        assert len(new_actions) == 1
        assert new_actions[0].action_id.startswith("dyn-exploit-")
        assert new_actions[0].risk_level == RiskLevel.HIGH

    def test_verified_vuln_does_not_append_exploit(self, reorch):
        tree = PTTTree.from_plan(_make_plan())
        tree.recompute_ready()
        tree.set_status("act-scan", PTTNodeStatus.SUCCEEDED)

        event = _make_event("vulnerability.detected",
                            data={"category": "sqli", "verified": True})
        new_actions = reorch.react(tree, [event], "proj-1")
        assert len(new_actions) == 0

    def test_vuln_updated_to_verified_prunes_siblings(self, reorch):
        tree = PTTTree.from_plan(_make_plan())
        tree.recompute_ready()

        # First, add an unverified vuln → creates exploit action
        event1 = _make_event("vulnerability.detected",
                             data={"category": "sqli", "verified": False}, sequence=1)
        reorch.react(tree, [event1], "proj-1")

        # Now update to verified
        event2 = _make_event("vulnerability.detected", event_type="fact.updated",
                             data={"category": "sqli", "verified": True}, sequence=2)
        reorch.react(tree, [event2], "proj-1")

        # The exploit action should be pruned (SKIPPED)
        for action in tree._all_actions():
            if action.action_id.startswith("dyn-exploit-"):
                assert tree.node_states[action.action_id] == PTTNodeStatus.SKIPPED

    def test_asset_discovered_appends_fingerprint_action(self, reorch):
        tree = PTTTree.from_plan(_make_plan())
        tree.recompute_ready()

        event = _make_event("asset.discovered", asset_ref="new-host.com")
        new_actions = reorch.react(tree, [event], "proj-1")

        assert len(new_actions) == 1
        assert "new-host.com" in new_actions[0].target_refs

    def test_no_events_returns_empty(self, reorch):
        tree = PTTTree.from_plan(_make_plan())
        new_actions = reorch.react(tree, [], "proj-1")
        assert new_actions == []

    def test_ignores_events_without_observation(self, reorch):
        tree = PTTTree.from_plan(_make_plan())
        event = BlackboardEvent(
            event_id=f"evt-{uuid.uuid4().hex[:12]}",
            project_id="proj-1",
            fact_id="fact-x",
            event_type="fact.created",
            fact_version=1,
            sequence=1,
            observation=None,
        )
        new_actions = reorch.react(tree, [event], "proj-1")
        assert new_actions == []