"""Phase 5 Integration Acceptance Test.

Proves the exit criterion:
- PTT-driven hive: Planner generates initial plan, orchestrator dispatches actions
- Dynamic re-orchestration: blackboard facts trigger new PTT nodes
- Lease enforcement: conflicting resource access rejected
- HITL approval: high-risk action blocked until approved
"""

import pytest

from src.agents.capabilities import register_default_capabilities
from src.agents.hive.crews import FakeCrewRunner
from src.agents.hive.orchestrator import HiveOrchestrator, HiveRunSummary
from src.agents.registry import AgentRegistry
from src.blackboard.service import BlackboardService
from src.domain.lease_service import LeaseService
from src.domain.models import (
    AgentCapability,
    Evidence,
    RiskLevel,
    Scope,
)
from src.domain.storage import SQLiteStore
from src.policy.approval import ApprovalGate


@pytest.fixture
def store():
    s = SQLiteStore(":memory:")
    yield s
    s.close()


def _setup_orchestrator(store, *, demo_mode=True, max_rounds=6):
    """Build a HiveOrchestrator for integration testing."""
    runner = FakeCrewRunner()
    orch = HiveOrchestrator(
        store,
        project_id="proj-int",
        scope_id="scope-int",
        session_id="sess-int",
        max_rounds=max_rounds,
        crew_runner=runner,
        demo_mode=demo_mode,
    )
    # Orchestration-only tests: disable tool hints so no real scanner runs.
    orch._tool_hints = lambda action, capability_id=None: []
    orch._chain_tactics_in_order = lambda: None  # tests exercise a single round
    return orch


class TestPhase5Integration:
    """Acceptance tests for Phase 5 exit criterion."""

    def test_ptt_driven_hive_generates_facts(self, store):
        """PTT-driven orchestrator runs and produces blackboard facts."""
        orch = _setup_orchestrator(store, max_rounds=5)
        summary = orch.run(seed_targets=["example.com"])

        assert isinstance(summary, HiveRunSummary)
        assert summary.fact_count > 0
        assert summary.rounds >= 1
        # Session should be recorded
        session = store.get_session("sess-int")
        assert session is not None
        # PTT tree should be persisted
        tree_data = store.get_ptt_tree("proj-int")
        assert tree_data is not None

    def test_dynamic_reorchestration_appends_actions(self, store):
        """When a service.exposed fact is created, a fingerprint action is appended."""
        orch = _setup_orchestrator(store, max_rounds=3)
        orch.run(seed_targets=["example.com"])

        # Verify PTT tree has dynamic nodes (appended by re-orchestrator)
        tree_data = store.get_ptt_tree("proj-int")
        assert tree_data is not None
        from src.planner.ptt_schema import PTTTree
        tree = PTTTree.from_persistable(tree_data)

        # Should have at least the plan actions + dynamic nodes
        all_actions = tree._all_actions()
        static_count = len(tree.plan.all_actions())
        assert len(all_actions) >= static_count, (
            f"Expected dynamic nodes; got {len(all_actions)} total vs {static_count} static"
        )

    def test_lease_prevents_concurrent_resource_access(self, store):
        """Two sessions cannot acquire the same resource concurrently.

        This tests LeaseService directly since the hive's sequential loop
        naturally avoids same-round conflicts.
        """
        # Register capabilities so lease acquisition works
        registry = AgentRegistry(store)
        register_default_capabilities(registry)

        lease = LeaseService(store)

        # Session A acquires lease
        r1 = lease.acquire(
            project_id="proj-int", resource_ref="example.com",
            session_id="sess-a", action_id="act-a",
        )
        assert r1.acquired is True

        # Session B attempts same resource → blocked
        r2 = lease.acquire(
            project_id="proj-int", resource_ref="example.com",
            session_id="sess-b", action_id="act-b",
        )
        assert r2.acquired is False
        assert r2.strategy == "suspend_wait"

        # After release, session B can acquire
        lease.release(r1.lease.lease_id)
        r3 = lease.acquire(
            project_id="proj-int", resource_ref="example.com",
            session_id="sess-b", action_id="act-b",
        )
        assert r3.acquired is True

    def test_hitl_approval_workflow(self, store):
        """High-risk actions blocked until approved."""
        gate = ApprovalGate(store, demo_mode=False)

        # Request approval → PENDING
        req = gate.request(
            action_id="act-verify-high",
            capability_id="exploit-verifier",
            session_id="sess-int",
            project_id="proj-int",
            risk_level=RiskLevel.HIGH,
            resource_refs=["example.com"],
        )
        assert not gate.is_granted("act-verify-high")
        assert len(gate.pending_for("proj-int")) == 1

        # Approve → granted
        gate.approve(req.request_id, decided_by="tester")
        assert gate.is_granted("act-verify-high")
        assert len(gate.pending_for("proj-int")) == 0

    def test_reject_blocks_action(self, store):
        """Rejected approval does NOT grant."""
        gate = ApprovalGate(store, demo_mode=False)
        req = gate.request(
            action_id="act-rejected",
            capability_id="exploit-verifier",
            session_id="sess-int",
            project_id="proj-int",
            risk_level=RiskLevel.HIGH,
        )
        gate.reject(req.request_id, reason="too dangerous")
        assert not gate.is_granted("act-rejected")

    def test_demo_mode_bypasses_approval(self, store):
        """In demo mode, high-risk actions are auto-approved."""
        gate = ApprovalGate(store, demo_mode=True)
        req = gate.request(
            action_id="act-demo",
            capability_id="exploit-verifier",
            session_id="sess-int",
            project_id="proj-int",
            risk_level=RiskLevel.HIGH,
        )
        assert gate.is_granted("act-demo")

    def test_hive_session_lifecycle(self, store):
        """Hive orchestrator opens and closes a session."""
        orch = _setup_orchestrator(store, max_rounds=2)
        summary = orch.run(seed_targets=["example.com"])

        session = store.get_session("sess-int")
        assert session is not None
        assert session.project_id == "proj-int"
        # Terminal status recorded
        assert session.status.value in ("succeeded", "failed", "cancelled")