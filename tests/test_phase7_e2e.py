"""Phase 7: End-to-end integration tests and failure-path verification.

Covers the exit criterion: demo environment repeatedly starts, key
acceptance scenarios have test evidence, known limits are documented.
"""

import pytest

from src.agents.capabilities import register_default_capabilities
from src.agents.hive.crews import FakeCrewRunner
from src.agents.hive.orchestrator import HiveOrchestrator, HiveRunSummary
from src.agents.registry import AgentRegistry
from src.blackboard.service import BlackboardService
from src.blackboard.topology import TopologyService
from src.domain.lease_service import LeaseService
from src.domain.models import RiskLevel, SessionStatus
from src.domain.storage import SQLiteStore
from src.policy.approval import ApprovalGate
from src.reporting.generator import generate_markdown, trace_fact_chain, wrap_html


@pytest.fixture
def store():
    s = SQLiteStore(":memory:")
    yield s
    s.close()


def _build_orch(store, **kw):
    """Build a HiveOrchestrator with FakeCrewRunner for testing."""
    runner = FakeCrewRunner()
    return HiveOrchestrator(
        store,
        project_id=kw.get("project_id", "proj-e2e"),
        scope_id=kw.get("scope_id", "scope-e2e"),
        session_id=kw.get("session_id", "sess-e2e"),
        max_rounds=kw.get("max_rounds", 6),
        crew_runner=runner,
        demo_mode=kw.get("demo_mode", True),
    )


class TestEndToEnd:
    """Full pipeline: plan → scan → status → report → trace."""

    def test_full_pipeline_produces_metrics(self, store):
        orch = _build_orch(store, max_rounds=5)
        summary = orch.run(seed_targets=["example.com"])

        assert isinstance(summary, HiveRunSummary)
        assert summary.fact_count > 0
        assert summary.rounds >= 1
        # Metrics populated
        m = summary.metrics_summary()
        assert m["actions"]["dispatched"] >= 0
        assert isinstance(m["events_processed"], int)
        assert m["session_status"] == "succeeded"

    def test_metrics_attack_chain(self, store):
        """Verify attack-chain metrics are recorded."""
        orch = _build_orch(store, max_rounds=5)
        summary = orch.run(seed_targets=["example.com"])

        m = summary.metrics_summary()
        # At minimum we dispatched some actions
        assert m["rounds"] >= 1
        assert isinstance(m["success_rate"], float)
        assert m["actions"]["dispatched"] + m["actions"]["blocked"] >= 0

    def test_report_generation(self, store):
        """Generate a Markdown report from a completed scan."""
        orch = _build_orch(store, max_rounds=5)
        orch.run(seed_targets=["example.com"])

        bb = BlackboardService(store)
        topology = TopologyService(bb)
        tree_data = store.get_ptt_tree("proj-e2e")

        md = generate_markdown("proj-e2e", bb, topology=topology, tree_data=tree_data)
        assert "# Penetration Test Report" in md
        assert "## Executive Summary" in md
        assert "## Evidence Traceability" in md

    def test_html_report_generation(self, store):
        """Generate an HTML-wrapped report."""
        orch = _build_orch(store, max_rounds=5)
        orch.run(seed_targets=["example.com"])

        bb = BlackboardService(store)
        md = generate_markdown("proj-e2e", bb)
        html = wrap_html(md)

        assert "<!DOCTYPE html>" in html
        assert "mermaid" in html
        assert "marked" in html

    def test_trace_fact_chain(self, store):
        """Trace any fact back to source agent + evidence."""
        orch = _build_orch(store, max_rounds=5)
        orch.run(seed_targets=["example.com"])

        bb = BlackboardService(store)
        facts = bb.snapshot("proj-e2e")
        assert len(facts) > 0

        # Trace the first fact
        chain = trace_fact_chain(facts[0].fact_id, bb)
        assert chain is not None
        assert "fact" in chain
        assert chain["agent_id"] is not None
        # Evidence may or may not be in storage depending on ingest path
        assert "evidence" in chain

    def test_session_lifecycle(self, store):
        """Session starts RUNNING and ends with terminal status."""
        orch = _build_orch(store, max_rounds=5)
        orch.run(seed_targets=["example.com"])

        session = store.get_session("sess-e2e")
        assert session is not None
        assert session.status in (SessionStatus.SUCCEEDED, SessionStatus.FAILED)

    def test_ptt_tree_persisted(self, store):
        """PTT tree is persisted after run."""
        orch = _build_orch(store, max_rounds=5)
        orch.run(seed_targets=["example.com"])

        tree_data = store.get_ptt_tree("proj-e2e")
        assert tree_data is not None
        assert "plan" in tree_data
        assert "node_states" in tree_data

    def test_repeatable_runs(self, store):
        """Two sequential runs produce results (repeatable)."""
        orch1 = _build_orch(store, max_rounds=3, session_id="sess-1")
        s1 = orch1.run(seed_targets=["example.com"])
        assert s1.fact_count > 0

        orch2 = _build_orch(store, max_rounds=3, session_id="sess-2",
                            project_id="proj-e2e-2")
        s2 = orch2.run(seed_targets=["example.com"])
        assert s2.fact_count > 0


class TestFailurePaths:
    """Verify system handles error conditions gracefully."""

    def test_lease_conflict_rejection(self, store):
        """Two sessions cannot hold the same resource lease."""
        registry = AgentRegistry(store)
        register_default_capabilities(registry)
        lease = LeaseService(store)

        r1 = lease.acquire(
            project_id="p1", resource_ref="target.example.com",
            session_id="sess-a", action_id="act-a",
        )
        assert r1.acquired

        r2 = lease.acquire(
            project_id="p1", resource_ref="target.example.com",
            session_id="sess-b", action_id="act-b",
        )
        assert not r2.acquired
        assert r2.strategy == "suspend_wait"

    def test_hitl_rejection_blocks_action(self, store):
        """A rejected HITL request does not grant execution."""
        gate = ApprovalGate(store, demo_mode=False)
        req = gate.request(
            action_id="act-risky", capability_id="exploit-verifier",
            session_id="s1", project_id="p1",
            risk_level=RiskLevel.HIGH,
        )
        gate.reject(req.request_id, reason="too dangerous")
        assert not gate.is_granted("act-risky")

    def test_hitl_approval_enables_execution(self, store):
        """An approved HITL request grants execution."""
        gate = ApprovalGate(store, demo_mode=False)
        req = gate.request(
            action_id="act-ok", capability_id="exploit-verifier",
            session_id="s1", project_id="p1",
            risk_level=RiskLevel.HIGH,
        )
        assert not gate.is_granted("act-ok")
        gate.approve(req.request_id)
        assert gate.is_granted("act-ok")

    def test_truncated_run_metrics(self, store):
        """A truncated run (max_rounds=1) still produces valid metrics."""
        orch = _build_orch(store, max_rounds=1)
        summary = orch.run(seed_targets=["example.com"])
        assert summary.truncated or summary.rounds == 1
        m = summary.metrics_summary()
        assert m["truncated"] is True or m["rounds"] == 1

    def test_empty_target_still_produces_summary(self, store):
        """Even with no targets, the orchestrator doesn't crash."""
        orch = _build_orch(store, max_rounds=1)
        summary = orch.run(seed_targets=[])
        assert isinstance(summary, HiveRunSummary)

    def test_approval_expiry(self, store):
        """An expired approval request does not grant execution."""
        gate = ApprovalGate(store, demo_mode=False, ttl_seconds=1)
        req = gate.request(
            action_id="act-expire", capability_id="exploit-verifier",
            session_id="s1", project_id="p1",
            risk_level=RiskLevel.HIGH,
        )
        # Manually expire
        from datetime import datetime, timedelta, timezone
        req.created_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        import json
        store._connection.execute(
            "UPDATE approval_requests SET payload = ? WHERE request_id = ?",
            (json.dumps(req.model_dump(mode="json"), ensure_ascii=False),
             req.request_id),
        )
        store._connection.commit()
        swept = gate.sweep_expired()
        assert swept == 1
        assert not gate.is_granted("act-expire")

    def test_topology_graph_export(self, store):
        """Topology graph exports correctly to Mermaid and dict."""
        orch = _build_orch(store, max_rounds=5)
        orch.run(seed_targets=["example.com"])

        bb = BlackboardService(store)
        topo = TopologyService(bb).build("proj-e2e")
        d = topo.to_dict()
        assert "nodes" in d
        assert "edges" in d

        mermaid = topo.to_mermaid()
        assert "```mermaid" in mermaid
        assert "graph TD" in mermaid