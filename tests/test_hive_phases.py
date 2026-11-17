"""Tests for HivePhase detection logic."""

import pytest

from src.agents.hive.phases import (
    HivePhase,
    PhaseContext,
    detect_phase,
    is_terminal,
)
from src.agents.shared.attack_dag import AttackDAG, AttackNode, NodeStatus
from src.domain.models import BlackboardFact, FactState


# ── helpers ───────────────────────────────────────────────────────────

def _make_fact(
    fact_id: str,
    fact_type: str,
    asset_ref: str = "192.168.1.1",
    data: dict | None = None,
    verified: bool = False,
) -> BlackboardFact:
    d = dict(data) if data else {}
    if fact_type == "vulnerability.detected":
        d.setdefault("verified", verified)
    return BlackboardFact(
        fact_id=fact_id,
        project_id="proj-1",
        fact_type=fact_type,
        asset_ref=asset_ref,
        data=d,
        confidence=0.9,
        source_agent="test-agent",
        session_id="sess-1",
        evidence_ref="ev-1",
    )


# ── detect_phase tests ─────────────────────────────────────────────────

class TestPhaseDetection:
    def test_empty_blackboard_returns_recon(self):
        ctx = detect_phase([])
        assert ctx.phase == HivePhase.RECON
        assert "No service.exposed" in ctx.reason

    def test_services_without_fingerprints_returns_fingerprint(self):
        facts = [_make_fact("f1", "service.exposed", data={"port": 80, "service_name": "http"})]
        ctx = detect_phase(facts)
        assert ctx.phase == HivePhase.FINGERPRINT
        assert ctx.services_count == 1
        assert ctx.fingerprint_count == 0

    def test_fingerprints_without_vulns_returns_vuln_detect(self):
        facts = [
            _make_fact("f1", "service.exposed", data={"port": 80, "service_name": "http"}),
            _make_fact("f2", "fingerprint.detected", data={"name": "nginx", "host": "192.168.1.1"}),
        ]
        ctx = detect_phase(facts)
        assert ctx.phase == HivePhase.VULN_DETECT
        assert ctx.vuln_count == 0

    def test_unverified_vulns_return_exploit(self):
        facts = [
            _make_fact("f1", "service.exposed", data={"port": 80, "service_name": "http"}),
            _make_fact("f2", "fingerprint.detected", data={"name": "nginx", "host": "192.168.1.1"}),
            _make_fact("f3", "vulnerability.detected", asset_ref="192.168.1.1",
                       data={"vulnerability_id": "v1", "verified": False, "category": "sqli"}),
        ]
        ctx = detect_phase(facts)
        assert ctx.phase == HivePhase.EXPLOIT
        assert ctx.unverified_count == 1

    def test_all_verified_returns_done(self):
        facts = [
            _make_fact("f1", "service.exposed", data={"port": 80, "service_name": "http"}),
            _make_fact("f2", "fingerprint.detected", data={"name": "nginx", "host": "192.168.1.1"}),
            _make_fact("f3", "vulnerability.detected", asset_ref="192.168.1.1",
                       data={"vulnerability_id": "v1", "verified": True, "category": "sqli"}),
        ]
        ctx = detect_phase(facts)
        assert ctx.phase == HivePhase.DONE
        assert ctx.unverified_count == 0

    def test_no_new_events_two_rounds_returns_done(self):
        facts = [_make_fact("f1", "service.exposed", data={"port": 80, "service_name": "http"})]
        ctx = detect_phase(facts, no_new_events_rounds=2)
        assert ctx.phase == HivePhase.DONE
        assert "No new blackboard events" in ctx.reason

    def test_dag_blocked_with_no_ready_returns_blocked(self):
        facts = [
            _make_fact("f1", "service.exposed", data={"port": 80, "service_name": "http"}),
            _make_fact("f2", "fingerprint.detected", data={"name": "nginx", "host": "192.168.1.1"}),
            _make_fact("f3", "vulnerability.detected", asset_ref="192.168.1.1",
                       data={"vulnerability_id": "v1", "verified": True, "category": "sqli"}),
        ]
        dag = AttackDAG(project_id="proj-1")
        dag.nodes["n1"] = AttackNode(
            node_id="n1", step_id="s1", tool="verify_sqli",
            target="x", priority="high", description="test",
            status=NodeStatus.BLOCKED,
        )
        ctx = detect_phase(facts, dag)
        assert ctx.phase == HivePhase.BLOCKED

    def test_dag_ready_nodes_continue_exploit(self):
        facts = [
            _make_fact("f1", "service.exposed", data={"port": 80, "service_name": "http"}),
            _make_fact("f2", "fingerprint.detected", data={"name": "nginx", "host": "192.168.1.1"}),
            _make_fact("f3", "vulnerability.detected", asset_ref="192.168.1.1",
                       data={"vulnerability_id": "v1", "verified": True, "category": "sqli"}),
        ]
        dag = AttackDAG(project_id="proj-1")
        dag.nodes["n1"] = AttackNode(
            node_id="n1", step_id="s1", tool="execute_python",
            target="x", priority="medium", description="test",
            status=NodeStatus.READY,
        )
        ctx = detect_phase(facts, dag)
        assert ctx.phase == HivePhase.EXPLOIT
        assert "DAG node(s) ready" in ctx.reason


class TestIsTerminal:
    def test_done_is_terminal(self):
        assert is_terminal(HivePhase.DONE)

    def test_blocked_is_terminal(self):
        assert is_terminal(HivePhase.BLOCKED)

    def test_recon_is_not_terminal(self):
        assert not is_terminal(HivePhase.RECON)

    def test_exploit_is_not_terminal(self):
        assert not is_terminal(HivePhase.EXPLOIT)


class TestPhaseContext:
    def test_context_stores_counts(self):
        ctx = PhaseContext(
            phase=HivePhase.RECON,
            services_count=0, fingerprint_count=0,
            vuln_count=0, unverified_count=0,
            dag_ready=0, dag_blocked=0, dag_total=0,
            reason="test",
        )
        assert ctx.phase == HivePhase.RECON
        assert ctx.services_count == 0
        assert ctx.reason == "test"

    def test_exploit_context_shows_unverified(self):
        ctx = PhaseContext(
            phase=HivePhase.EXPLOIT,
            services_count=3, fingerprint_count=2,
            vuln_count=5, unverified_count=3,
            dag_ready=2, dag_blocked=0, dag_total=5,
            reason="has unverified",
        )
        assert ctx.vuln_count == 5
        assert ctx.unverified_count == 3
        assert ctx.dag_ready == 2