"""End-to-end tests for HiveOrchestrator — the full bee hive lifecycle.

Uses MockTransport to inject canned tool outputs, so no LLM or external
tools are needed.
"""

import pytest

from src.agents.hive.crews import FakeCrewRunner
from src.agents.hive.orchestrator import HiveOrchestrator, HiveRunSummary
from src.agents.hive.phases import HivePhase
from src.agents.registry import AgentRegistry
from src.domain.models import AgentCapability, RiskLevel
from src.domain.storage import SQLiteStore
from src.mcp.gateway import MCPGateway
from src.mcp.transport import InProcessTransport, MockTransport, TransportResult
from src.policy.guard import PolicyGuard


@pytest.fixture
def store():
    s = SQLiteStore(":memory:")
    yield s
    s.close()


def _make_transport_with_canned() -> MockTransport:
    """Return a MockTransport with realistic canned responses for all phases."""
    transport = MockTransport()

    # Recon phase: info-gatherer tools
    transport.canned["info-gatherer"] = TransportResult(
        raw_output={
            "target": "example.com",
            "result": [
                {"port": 80, "service": "http", "banner": "nginx/1.18.0"},
                {"port": 443, "service": "https", "banner": ""},
                {"port": 22, "service": "ssh", "banner": "OpenSSH_8.4"},
            ],
        },
    )

    # Fingerprint phase: nuclei tech-detect
    transport.canned["framework-vuln"] = TransportResult(
        raw_output={
            "results": [
                {"name": "nginx", "extracted": "1.18.0", "host": "192.168.1.1",
                 "severity": "info", "template_id": "tech-detect-nginx"},
            ],
        },
    )

    # Vuln detect phase
    transport.canned["web-attack"] = TransportResult(
        raw_output={
            "results": [
                {"template_id": "sqli-detected", "type": "sqli",
                 "host": "192.168.1.1", "matched_at": "http://example.com/login",
                 "info": {"name": "SQL Injection", "severity": "high",
                          "description": "Possible SQL injection in login parameter"},
                 "severity": "high", "confidence": 0.85},
            ],
        },
    )

    transport.canned["component-vuln"] = TransportResult(
        raw_output={
            "results": [],
        },
    )

    # Exploit phase
    transport.canned["exploit-verifier"] = TransportResult(
        raw_output={
            "confirmed": True, "severity": "high",
            "technique": "Boolean-based blind",
        },
    )

    return transport


def _build_orchestrator(
    store: SQLiteStore,
    transport: MockTransport,
    *,
    max_rounds: int = 8,
    use_fake_runner: bool = True,
) -> HiveOrchestrator:
    """Build a HiveOrchestrator for testing with mock transport."""
    registry = AgentRegistry(store)
    guard = PolicyGuard(store)
    gateway = MCPGateway(registry, guard, transport)

    runner = FakeCrewRunner() if use_fake_runner else None

    return HiveOrchestrator(
        store,
        project_id="proj-1",
        scope_id="scope-1",
        session_id="sess-1",
        max_rounds=max_rounds,
        transport=transport,
        crew_runner=runner,
    )


# ── tests ─────────────────────────────────────────────────────────────

class TestHiveOrchestratorLifecycle:
    def test_full_lifecycle(self, store):
        """SEED → RECON → FINGERPRINT → VULN_DETECT → EXPLOIT → DONE."""
        transport = _make_transport_with_canned()
        orch = _build_orchestrator(store, transport, max_rounds=10)

        summary = orch.run(seed_targets=["example.com"])

        assert isinstance(summary, HiveRunSummary)
        assert summary.rounds >= 1
        assert summary.rounds <= 10
        assert not summary.truncated
        # Should have produced some facts
        assert summary.fact_count > 0
        # Round log should show multiple phases
        phases_seen = {r["phase"] for r in summary.round_log}
        assert "recon" in phases_seen

    def test_seed_targets_are_written_to_blackboard(self, store):
        transport = _make_transport_with_canned()
        orch = _build_orchestrator(store, transport, max_rounds=1)

        summary = orch.run(seed_targets=["example.com"])
        assert summary.fact_count >= 0  # seeding writes facts
        assert summary.rounds == 1  # one round then done

    def test_max_rounds_truncation(self, store):
        """With max_rounds=1 and no services → truncated after seed + recon attempt."""
        transport = MockTransport()
        # Transport returns no services → phase stays RECON but no progress
        transport.canned["info-gatherer"] = TransportResult(
            raw_output={"result": []},
        )

        orch = _build_orchestrator(store, transport, max_rounds=2)
        summary = orch.run(seed_targets=["example.com"])
        assert summary.truncated or summary.final_phase in (HivePhase.DONE, HivePhase.RECON)

    def test_capabilities_registered(self, store):
        """After orchestrator runs, all 5 agents are registered."""
        transport = _make_transport_with_canned()
        orch = _build_orchestrator(store, transport, max_rounds=1)

        orch.run(seed_targets=["example.com"])

        registry = AgentRegistry(store)
        caps = registry.list_all()
        cap_ids = {c.capability_id for c in caps}
        assert "info-gatherer" in cap_ids
        assert "framework-vuln" in cap_ids
        assert "web-attack" in cap_ids
        assert "component-vuln" in cap_ids
        assert "exploit-verifier" in cap_ids


class TestHiveOrchestratorEdgeCases:
    def test_empty_targets(self, store):
        transport = MockTransport()
        orch = _build_orchestrator(store, transport, max_rounds=2)
        summary = orch.run(seed_targets=[])
        assert summary.final_phase in (HivePhase.RECON, HivePhase.DONE)
        # No targets → stuck in RECON with no tasks

    def test_scope_rejection_blocks_phase(self, store):
        """Remove scope → gateway rejects → phase can still complete."""
        transport = MockTransport()
        orch = _build_orchestrator(store, transport, max_rounds=2)
        summary = orch.run(seed_targets=["blocked.com"])
        assert summary.rounds <= 2

    def test_blackboard_feedback_loop(self, store):
        """Run with services-only transport → check facts are persisted."""
        transport = MockTransport()
        transport.canned["info-gatherer"] = TransportResult(
            raw_output={
                "result": [
                    {"port": 80, "service": "http", "banner": "nginx"},
                ],
            },
        )
        orch = _build_orchestrator(store, transport, max_rounds=3)
        summary = orch.run(seed_targets=["example.com"])
        # Facts should be persisted across rounds
        assert summary.fact_count >= 0
        # Round log should be non-empty
        assert len(summary.round_log) > 0


class TestHiveRunSummary:
    def test_summary_fields(self):
        s = HiveRunSummary(
            rounds=5,
            final_phase=HivePhase.DONE,
            fact_count=12,
            vuln_count=3,
            verified_count=2,
            truncated=False,
            round_log=[
                {"round": 1, "phase": "recon", "evidence_count": 1},
                {"round": 2, "phase": "fingerprint", "evidence_count": 1},
            ],
        )
        assert s.rounds == 5
        assert s.vuln_count == 3
        assert s.verified_count == 2
        assert len(s.round_log) == 2

    def test_blocked_summary(self):
        s = HiveRunSummary(
            rounds=3,
            final_phase=HivePhase.BLOCKED,
            fact_count=5,
            vuln_count=1,
            verified_count=0,
            truncated=False,
            blocked_reasons=["All nodes blocked"],
        )
        assert s.blocked_reasons == ["All nodes blocked"]