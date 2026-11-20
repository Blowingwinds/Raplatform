"""Tests for AgentRouter — capability selection for ActionContract."""

import pytest

from src.agents.capabilities import register_default_capabilities
from src.agents.registry import AgentRegistry
from src.agents.router import AgentRouter, RouteDecision
from src.domain.lease_service import LeaseService
from src.domain.models import AgentCapability, RiskLevel
from src.domain.storage import SQLiteStore
from src.planner.ptt_schema import ActionContract


# ── fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def store():
    s = SQLiteStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def registry(store):
    return AgentRegistry(store)


@pytest.fixture
def lease(store):
    return LeaseService(store)


@pytest.fixture
def router(registry, lease):
    return AgentRouter(registry, lease)


def _action(
    *,
    technique_id: str = "T1046",
    risk_level: RiskLevel = RiskLevel.LOW,
    action_id: str = "act-1",
) -> ActionContract:
    return ActionContract(
        action_id=action_id,
        name="probe action",
        description="probe the target",
        technique_id=technique_id,
        target_refs=["example.com"],
        expected_outputs=["service.exposed"],
        risk_level=risk_level,
    )


def _cap(
    *,
    capability_id: str,
    techniques: list[str],
    target_types: list[str],
    risk_level: RiskLevel = RiskLevel.LOW,
    max_concurrency: int = 1,
) -> AgentCapability:
    return AgentCapability(
        capability_id=capability_id,
        name=capability_id,
        techniques=techniques,
        target_types=target_types,
        input_schema=f"{capability_id}_input.schema.json",
        output_schema=f"{capability_id}_output.schema.json",
        risk_level=risk_level,
        side_effects=[],
        max_concurrency=max_concurrency,
    )


# ── tests ─────────────────────────────────────────────────────────────────


class TestRouter:
    def test_empty_registry_returns_deferred(self, router):
        """1. No capabilities registered → deferred with empty capability_id."""
        decision = router.route(_action(), target_type="url", session_id="s1")
        assert isinstance(decision, RouteDecision)
        assert decision.deferred is True
        assert decision.capability_id == ""
        assert decision.score == 0.0

    def test_single_match_returns_that_capability(self, router, registry):
        """2. Exactly one matching cap → it is selected, not deferred."""
        registry.register(_cap(
            capability_id="info-gatherer",
            techniques=["T1046"],
            target_types=["url"],
        ))
        decision = router.route(_action(), target_type="url", session_id="s1")
        assert decision.deferred is False
        assert decision.capability_id == "info-gatherer"
        assert decision.score == 2.0  # technique + target overlap

    def test_two_matches_prefer_better_technique_overlap(self, router, registry):
        """3. Both caps match the target; the one also matching the technique wins."""
        # cap_a matches technique T1046 AND target url → score 2
        registry.register(_cap(
            capability_id="cap-a",
            techniques=["T1046"],
            target_types=["url"],
        ))
        # cap_b matches only target url (different technique) → score 1
        registry.register(_cap(
            capability_id="cap-b",
            techniques=["T1190"],
            target_types=["url"],
        ))
        decision = router.route(_action(technique_id="T1046"),
                                target_type="url", session_id="s1")
        assert decision.deferred is False
        assert decision.capability_id == "cap-a"
        assert decision.score == 2.0

    def test_all_candidates_at_max_concurrency_deferred(self, router, registry, lease):
        """4. Every candidate is at max concurrency → deferred=True."""
        # Both candidates allow max_concurrency=1.
        registry.register(_cap(
            capability_id="cap-a",
            techniques=["T1046"],
            target_types=["url"],
            max_concurrency=1,
        ))
        registry.register(_cap(
            capability_id="cap-b",
            techniques=["T1046"],
            target_types=["url"],
            max_concurrency=1,
        ))
        # Put BOTH capabilities at their limit — quotas are per-capability.
        lease.acquire(
            project_id="p1", resource_ref="a:80",
            session_id="s-other", action_id="act-a",
            capability_id="cap-a",
        )
        lease.acquire(
            project_id="p1", resource_ref="b:80",
            session_id="s-other", action_id="act-b",
            capability_id="cap-b",
        )
        decision = router.route(_action(), target_type="url", session_id="s1")
        assert decision.deferred is True
        # A capability id is still reported (the highest-scoring blocked one).
        assert decision.capability_id in {"cap-a", "cap-b"}

    def test_other_capability_load_does_not_block(self, router, registry, lease):
        """4b. A busy *unrelated* capability must not count against this one."""
        registry.register(_cap(
            capability_id="cap-a",
            techniques=["T1046"],
            target_types=["url"],
            max_concurrency=1,
        ))
        registry.register(_cap(
            capability_id="cap-b",
            techniques=["T1046"],
            target_types=["url"],
            max_concurrency=1,
        ))
        # cap-a is at its limit; cap-b is free.
        lease.acquire(
            project_id="p1", resource_ref="x:80",
            session_id="s-other", action_id="act-x",
            capability_id="cap-a",
        )
        decision = router.route(_action(), target_type="url", session_id="s1")
        assert decision.deferred is False
        assert decision.capability_id == "cap-b"

    def test_risk_gate_filters_out_over_risk_capabilities(self, router, registry):
        """5. A cap whose risk_level exceeds the action's is filtered out."""
        # Low-risk cap survives the gate.
        registry.register(_cap(
            capability_id="cap-safe",
            techniques=["T1046"],
            target_types=["url"],
            risk_level=RiskLevel.LOW,
        ))
        # High-risk cap is filtered when action risk is LOW.
        registry.register(_cap(
            capability_id="cap-risky",
            techniques=["T1046"],
            target_types=["url"],
            risk_level=RiskLevel.HIGH,
        ))
        decision = router.route(
            _action(technique_id="T1046", risk_level=RiskLevel.LOW),
            target_type="url", session_id="s1",
        )
        assert decision.deferred is False
        assert decision.capability_id == "cap-safe"

        # When the action's risk budget is HIGH, the risky cap becomes eligible
        # and wins the tie-break (both score 2; lower risk wins → cap-safe still
        # wins, but cap-risky is no longer filtered out — verify by removing
        # the safe cap).
        registry.unregister("cap-safe")
        decision2 = router.route(
            _action(technique_id="T1046", risk_level=RiskLevel.HIGH),
            target_type="url", session_id="s1",
        )
        assert decision2.deferred is False
        assert decision2.capability_id == "cap-risky"


class TestRouterWithDefaultCapabilities:
    """Sanity check against the canonical DEFAULT_CAPABILITIES set."""

    def test_routes_info_gatherer_for_recon(self, router, registry):
        register_default_capabilities(registry)
        decision = router.route(
            _action(technique_id="T1046", risk_level=RiskLevel.LOW),
            target_type="ip", session_id="s1",
        )
        assert decision.deferred is False
        assert decision.capability_id == "info-gatherer"

    def test_high_risk_action_keeps_high_risk_caps(self, router, registry):
        register_default_capabilities(registry)
        # T1190 + url at HIGH risk should keep web-attack (high) eligible.
        decision = router.route(
            _action(technique_id="T1190", risk_level=RiskLevel.HIGH),
            target_type="url", session_id="s1",
        )
        assert decision.deferred is False
        # web-attack matches technique T1190 and target url → score 2,
        # and is the highest-risk eligible cap that matches both.
        assert decision.capability_id in {"web-attack", "framework-vuln",
                                          "component-vuln", "exploit-verifier"}
