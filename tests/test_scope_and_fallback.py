"""Tests for scope wildcard handling and plan-generation fallback."""

from __future__ import annotations

from src.domain.models import Scope
from src.domain.storage import SQLiteStore
from src.planner.providers import LLMProviderError


def _scope(target: str, target_type: str = "domain") -> Scope:
    return Scope(
        scope_id="scope-1",
        project_id="proj-1",
        target_type=target_type,
        target=target,
        authorization_ref="auth-1",
    )


class TestScopeWildcard:
    def test_wildcard_scope_matches_ip(self):
        from src.policy.guard import _target_matches_scope

        assert _target_matches_scope("192.168.240.128", _scope("*")) is True

    def test_wildcard_scope_matches_domain(self):
        from src.policy.guard import _target_matches_scope

        assert _target_matches_scope("example.com", _scope("*")) is True

    def test_exact_scope_still_enforced(self):
        from src.policy.guard import _target_matches_scope

        assert _target_matches_scope("192.168.240.128", _scope("192.168.240.128", "ip")) is True
        assert _target_matches_scope("10.0.0.5", _scope("192.168.240.128", "ip")) is False

    def test_suffix_scope_for_subdomains(self):
        from src.policy.guard import _target_matches_scope

        assert _target_matches_scope("api.example.com", _scope("example.com")) is True
        assert _target_matches_scope("evil-example.com", _scope("example.com")) is False


class TestSessionReuse:
    """Re-running the same session id against the same DB must not crash."""

    def test_reopen_existing_session(self):
        from src.agents.hive.crews import FakeCrewRunner
        from src.agents.hive.orchestrator import HiveOrchestrator

        store = SQLiteStore(":memory:")
        orch = HiveOrchestrator(
            store, project_id="p-ss", scope_id="s-ss", session_id="sess-ss",
            max_rounds=1, crew_runner=FakeCrewRunner(),
        )
        orch._tool_hints = lambda action, capability_id=None: []
        orch._chain_tactics_in_order = lambda: None

        s1 = orch.run(seed_targets=["192.168.240.128"])
        s2 = orch.run(seed_targets=["192.168.240.128"])  # same session id

        assert s1.session_status == s2.session_status
        assert store.get_session("sess-ss") is not None
        store.close()


class TestPlannerFallback:
    """A failing planner must not crash the run — the orchestrator degrades."""

    def test_fallback_plan_is_valid_when_provider_fails(self):
        from src.agents.hive.crews import FakeCrewRunner
        from src.agents.hive.orchestrator import HiveOrchestrator

        store = SQLiteStore(":memory:")
        orch = HiveOrchestrator(
            store, project_id="p-fb", scope_id="s-fb", session_id="sess-fb",
            max_rounds=1, crew_runner=FakeCrewRunner(),
        )

        class _BrokenPlanner:
            def generate(self, **kwargs):
                raise LLMProviderError("simulated LLM outage")

        orch._planner = _BrokenPlanner()
        orch._tool_hints = lambda action, capability_id=None: []
        orch._chain_tactics_in_order = lambda: None

        summary = orch.run(seed_targets=["192.168.240.128"], goal="执行完整渗透测试")

        # Degraded but alive: fallback plan executed at least one action
        assert summary.rounds >= 1
        assert orch._tree is not None
        assert orch._tree.plan.generated_by == "fallback"
        store.close()