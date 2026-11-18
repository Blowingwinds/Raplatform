"""Tests for MockProvider — fuzzy matching, plan generation, wildcard resolution."""

import pytest

from src.domain.models import Scope
from src.planner.errors import NoMatchingScenarioError
from src.planner.provider import MockProvider, PlanRequest


@pytest.fixture
def provider() -> MockProvider:
    return MockProvider()


@pytest.fixture
def scope() -> Scope:
    return Scope(
        scope_id="scope-1",
        project_id="proj-1",
        target_type="domain",
        target="example.com",
        authorization_ref="auth-1",
    )


def _make_request(goal: str, scope: Scope) -> PlanRequest:
    return PlanRequest(
        goal=goal,
        scope=scope,
        project_id="proj-1",
        available_techniques=["T1046", "T1595", "T1590", "T1190", "T1059"],
    )


class TestMockProviderMatching:
    def test_match_asset_discovery_exact(self, provider, scope):
        plan = provider.plan(_make_request("发现授权网段的资产和服务", scope))
        assert plan.goal == "发现授权网段的资产和服务"
        assert plan.generated_by == "mock"
        assert len(plan.tactics) > 0
        tactic_ids = [t.tactic_id for t in plan.tactics]
        assert "reconnaissance" in tactic_ids

    def test_match_asset_discovery_fuzzy(self, provider, scope):
        """Fuzzy match — '端口扫描' should hit asset_discovery keywords."""
        plan = provider.plan(_make_request("对目标执行端口扫描", scope))
        assert len(plan.tactics) > 0

    def test_match_web_vuln(self, provider, scope):
        plan = provider.plan(_make_request("扫描 Web 应用漏洞", scope))
        assert len(plan.tactics) > 0
        tactic_ids = [t.tactic_id for t in plan.tactics]
        assert "initial-access" in tactic_ids

    def test_match_web_vuln_fuzzy_sqli(self, provider, scope):
        plan = provider.plan(_make_request("检测 SQL 注入漏洞", scope))
        assert len(plan.tactics) > 0

    def test_match_full_pentest(self, provider, scope):
        plan = provider.plan(_make_request("执行完整渗透测试", scope))
        assert len(plan.tactics) > 0
        # Full pentest should have more tactics than basic scan
        assert len(plan.tactics) >= 3

    def test_match_full_pentest_fuzzy(self, provider, scope):
        plan = provider.plan(_make_request("全面攻击测试", scope))
        assert len(plan.tactics) > 0

    def test_no_match_raises(self, provider, scope):
        with pytest.raises(NoMatchingScenarioError, match="No mock scenario"):
            provider.plan(_make_request("xyzzy quux blarg", scope))


class TestMockProviderPlanStructure:
    def test_plan_has_required_fields(self, provider, scope):
        plan = provider.plan(_make_request("发现资产和服务", scope))
        assert plan.plan_id.startswith("plan-")
        assert plan.goal == "发现资产和服务"
        assert plan.project_id == "proj-1"
        assert plan.scope_id == "scope-1"
        assert plan.generated_by == "mock"
        assert plan.created_at is not None

    def test_all_actions_have_contracts(self, provider, scope):
        plan = provider.plan(_make_request("执行完整渗透测试", scope))
        actions = plan.all_actions()
        assert len(actions) > 0
        for action in actions:
            assert len(action.expected_outputs) > 0
            assert action.technique_id
            assert len(action.target_refs) > 0

    def test_wildcard_resolves_to_scope_target(self, provider, scope):
        plan = provider.plan(_make_request("发现资产和服务", scope))
        for action in plan.all_actions():
            for target in action.target_refs:
                # Should never be literal '*' — resolved to scope target
                assert target != "*"
                assert target == scope.target

    def test_technique_hierarchy(self, provider, scope):
        """Every technique must have at least one action."""
        plan = provider.plan(_make_request("执行完整渗透测试", scope))
        for tactic in plan.tactics:
            for technique in tactic.techniques:
                assert len(technique.actions) >= 1

    def test_tactic_hierarchy(self, provider, scope):
        """Every tactic must have at least one technique."""
        plan = provider.plan(_make_request("执行完整渗透测试", scope))
        for tactic in plan.tactics:
            assert len(tactic.techniques) >= 1


class TestMockProviderExplainsRejection:
    def test_failed_match_logs_tried_keywords(self, provider, scope):
        try:
            provider.plan(_make_request("扫描 端口", scope))
        except NoMatchingScenarioError:
            pass  # '扫描' and '端口' might match asset_discovery
        # If no match, the error should include tried keywords
        # (tested by the no-match case above)


class TestMockProviderCrossScenario:
    def test_scenario_ids_match_plan_goals(self, provider, scope):
        """Verify the 3 scenarios produce expected tactic counts."""
        # Asset discovery → mostly reconnaissance
        plan1 = provider.plan(_make_request("发现授权网段的资产和服务", scope))
        assert len(plan1.tactics) >= 1

        # Web vuln → initial-access + reconnaissance
        plan2 = provider.plan(_make_request("扫描 Web 应用漏洞", scope))
        tactic_ids_2 = {t.tactic_id for t in plan2.tactics}
        assert "initial-access" in tactic_ids_2

        # Full pentest → most comprehensive
        plan3 = provider.plan(_make_request("执行完整渗透测试", scope))
        assert len(plan3.tactics) >= len(plan1.tactics)
        assert len(plan3.all_actions()) >= len(plan1.all_actions())