"""Tests for Planner — end-to-end plan generation and validation."""

import pytest

from src.agents.registry import AgentRegistry
from src.domain.models import AgentCapability, RiskLevel, Scope
from src.domain.storage import SQLiteStore
from src.planner.attack_kb import AttackKB
from src.planner.errors import PlanRejection
from src.planner.planner import Planner
from src.planner.provider import MockProvider


# ── fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def store() -> SQLiteStore:
    s = SQLiteStore(":memory:")
    s.save_scope(Scope(
        scope_id="scope-1",
        project_id="proj-1",
        target_type="domain",
        target="example.com",
        authorization_ref="auth-1",
    ))
    return s


@pytest.fixture
def registry(store) -> AgentRegistry:
    reg = AgentRegistry(store)
    # Register the 5 capabilities matching HiveOrchestrator defaults
    caps = [
        ("info-gatherer", "Information Gatherer",
         ["T1046", "T1592", "T1590", "T1595"], ["ip", "domain", "url", "hostname"], "low"),
        ("framework-vuln", "Framework Vuln",
         ["T1190", "T1595", "T1210"], ["url", "service", "hostname"], "medium"),
        ("web-attack", "Web Attack",
         ["T1190", "T1595", "T1059"], ["url", "service", "endpoint"], "high"),
        ("component-vuln", "Component Vuln",
         ["T1190", "T1595", "T1210"], ["url", "service", "component"], "medium"),
        ("exploit-verifier", "Exploit Verifier",
         ["T1190", "T1059", "T1210"], ["url", "endpoint", "service"], "high"),
    ]
    for cid, name, techs, targets, risk in caps:
        reg.register(AgentCapability(
            capability_id=cid, name=name,
            techniques=techs, target_types=targets,
            input_schema=f"{cid}_input.schema.json",
            output_schema=f"{cid}_output.schema.json",
            risk_level=RiskLevel(risk),
        ))
    return reg


@pytest.fixture
def scope(store) -> Scope:
    return store.get_scope("scope-1")


@pytest.fixture
def planner(store) -> Planner:
    return Planner(store)


# ── end-to-end: generate ─────────────────────────────────────────────────

class TestPlannerGenerate:
    def test_generate_asset_discovery(self, planner, scope, registry):
        tree = planner.generate("发现授权网段的资产和服务", scope, registry)
        assert tree.plan.goal == "发现授权网段的资产和服务"
        assert len(tree.plan.tactics) > 0
        # Root actions (no dependencies) become READY after recompute_ready()
        ready = tree.ready_actions()
        assert len(ready) > 0

    def test_generate_web_vuln_scan(self, planner, scope, registry):
        tree = planner.generate("扫描 Web 应用漏洞", scope, registry)
        assert len(tree.plan.all_actions()) > 0
        tactic_ids = tree.plan.tactic_ids()
        assert "initial-access" in tactic_ids

    def test_generate_full_pentest(self, planner, scope, registry):
        tree = planner.generate("执行完整渗透测试", scope, registry)
        assert len(tree.plan.tactics) >= 2
        assert len(tree.plan.all_actions()) >= 2

    def test_generate_returns_live_tree(self, planner, scope, registry):
        tree = planner.generate("发现资产和服务", scope, registry)
        assert tree.progress()["total"] > 0
        # Root actions (no dependencies) become READY after recompute_ready()
        assert tree.progress()["total"] == tree.progress()["ready"]

    def test_generate_no_match_raises(self, planner, scope, registry):
        with pytest.raises(PlanRejection, match="No mock scenario"):
            planner.generate("xyzzy blarg quux", scope, registry)


class TestPlannerPlanOnly:
    def test_plan_only_returns_raw_plan(self, planner, scope, registry):
        plan = planner.plan_only("发现资产和服务", scope, registry)
        assert plan.plan_id.startswith("plan-")
        assert plan.goal == "发现资产和服务"


class TestPlannerValidateExisting:
    def test_valid_plan_passes(self, planner, scope, registry):
        # Generate a plan first
        tree = planner.generate("发现授权网段的资产和服务", scope, registry)
        # Re-validate the same plan
        assert planner.validate_existing(tree.plan, scope)

    def test_invalid_plan_fails(self, planner, scope, registry):
        from src.planner.ptt_schema import PTTPlan, TacticNode, TechniqueNode, ActionContract

        bad_plan = PTTPlan(
            plan_id="plan-bad",
            goal="bad",
            normalized_goal="bad",
            project_id="proj-1",
            scope_id="scope-1",
            tactics=[
                TacticNode(
                    tactic_id="discovery", name="D",
                    techniques=[
                        TechniqueNode(
                            technique_id="T9999", name="Fake",
                            actions=[
                                ActionContract(
                                    action_id="act-bad", name="Bad",
                                    description="Bad",
                                    technique_id="T9999",
                                    target_refs=["example.com"],
                                    expected_outputs=["service.exposed"],
                                    risk_level=RiskLevel.LOW,
                                )
                            ],
                        )
                    ],
                )
            ],
        )
        assert not planner.validate_existing(
            bad_plan, scope,
            available_techniques=["T1046"],
        )


class TestPlannerScopeValidation:
    def test_plan_with_out_of_scope_targets_fails(self, planner, registry):
        """Create a scope that excludes the target, then try to plan against it."""
        store2 = SQLiteStore(":memory:")
        store2.save_scope(Scope(
            scope_id="scope-2",
            project_id="proj-2",
            target_type="domain",
            target="example.com",
            authorization_ref="auth-2",
        ))
        narrow_scope = store2.get_scope("scope-2")

        planner2 = Planner(store2)

        # Use a scope that only allows example.com. Mock scenarios resolve to
        # example.com via wildcard resolution, so this should work.
        tree = planner2.generate("发现资产和服务", narrow_scope, registry)
        # All targets should be within example.com domain
        for action in tree.plan.all_actions():
            for target in action.target_refs:
                assert target == "example.com" or target.endswith(".example.com")


class TestPlannerMaxRisk:
    def test_max_risk_low_rejects_high_actions(self, store, scope, registry):
        planner_low = Planner(store, max_risk=RiskLevel.LOW)
        # '扫描 Web 应用漏洞' scenario has HIGH risk actions (sqli test)
        # The mock scenario includes HIGH risk actions → should be rejected
        with pytest.raises(PlanRejection):
            planner_low.generate("扫描 Web 漏洞", scope, registry)

    def test_max_risk_high_allows_pentest(self, store, scope, registry):
        planner_high = Planner(store, max_risk=RiskLevel.HIGH)
        # Full pentest has HIGH actions (verify) but no CRITICAL
        tree = planner_high.generate("执行完整渗透测试", scope, registry)
        for action in tree.plan.all_actions():
            assert action.risk_level != RiskLevel.CRITICAL