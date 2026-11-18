"""Tests for PTTValidator — multi-layer plan validation (ATT&CK, scope, risk, capability)."""

import pytest

from src.domain.models import RiskLevel, Scope
from src.domain.storage import SQLiteStore
from src.planner.attack_kb import AttackKB
from src.planner.contract import PTTValidator, ValidationResult
from src.planner.errors import PlanRejection
from src.planner.ptt_schema import (
    ActionContract,
    PTTPlan,
    TacticNode,
    TechniqueNode,
)
from src.policy.guard import PolicyGuard


# ── helpers ──────────────────────────────────────────────────────────────

def _make_action(
    action_id: str = "act-1",
    technique_id: str = "T1046",
    target_refs: list[str] | None = None,
    expected_outputs: list[str] | None = None,
    risk_level: str = "low",
) -> ActionContract:
    return ActionContract(
        action_id=action_id,
        name="Test Action",
        description="Test",
        technique_id=technique_id,
        target_refs=target_refs or ["example.com"],
        expected_outputs=expected_outputs or ["service.exposed"],
        risk_level=RiskLevel(risk_level),
    )


def _make_plan(
    plan_id: str = "plan-test",
    tactics: list[TacticNode] | None = None,
) -> PTTPlan:
    if tactics is None:
        tactics = [
            TacticNode(
                tactic_id="discovery",
                name="Discovery",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046",
                        name="Network Service Discovery",
                        actions=[_make_action("act-1", "T1046")],
                    )
                ],
            )
        ]
    return PTTPlan(
        plan_id=plan_id,
        goal="test",
        normalized_goal="test",
        project_id="proj-1",
        scope_id="scope-1",
        tactics=tactics,
    )


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
def validator(store) -> PTTValidator:
    kb = AttackKB()
    guard = PolicyGuard(store, demo_mode=True)
    return PTTValidator(kb, guard)


@pytest.fixture
def scope(store) -> Scope:
    return store.get_scope("scope-1")


# ── layer 1: ATT&CK legitimacy ───────────────────────────────────────────

class TestAttackLegitimacy:
    def test_valid_plan_passes(self, validator, scope):
        plan = _make_plan()
        result = validator.validate(plan, scope)
        assert result.passed

    def test_unknown_technique_rejected(self, validator, scope):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T9999", name="Fake",
                        actions=[_make_action("act-x", "T9999")],
                    )
                ],
            )
        ])
        result = validator.validate(plan, scope)
        assert not result.passed
        assert any(e.code == "UNKNOWN_TECHNIQUE" for e in result.errors)

    def test_unknown_tactic_rejected(self, validator, scope):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="nonexistent", name="Fake",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="NSD",
                        actions=[_make_action("act-x", "T1046")],
                    )
                ],
            )
        ])
        result = validator.validate(plan, scope)
        assert not result.passed
        assert any(e.code == "UNKNOWN_TACTIC" for e in result.errors)

    def test_tactic_mismatch_rejected(self, validator, scope):
        """Technique T1046 belongs to 'discovery', not 'reconnaissance'."""
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="reconnaissance", name="R",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="NSD",
                        actions=[_make_action("act-x", "T1046")],
                    )
                ],
            )
        ])
        result = validator.validate(plan, scope)
        assert not result.passed
        assert any(e.code == "TACTIC_MISMATCH" for e in result.errors)


# ── layer 2: capability match ────────────────────────────────────────────

class TestCapabilityMatch:
    def test_all_techniques_available_passes(self, validator, scope):
        plan = _make_plan()
        result = validator.validate(
            plan, scope,
            available_techniques=["T1046", "T1595", "T1190"],
        )
        assert result.passed

    def test_missing_capability_rejected(self, validator, scope):
        plan = _make_plan()
        result = validator.validate(
            plan, scope,
            available_techniques=["T1595"],  # T1046 not available
        )
        assert not result.passed
        assert any(e.code == "CAPABILITY_MISSING" for e in result.errors)

    def test_no_capability_check_when_none_provided(self, validator, scope):
        """When available_techniques is None, skip capability check."""
        plan = _make_plan()
        result = validator.validate(plan, scope)  # no available_techniques
        assert result.passed


# ── layer 3: scope boundary ──────────────────────────────────────────────

class TestScopeBoundary:
    def test_in_scope_target_passes(self, validator, scope):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="NSD",
                        actions=[_make_action("act-1", "T1046", target_refs=["example.com"])],
                    )
                ],
            )
        ])
        result = validator.validate(plan, scope)
        assert result.passed

    def test_wildcard_target_passes(self, validator, scope):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="NSD",
                        actions=[_make_action("act-1", "T1046", target_refs=["*"])],
                    )
                ],
            )
        ])
        result = validator.validate(plan, scope)
        assert result.passed

    def test_subdomain_of_scope_passes(self, validator, scope):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="NSD",
                        actions=[_make_action("act-1", "T1046", target_refs=["api.example.com"])],
                    )
                ],
            )
        ])
        result = validator.validate(plan, scope)
        assert result.passed

    def test_out_of_scope_target_rejected(self, validator, scope):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="NSD",
                        actions=[_make_action("act-1", "T1046", target_refs=["evil.com"])],
                    )
                ],
            )
        ])
        result = validator.validate(plan, scope)
        assert not result.passed
        assert any(e.code == "SCOPE_VIOLATION" for e in result.errors)


# ── layer 4: risk policy ─────────────────────────────────────────────────

class TestRiskPolicy:
    def test_low_risk_within_max_passes(self, validator, scope):
        plan = _make_plan()
        result = validator.validate(plan, scope, max_risk=RiskLevel.LOW)
        assert result.passed

    def test_high_risk_exceeds_max_low_rejected(self, validator, scope):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="initial-access", name="IA",
                techniques=[
                    TechniqueNode(
                        technique_id="T1190", name="Exploit",
                        actions=[_make_action("act-exp", "T1190", risk_level="high")],
                    )
                ],
            )
        ])
        result = validator.validate(plan, scope, max_risk=RiskLevel.LOW)
        assert not result.passed
        assert any(e.code == "RISK_EXCEEDED" for e in result.errors)

    def test_critical_within_max_critical_passes(self, validator, scope):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="lateral-movement", name="LM",
                techniques=[
                    TechniqueNode(
                        technique_id="T1210", name="Remote Exploit",
                        actions=[_make_action("act-crit", "T1210", risk_level="critical")],
                    )
                ],
            )
        ])
        result = validator.validate(plan, scope, max_risk=RiskLevel.CRITICAL)
        assert result.passed


# ── layer 5: output contract ─────────────────────────────────────────────

class TestOutputContract:
    def test_known_fact_types_pass(self, validator, scope):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="NSD",
                        actions=[_make_action("act-1", "T1046",
                                              expected_outputs=["service.exposed", "asset.discovered"])],
                    )
                ],
            )
        ])
        result = validator.validate(plan, scope)
        assert result.passed

    def test_unknown_fact_type_rejected(self, validator, scope):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="NSD",
                        actions=[_make_action("act-1", "T1046",
                                              expected_outputs=["magic.unicorn"])],
                    )
                ],
            )
        ])
        result = validator.validate(plan, scope)
        assert not result.passed
        assert any(e.code == "UNKNOWN_FACT_TYPE" for e in result.errors)


# ── ValidationResult ────────────────────────────────────────────────────

class TestValidationResult:
    def test_raise_if_failed(self, validator, scope):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T9999", name="Fake",
                        actions=[_make_action("act-x", "T9999")],
                    )
                ],
            )
        ])
        result = validator.validate(plan, scope)
        with pytest.raises(PlanRejection, match="PTT plan rejected"):
            result.raise_if_failed()

    def test_bool_conversion(self, validator, scope):
        plan_good = _make_plan()
        assert bool(validator.validate(plan_good, scope))

        plan_bad = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(technique_id="T9999", name="F",
                                  actions=[_make_action("act-x", "T9999")]),
                ],
            )
        ])
        assert not bool(validator.validate(plan_bad, scope))