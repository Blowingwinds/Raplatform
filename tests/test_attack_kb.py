"""Tests for AttackKB — ATT&CK knowledge base queries and validation."""

import pytest

from src.domain.models import RiskLevel
from src.planner.attack_kb import AttackKB


@pytest.fixture
def kb() -> AttackKB:
    return AttackKB()


class TestTechniqueValidation:
    def test_known_technique_validates(self, kb):
        assert kb.validate_technique("T1046")

    def test_unknown_technique_rejected(self, kb):
        assert not kb.validate_technique("T9999")

    def test_technique_name(self, kb):
        assert kb.technique_name("T1046") == "Network Service Discovery"

    def test_unknown_technique_name_is_none(self, kb):
        assert kb.technique_name("T9999") is None

    def test_tactic_for_technique(self, kb):
        assert kb.tactic_for("T1046") == "discovery"
        assert kb.tactic_for("T1595") == "reconnaissance"
        assert kb.tactic_for("T1190") == "initial-access"

    def test_tactic_for_unknown_is_none(self, kb):
        assert kb.tactic_for("T9999") is None

    def test_risk_for_technique(self, kb):
        assert kb.risk_for("T1046") == RiskLevel.LOW
        assert kb.risk_for("T1190") == RiskLevel.HIGH
        assert kb.risk_for("T1210") == RiskLevel.CRITICAL

    def test_risk_for_unknown_is_none(self, kb):
        assert kb.risk_for("T9999") is None

    def test_target_types(self, kb):
        assert "ip" in kb.target_types_for("T1046")
        assert "url" in kb.target_types_for("T1190")

    def test_target_types_unknown_is_empty(self, kb):
        assert kb.target_types_for("T9999") == []

    def test_expected_outputs(self, kb):
        outputs = kb.expected_outputs("T1595")
        assert "asset.discovered" in outputs
        assert "service.exposed" in outputs

    def test_expected_outputs_unknown_is_empty(self, kb):
        assert kb.expected_outputs("T9999") == []

    def test_technique_description(self, kb):
        desc = kb.technique_description("T1046")
        assert len(desc) > 10

    def test_unknown_description_is_empty(self, kb):
        assert kb.technique_description("T9999") == ""


class TestTacticValidation:
    def test_known_tactic_validates(self, kb):
        assert kb.validate_tactic("reconnaissance")
        assert kb.validate_tactic("discovery")
        assert kb.validate_tactic("initial-access")
        assert kb.validate_tactic("execution")
        assert kb.validate_tactic("lateral-movement")

    def test_unknown_tactic_rejected(self, kb):
        assert not kb.validate_tactic("nonexistent")

    def test_tactic_name(self, kb):
        assert kb.tactic_name("reconnaissance") == "Reconnaissance"

    def test_unknown_tactic_name_is_none(self, kb):
        assert kb.tactic_name("nonexistent") is None

    def test_techniques_for_tactic(self, kb):
        recon_techs = kb.techniques_for_tactic("reconnaissance")
        assert "T1595" in recon_techs
        assert "T1592" in recon_techs

    def test_techniques_for_unknown_is_empty(self, kb):
        assert kb.techniques_for_tactic("nonexistent") == []


class TestAggregateQueries:
    def test_all_tactic_ids(self, kb):
        ids = kb.all_tactic_ids()
        assert "reconnaissance" in ids
        assert "discovery" in ids
        assert len(ids) == 5

    def test_all_technique_ids(self, kb):
        ids = kb.all_technique_ids()
        assert "T1046" in ids
        assert "T1210" in ids
        assert len(ids) == 12

    def test_tactics_for_techniques(self, kb):
        mapping = kb.tactics_for_techniques(["T1046", "T1190", "T9999"])
        assert mapping["T1046"] == "discovery"
        assert mapping["T1190"] == "initial-access"
        assert "T9999" not in mapping

    def test_available_techniques_max_risk_low(self, kb):
        techs = kb.available_techniques(max_risk=RiskLevel.LOW)
        for tid in techs:
            risk = kb.risk_for(tid)
            assert risk in (RiskLevel.LOW,)

    def test_available_techniques_max_risk_high(self, kb):
        techs = kb.available_techniques(max_risk=RiskLevel.HIGH)
        for tid in techs:
            risk = kb.risk_for(tid)
            assert risk in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH)

    def test_available_techniques_max_risk_critical(self, kb):
        techs = kb.available_techniques(max_risk=RiskLevel.CRITICAL)
        assert len(techs) == 12  # all techniques