"""Tests for AgentRegistry — register, unregister, and query agents."""

import pytest

from src.agents.registry import AgentRegistry
from src.domain.models import AgentCapability, RiskLevel
from src.domain.storage import SQLiteStore


@pytest.fixture
def store():
    s = SQLiteStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def registry(store):
    return AgentRegistry(store)


@pytest.fixture
def gatherer():
    return AgentCapability(
        capability_id="agent-info-gatherer",
        name="Information Gatherer",
        techniques=["T1046", "T1592"],
        target_types=["ip", "domain", "url"],
        input_schema="info_gatherer_input.schema.json",
        output_schema="info_gatherer_output.schema.json",
        risk_level=RiskLevel.LOW,
        side_effects=[],
        max_concurrency=4,
    )


@pytest.fixture
def vuln_scanner():
    return AgentCapability(
        capability_id="agent-vuln-scanner",
        name="Vulnerability Scanner",
        techniques=["T1190", "T1595"],
        target_types=["url", "service"],
        input_schema="vuln_scanner_input.schema.json",
        output_schema="vuln_scanner_output.schema.json",
        risk_level=RiskLevel.HIGH,
        side_effects=["may trigger WAF alerts", "active probing"],
        max_concurrency=1,
    )


class TestRegistryLifecycle:

    def test_register_and_retrieve(self, registry, gatherer):
        registry.register(gatherer)
        result = registry.get("agent-info-gatherer")
        assert result is not None
        assert result.name == "Information Gatherer"

    def test_register_duplicate_raises(self, registry, gatherer):
        registry.register(gatherer)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(gatherer)

    def test_unregister_and_get_none(self, registry, gatherer):
        registry.register(gatherer)
        registry.unregister("agent-info-gatherer")
        assert registry.get("agent-info-gatherer") is None

    def test_unregister_missing_raises(self, registry):
        with pytest.raises(ValueError, match="not registered"):
            registry.unregister("nonexistent")

    def test_list_all(self, registry, gatherer, vuln_scanner):
        registry.register(gatherer)
        registry.register(vuln_scanner)
        all_agents = registry.list_all()
        assert len(all_agents) == 2
        names = {a.name for a in all_agents}
        assert names == {"Information Gatherer", "Vulnerability Scanner"}


class TestRegistryMatching:

    def test_find_by_techniques(self, registry, gatherer, vuln_scanner):
        registry.register(gatherer)
        registry.register(vuln_scanner)
        results = registry.find_by_techniques(["T1046"])
        assert len(results) == 1
        assert results[0].capability_id == "agent-info-gatherer"

    def test_find_by_target_type(self, registry, gatherer, vuln_scanner):
        registry.register(gatherer)
        registry.register(vuln_scanner)
        results = registry.find_by_target_type("url")
        ids = {r.capability_id for r in results}
        assert ids == {"agent-info-gatherer", "agent-vuln-scanner"}

    def test_find_by_target_type_ip_only(self, registry, gatherer, vuln_scanner):
        registry.register(gatherer)
        registry.register(vuln_scanner)
        results = registry.find_by_target_type("ip")
        assert len(results) == 1
        assert results[0].capability_id == "agent-info-gatherer"

    def test_find_best_scores_candidates(self, registry, gatherer, vuln_scanner):
        registry.register(gatherer)
        registry.register(vuln_scanner)
        results = registry.find_best(techniques=["T1046"], target_types=["url"])
        # gatherer matches both technique and target_type → higher score
        assert results[0].capability_id == "agent-info-gatherer"

    def test_risk_max_filters_out_high_risk(self, registry, gatherer, vuln_scanner):
        registry.register(gatherer)
        registry.register(vuln_scanner)
        results = registry.find_by_target_type("url", risk_max=RiskLevel.LOW)
        ids = {r.capability_id for r in results}
        assert ids == {"agent-info-gatherer"}  # vuln_scanner is HIGH

    def test_find_best_with_no_criteria_returns_all(self, registry, gatherer, vuln_scanner):
        registry.register(gatherer)
        registry.register(vuln_scanner)
        results = registry.find_best()
        assert len(results) == 2