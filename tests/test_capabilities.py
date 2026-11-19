"""Tests for shared capability definitions."""

import pytest

from src.agents.capabilities import (
    DEFAULT_CAPABILITIES,
    DEFAULT_CAPABILITY_IDS,
    register_default_capabilities,
)
from src.agents.registry import AgentRegistry
from src.domain.storage import SQLiteStore


@pytest.fixture
def store():
    s = SQLiteStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def registry(store):
    return AgentRegistry(store)


class TestDefaultCapabilities:
    def test_all_five_capabilities_defined(self):
        assert len(DEFAULT_CAPABILITIES) == 5

    def test_capability_ids_set(self):
        assert DEFAULT_CAPABILITY_IDS == {
            "info-gatherer",
            "framework-vuln",
            "web-attack",
            "component-vuln",
            "exploit-verifier",
        }

    def test_each_has_required_fields(self):
        for cap in DEFAULT_CAPABILITIES:
            assert "capability_id" in cap
            assert "name" in cap
            assert "techniques" in cap
            assert len(cap["techniques"]) > 0
            assert "target_types" in cap
            assert len(cap["target_types"]) > 0
            assert "risk_level" in cap
            assert "max_concurrency" in cap


class TestRegisterDefaultCapabilities:
    def test_registers_all_five(self, registry):
        count = register_default_capabilities(registry)
        assert count == 5
        assert len(registry.list_all()) == 5

    def test_idempotent(self, registry):
        first = register_default_capabilities(registry)
        assert first == 5
        second = register_default_capabilities(registry)
        assert second == 0  # no new registrations
        assert len(registry.list_all()) == 5

    def test_registered_capabilities_match_defaults(self, registry):
        register_default_capabilities(registry)
        for cap_dict in DEFAULT_CAPABILITIES:
            cap = registry.get(cap_dict["capability_id"])
            assert cap is not None
            assert cap.name == cap_dict["name"]
            assert cap.techniques == cap_dict["techniques"]
            assert cap.target_types == cap_dict["target_types"]
            assert cap.max_concurrency == cap_dict["max_concurrency"]

    def test_no_duplicates_on_partial_existing(self, registry):
        """If some caps already registered, only missing ones are added."""
        # Manually register one capability first
        from src.domain.models import AgentCapability, RiskLevel

        registry.register(AgentCapability(
            capability_id="info-gatherer",
            name="Info Gatherer",
            techniques=["T1046"],
            target_types=["ip"],
            input_schema="x.json",
            output_schema="y.json",
            risk_level=RiskLevel.LOW,
        ))
        # Now register_default should skip info-gatherer
        count = register_default_capabilities(registry)
        assert count == 4
        assert len(registry.list_all()) == 5