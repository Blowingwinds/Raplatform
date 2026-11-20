"""Tests for port-level lease resource key derivation (阶段 5 补丁 2)."""

from types import SimpleNamespace

from src.agents.hive.orchestrator import HiveOrchestrator


def _action(*targets: str) -> SimpleNamespace:
    return SimpleNamespace(target_refs=list(targets))


class TestLeaseResourceRef:
    """Lease keys must be port-level so multi-service hosts scan in parallel."""

    def test_url_with_explicit_port(self):
        assert HiveOrchestrator._lease_resource_ref(
            _action("http://10.0.0.5:8080/admin"),
        ) == "10.0.0.5:8080"

    def test_https_defaults_to_443(self):
        assert HiveOrchestrator._lease_resource_ref(
            _action("https://target.local/"),
        ) == "target.local:443"

    def test_http_defaults_to_80(self):
        assert HiveOrchestrator._lease_resource_ref(
            _action("http://target.local/path"),
        ) == "target.local:80"

    def test_host_port_string_kept(self):
        assert HiveOrchestrator._lease_resource_ref(_action("10.0.0.5:22")) == "10.0.0.5:22"

    def test_bare_host_stays_target_level(self):
        assert HiveOrchestrator._lease_resource_ref(_action("10.0.0.5")) == "10.0.0.5"

    def test_no_targets_is_unscoped(self):
        assert HiveOrchestrator._lease_resource_ref(_action()) == "unscoped"