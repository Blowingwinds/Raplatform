"""Tests for FakeCrewRunner tool hints derived from action contracts (阶段 5 补丁)."""

from types import SimpleNamespace

from src.agents.hive.orchestrator import HiveOrchestrator


def _orch(seed_targets: list[str] | None = None) -> HiveOrchestrator:
    orch = HiveOrchestrator.__new__(HiveOrchestrator)
    orch._seed_targets = list(seed_targets or [])
    return orch


def _action(**kw) -> SimpleNamespace:
    base = {
        "target_refs": ["*"],
        "expected_outputs": [],
        "description": "",
    }
    base.update(kw)
    return SimpleNamespace(**base)


class TestToolHints:
    def test_wildcard_resolves_to_seed_target(self):
        hints = _orch(["10.0.0.5"])._tool_hints(
            _action(expected_outputs=["service.exposed"]),
        )
        assert "scan_ports(target='10.0.0.5')" in hints

    def test_no_targets_no_hints(self):
        assert _orch()._tool_hints(_action(expected_outputs=["service.exposed"])) == []

    def test_subdomain_enum_for_domain_only(self):
        domain_hints = _orch(["example.com"])._tool_hints(
            _action(expected_outputs=["asset.discovered"]),
        )
        ip_hints = _orch(["10.0.0.5"])._tool_hints(
            _action(expected_outputs=["asset.discovered"]),
        )
        assert any("enumerate_subdomains" in h for h in domain_hints)
        assert not any("enumerate_subdomains" in h for h in ip_hints)

    def test_fingerprint_outputs(self):
        hints = _orch()._tool_hints(
            _action(target_refs=["example.com"], expected_outputs=["fingerprint.detected"]),
        )
        assert hints == ["scan_fingerprints(target='http://example.com')"]

    def test_vulnerability_outputs_keep_url_port(self):
        hints = _orch()._tool_hints(
            _action(
                target_refs=["http://10.0.0.5:8080/app"],
                expected_outputs=["vulnerability.detected"],
            ),
        )
        assert any(h.startswith("scan_vulnerabilities(") for h in hints)
        assert any("10.0.0.5:8080" in h for h in hints)

    def test_verification_action_hint(self):
        hints = _orch()._tool_hints(
            _action(
                target_refs=["http://10.0.0.5:8080/app?id=1"],
                description="验证注入漏洞",
                expected_outputs=["vulnerability.detected"],
            ),
        )
        assert any(h.startswith("verify_sqli(") for h in hints)

    def test_lease_ref_wildcard_uses_fallback(self):
        assert HiveOrchestrator._lease_resource_ref(
            _action(target_refs=["*"]), ["10.0.0.5:8080"],
        ) == "10.0.0.5:8080"