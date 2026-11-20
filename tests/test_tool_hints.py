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

    def test_vuln_scan_carries_cve_tag(self):
        """Ghostcat-style findings need the cve tag; the light default set misses them."""
        hints = _orch()._tool_hints(
            _action(target_refs=["http://10.0.0.5"], expected_outputs=["vulnerability.detected"]),
            capability_id="framework-vuln",
        )
        assert any("tags='cve," in h for h in hints)

    def test_web_attack_uses_lightweight_tags(self):
        """CVE coverage lives in framework-vuln; web-attack stays fast."""
        hints = _orch()._tool_hints(
            _action(target_refs=["http://10.0.0.5"], expected_outputs=["vulnerability.detected"]),
            capability_id="web-attack",
        )
        assert any("tags='sqli," in h for h in hints)
        assert not any("cve," in h for h in hints)


class TestScanTargetExpansion:
    """Scan hints must cover every discovered web service, not just one port."""

    def _orch_with_services(self, services: list[tuple[int, str]]) -> HiveOrchestrator:
        from src.blackboard.service import BlackboardService
        from src.domain.models import Evidence
        from src.domain.storage import SQLiteStore

        store = SQLiteStore(":memory:")
        blackboard = BlackboardService(store)
        blackboard.ingest_result(Evidence(
            evidence_id="ev-scan-targets",
            project_id="proj-scan",
            session_id="sess-scan",
            task_id="task-scan",
            agent_id="info-gatherer",
            kind="agent.result",
            raw_payload={"observations": [
                {
                    "fact_type": "service.exposed",
                    "asset_ref": "10.0.0.5",
                    "data": {"protocol": "tcp", "port": port, "service_name": name},
                    "identity": {"protocol": "tcp", "port": port},
                    "confidence": 0.9,
                    "state": "active",
                }
                for port, name in services
            ]},
        ))

        orch = _orch(["10.0.0.5"])
        orch._project_id = "proj-scan"
        orch._blackboard = blackboard
        return orch

    def test_expands_to_all_http_services(self):
        orch = self._orch_with_services([(80, "http"), (8009, "unknown"), (9200, "unknown")])
        hints = orch._tool_hints(
            _action(target_refs=["http://10.0.0.5"], expected_outputs=["vulnerability.detected"]),
            capability_id="web-attack",
        )
        joined = "\n".join(hints)
        assert "10.0.0.5:80" in joined
        assert "10.0.0.5:8009" in joined      # AJP → Ghostcat surface
        assert "10.0.0.5:9200" in joined      # ElasticSearch

    def test_skips_non_web_services(self):
        orch = self._orch_with_services([(22, "ssh"), (445, "smb"), (3306, "mysql")])
        hints = orch._tool_hints(
            _action(target_refs=["http://10.0.0.5"], expected_outputs=["vulnerability.detected"]),
            capability_id="web-attack",
        )
        # No web service discovered → fall back to the action's own target
        assert len(hints) == 1
        assert "http://10.0.0.5'" in hints[0]

    def test_caps_number_of_targets(self):
        orch = self._orch_with_services(
            [(80, "http"), (8080, "http"), (8009, "unknown"), (9200, "unknown"), (8282, "unknown")],
        )
        hints = orch._tool_hints(
            _action(target_refs=["http://10.0.0.5"], expected_outputs=["vulnerability.detected"]),
            capability_id="web-attack",
        )
        assert 1 <= len(hints) <= 4  # hard cap keeps runtime bounded

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