"""Tests for output-driven capability routing (Router.prefer + preference rules)."""

from __future__ import annotations

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
        "risk_level": "low",
    }
    base.update(kw)
    return SimpleNamespace(**base)


class TestPreferredCapability:
    """Expected outputs must decide which tools run, not overlapping techniques."""

    def test_recon_outputs_go_to_info_gatherer(self):
        orch = _orch()
        assert orch._preferred_capability(
            _action(expected_outputs=["service.exposed"]),
        ) == "info-gatherer"

    def test_fingerprint_outputs_go_to_framework_vuln(self):
        orch = _orch()
        assert orch._preferred_capability(
            _action(expected_outputs=["fingerprint.detected"]),
        ) == "framework-vuln"

    def test_vuln_scan_defaults_to_framework_vuln_for_cve_coverage(self):
        orch = _orch()
        assert orch._preferred_capability(
            _action(expected_outputs=["vulnerability.detected"], description="扫描漏洞"),
        ) == "framework-vuln"

    def test_web_keywords_route_to_web_attack(self):
        orch = _orch()
        assert orch._preferred_capability(
            _action(expected_outputs=["vulnerability.detected"], description="检测 SQLi 与 XSS"),
        ) == "web-attack"

    def test_verification_keywords_route_to_exploit_verifier(self):
        orch = _orch()
        assert orch._preferred_capability(
            _action(expected_outputs=["vulnerability.detected"], description="受控验证漏洞", risk_level="high"),
        ) == "exploit-verifier"

    def test_medium_risk_vuln_scan_never_picks_high_risk_capability(self):
        """A medium-risk scan whose text says 'exploit' still goes to a medium cap."""
        orch = _orch()
        assert orch._preferred_capability(
            _action(
                expected_outputs=["vulnerability.detected"],
                description="Exploit scanning of exposed services",  # contains 'exploit'
                risk_level="medium",
            ),
        ) == "framework-vuln"

    def test_unknown_outputs_return_none(self):
        orch = _orch()
        assert orch._preferred_capability(_action(expected_outputs=["custom.thing"])) is None


class TestRouterPreferBonus:
    """Router must honour the prefer hint over technique overlap."""

    def test_preferred_capability_wins(self):
        from src.agents.registry import AgentRegistry
        from src.domain.lease_service import LeaseService
        from src.domain.models import AgentCapability, RiskLevel, Scope
        from src.domain.storage import SQLiteStore
        from src.agents.router import AgentRouter
        from src.planner.ptt_schema import ActionContract

        store = SQLiteStore(":memory:")
        registry = AgentRegistry(store)
        # Two caps share the technique; the preferred one must win.
        registry.register(AgentCapability(
            capability_id="cap-recon", name="recon", techniques=["T1595"],
            target_types=["ip"], input_schema="i.json", output_schema="o.json",
            risk_level=RiskLevel.LOW, max_concurrency=4,
        ))
        registry.register(AgentCapability(
            capability_id="cap-scan", name="scan", techniques=["T1595"],
            target_types=["ip"], input_schema="i.json", output_schema="o.json",
            risk_level=RiskLevel.MEDIUM, max_concurrency=1,
        ))
        router = AgentRouter(registry, LeaseService(store))
        action = ActionContract(
            action_id="a1", name="scan", description="scan",
            technique_id="T1595", target_refs=["10.0.0.5"],
            expected_outputs=["vulnerability.detected"], risk_level=RiskLevel.MEDIUM,
        )

        decision = router.route(
            action, target_type="ip", session_id="s1", prefer="cap-scan",
        )
        assert decision.deferred is False
        assert decision.capability_id == "cap-scan"
        assert "preferred_capability" in decision.reasons
        store.close()

    def test_preferred_capability_pulled_in_when_pool_excludes_it(self):
        """T1046 is claimed only by the recon cap; prefer must still reach the scanner."""
        from src.agents.registry import AgentRegistry
        from src.domain.lease_service import LeaseService
        from src.domain.models import AgentCapability, RiskLevel
        from src.domain.storage import SQLiteStore
        from src.agents.router import AgentRouter
        from src.planner.ptt_schema import ActionContract

        store = SQLiteStore(":memory:")
        registry = AgentRegistry(store)
        registry.register(AgentCapability(
            capability_id="info-gatherer", name="recon", techniques=["T1046"],
            target_types=["ip"], input_schema="i.json", output_schema="o.json",
            risk_level=RiskLevel.LOW, max_concurrency=4,
        ))
        # Scanner claims a different technique — excluded from the technique pool
        registry.register(AgentCapability(
            capability_id="framework-vuln", name="scan", techniques=["T1190"],
            target_types=["url"], input_schema="i.json", output_schema="o.json",
            risk_level=RiskLevel.MEDIUM, max_concurrency=1,
        ))
        router = AgentRouter(registry, LeaseService(store))
        action = ActionContract(
            action_id="a2", name="probe", description="漏洞探测",
            technique_id="T1046", target_refs=["10.0.0.5"],
            expected_outputs=["vulnerability.detected"], risk_level=RiskLevel.MEDIUM,
        )

        decision = router.route(
            action, target_type="ip", session_id="s1", prefer="framework-vuln",
        )
        assert decision.deferred is False
        assert decision.capability_id == "framework-vuln"
        store.close()

    def test_preferred_capability_respects_risk_gate(self):
        """A CRITICAL cap must not be pulled in for a LOW-risk action."""
        from src.agents.registry import AgentRegistry
        from src.domain.lease_service import LeaseService
        from src.domain.models import AgentCapability, RiskLevel
        from src.domain.storage import SQLiteStore
        from src.agents.router import AgentRouter
        from src.planner.ptt_schema import ActionContract

        store = SQLiteStore(":memory:")
        registry = AgentRegistry(store)
        registry.register(AgentCapability(
            capability_id="info-gatherer", name="recon", techniques=["T1046"],
            target_types=["ip"], input_schema="i.json", output_schema="o.json",
            risk_level=RiskLevel.LOW, max_concurrency=4,
        ))
        registry.register(AgentCapability(
            capability_id="exploit-verifier", name="exploit", techniques=["T1210"],
            target_types=["ip"], input_schema="i.json", output_schema="o.json",
            risk_level=RiskLevel.CRITICAL, max_concurrency=1,
        ))
        router = AgentRouter(registry, LeaseService(store))
        action = ActionContract(
            action_id="a3", name="scan", description="scan",
            technique_id="T1046", target_refs=["10.0.0.5"],
            expected_outputs=["service.exposed"], risk_level=RiskLevel.LOW,
        )

        decision = router.route(
            action, target_type="ip", session_id="s1", prefer="exploit-verifier",
        )
        assert decision.capability_id != "exploit-verifier"
        store.close()