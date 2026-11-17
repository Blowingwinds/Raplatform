"""Tests for dynamic Task builders."""

import pytest

from src.agents.hive.tasks import (
    _endpoints_from_facts,
    _fingerprints_from_facts,
    _services_from_facts,
    _targets_needing_recon,
    _unverified_vulns,
    make_exploit_tasks,
    make_fingerprint_tasks,
    make_info_tasks,
    make_vuln_tasks,
)
from src.agents.hive.tools import CrewContext
from src.domain.models import BlackboardFact


@pytest.fixture
def ctx():
    return CrewContext(
        project_id="proj-1", scope_id="scope-1",
        session_id="sess-1", task_id="task-1",
    )


def _make_fact(fact_id, fact_type, asset_ref="192.168.1.1", data=None, verified=False):
    d = dict(data) if data else {}
    if fact_type == "vulnerability.detected":
        d.setdefault("verified", verified)
    return BlackboardFact(
        fact_id=fact_id, project_id="proj-1", fact_type=fact_type,
        asset_ref=asset_ref, data=d, confidence=0.9,
        source_agent="test", session_id="sess-1", evidence_ref="ev-1",
    )


def _make_minimal_agent(role: str = "test"):
    """Create a minimal CrewAI Agent for testing — no LLM needed for Task construction."""
    from crewai import Agent
    return Agent(
        role=role,
        goal="Test goal",
        backstory="Test backstory",
        allow_delegation=False,
    )


# ── fact extractors ────────────────────────────────────────────────────

class TestFactExtractors:
    def test_services_from_facts(self):
        facts = [
            _make_fact("f1", "service.exposed", data={"port": 80, "service_name": "http"}),
            _make_fact("f2", "service.exposed", data={"port": 443, "service_name": "https"}),
            _make_fact("f3", "fingerprint.detected", data={"name": "nginx"}),
        ]
        svcs = _services_from_facts(facts)
        assert len(svcs) == 2
        assert svcs[0]["port"] == 80

    def test_fingerprints_from_facts(self):
        facts = [
            _make_fact("f1", "fingerprint.detected", data={"name": "nginx", "extracted": "1.18"}),
            _make_fact("f2", "service.exposed", data={"port": 80}),
        ]
        fps = _fingerprints_from_facts(facts)
        assert len(fps) == 1
        assert fps[0]["name"] == "nginx"

    def test_endpoints_from_facts(self):
        facts = [
            _make_fact("f1", "asset.discovered", asset_ref="http://host/api",
                       data={"url": "http://host/api", "status": 200}),
            _make_fact("f2", "subdomain.discovered", asset_ref="sub.host.com",
                       data={"http_status": 301}),
        ]
        eps = _endpoints_from_facts(facts)
        assert len(eps) == 2

    def test_unverified_vulns(self):
        facts = [
            _make_fact("f1", "vulnerability.detected", data={"verified": False, "category": "sqli"}),
            _make_fact("f2", "vulnerability.detected", data={"verified": True, "category": "xss"}),
        ]
        unverified = _unverified_vulns(facts)
        assert len(unverified) == 1
        assert unverified[0].fact_id == "f1"

    def test_targets_needing_recon_all_new(self):
        facts: list = []
        targets = _targets_needing_recon(facts, ["example.com"])
        assert targets == ["example.com"]

    def test_targets_needing_recon_skip_processed(self):
        facts = [
            _make_fact("f1", "service.exposed", asset_ref="example.com",
                       data={"port": 80, "service_name": "http"}),
        ]
        targets = _targets_needing_recon(facts, ["example.com", "other.com"])
        assert targets == ["other.com"]


# ── task builders ──────────────────────────────────────────────────────

class TestMakeInfoTasks:
    def test_creates_task_per_seed_target(self, ctx):
        info_agent = _make_minimal_agent("info-gatherer")
        facts: list = []
        tasks = make_info_tasks(ctx, facts, info_agent, ["example.com"])
        assert len(tasks) >= 1
        task = tasks[0]
        assert "example.com" in task.description
        assert task.agent is info_agent

    def test_no_tasks_when_all_processed(self, ctx):
        info_agent = _make_minimal_agent("info-gatherer")
        facts = [
            _make_fact("f1", "service.exposed", asset_ref="done.com",
                       data={"port": 80, "service_name": "http"}),
        ]
        tasks = make_info_tasks(ctx, facts, info_agent, ["done.com"])
        assert len(tasks) == 0


class TestMakeFingerprintTasks:
    def test_creates_tasks_for_services(self, ctx):
        agent = _make_minimal_agent("framework")
        facts = [
            _make_fact("f1", "service.exposed", asset_ref="target.com",
                       data={"port": 80, "service_name": "http"}),
            _make_fact("f2", "service.exposed", asset_ref="target.com",
                       data={"port": 443, "service_name": "https"}),
        ]
        tasks = make_fingerprint_tasks(ctx, facts, agent)
        assert len(tasks) >= 1
        assert "target.com" in tasks[0].description

    def test_no_tasks_without_services(self, ctx):
        agent = _make_minimal_agent("framework")
        tasks = make_fingerprint_tasks(ctx, [], agent)
        assert len(tasks) == 0


class TestMakeVulnTasks:
    def test_creates_tasks_from_fingerprints(self, ctx):
        fw = _make_minimal_agent("framework")
        web = _make_minimal_agent("web")
        comp = _make_minimal_agent("component")
        facts = [
            _make_fact("f1", "service.exposed", asset_ref="target.com",
                       data={"port": 80, "service_name": "http"}),
            _make_fact("f2", "fingerprint.detected", asset_ref="target.com",
                       data={"name": "nginx", "extracted": "1.18.0", "host": "target.com"}),
        ]
        tasks = make_vuln_tasks(ctx, facts, fw, web, comp)
        assert len(tasks) >= 1

    def test_no_tasks_without_fingerprints_or_endpoints(self, ctx):
        tasks = make_vuln_tasks(
            ctx, [],
            _make_minimal_agent("f"), _make_minimal_agent("w"), _make_minimal_agent("c"),
        )
        assert len(tasks) == 0


class TestMakeExploitTasks:
    def test_creates_task_per_unverified_vuln(self, ctx):
        agent = _make_minimal_agent("exploit")
        facts = [
            _make_fact("f1", "vulnerability.detected", asset_ref="target.com",
                       data={"verified": False, "category": "sqli", "name": "SQLi in login",
                             "matched_at": "http://target.com/login"}),
        ]
        tasks = make_exploit_tasks(ctx, facts, agent)
        assert len(tasks) == 1
        desc_lower = tasks[0].description.lower()
        assert "sql injection" in desc_lower or "sqli" in desc_lower

    def test_skip_verified_vulns(self, ctx):
        agent = _make_minimal_agent("exploit")
        facts = [
            _make_fact("f1", "vulnerability.detected", data={"verified": True, "category": "sqli"}),
        ]
        tasks = make_exploit_tasks(ctx, facts, agent)
        assert len(tasks) == 0

    def test_non_sqli_uses_python(self, ctx):
        agent = _make_minimal_agent("exploit")
        facts = [
            _make_fact("f1", "vulnerability.detected", asset_ref="target.com",
                       data={"verified": False, "category": "xss", "name": "XSS",
                             "matched_at": "http://target.com/search"}),
        ]
        tasks = make_exploit_tasks(ctx, facts, agent)
        assert len(tasks) == 1
        desc = tasks[0].description
        assert "execute_python" in desc or "Python" in desc