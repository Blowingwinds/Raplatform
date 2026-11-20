"""Tests for re-orchestrator deduplication and URL canonicalisation."""

from __future__ import annotations

from src.planner.reorchestrator import _host_of
from src.agents.shared.nuclei_runner import _canonical_url, _normalize_vuln


class TestHostNormalisation:
    def test_default_port_stripped(self):
        assert _host_of("http://10.0.0.5:80") == "10.0.0.5"
        assert _host_of("https://10.0.0.5:443") == "10.0.0.5"

    def test_non_default_port_kept(self):
        assert _host_of("http://10.0.0.5:8080") == "10.0.0.5:8080"
        assert _host_of("10.0.0.5:22") == "10.0.0.5:22"

    def test_bare_host(self):
        assert _host_of("10.0.0.5") == "10.0.0.5"


class TestVulnUrlCanonicalisation:
    def test_default_port_collapses(self):
        assert _canonical_url("http://10.0.0.5:80/") == "http://10.0.0.5/"
        assert _canonical_url("http://10.0.0.5") == "http://10.0.0.5"

    def test_non_default_port_preserved(self):
        assert _canonical_url("http://10.0.0.5:8080/x") == "http://10.0.0.5:8080/x"

    def test_same_finding_gets_same_id(self):
        entry_a = {"template-id": "CVE-2015-1635", "matched-at": "http://10.0.0.5"}
        entry_b = {"template-id": "CVE-2015-1635", "matched-at": "http://10.0.0.5:80"}
        assert _normalize_vuln(entry_a)["vulnerability_id"] == _normalize_vuln(entry_b)["vulnerability_id"]

    def test_different_ports_stay_distinct(self):
        entry_a = {"template-id": "T1", "matched-at": "http://10.0.0.5:8080"}
        entry_b = {"template-id": "T1", "matched-at": "http://10.0.0.5:9200"}
        assert _normalize_vuln(entry_a)["vulnerability_id"] != _normalize_vuln(entry_b)["vulnerability_id"]


class TestReorchestratorDedup:
    def _tree(self):
        from src.planner.ptt_schema import PTTPlan, PTTTree, TacticNode, TechniqueNode
        from src.planner.ptt_schema import ActionContract

        plan = PTTPlan(
            plan_id="p1", goal="g", normalized_goal="g",
            project_id="proj", scope_id="scope",
            tactics=[TacticNode(
                tactic_id="reconnaissance", name="Recon",
                techniques=[TechniqueNode(
                    technique_id="T1595", name="AS",
                    actions=[ActionContract(
                        action_id="act-a", name="a", description="a",
                        technique_id="T1595", target_refs=["10.0.0.5"],
                        expected_outputs=["service.exposed"], risk_level="low",
                    )],
                )],
            )],
        )
        return PTTTree.from_plan(plan)

    def test_fingerprint_node_deduplicated_per_host(self):
        from src.planner.reorchestrator import ReOrchestrator

        tree = self._tree()
        reorch = ReOrchestrator.__new__(ReOrchestrator)

        first = reorch._append_scan_action(tree, "10.0.0.5", "proj")
        second = reorch._append_scan_action(tree, "10.0.0.5", "proj")
        third = reorch._append_scan_action(tree, "http://10.0.0.5:80", "proj")

        assert len(first) == 1
        assert second == []   # same host → skipped
        assert third == []    # same host via URL form → skipped
        assert len(tree.dynamic_nodes) == 1

    def test_vuln_node_deduplicated_per_host(self):
        from src.planner.reorchestrator import ReOrchestrator

        tree = self._tree()
        reorch = ReOrchestrator.__new__(ReOrchestrator)

        assert len(reorch._append_vuln_action(tree, "10.0.0.5", "proj")) == 1
        assert reorch._append_vuln_action(tree, "10.0.0.5", "proj") == []

    def test_exploit_nodes_distinct_per_port(self):
        from src.planner.reorchestrator import ReOrchestrator

        tree = self._tree()
        reorch = ReOrchestrator.__new__(ReOrchestrator)

        assert len(reorch._append_exploit_action(tree, "10.0.0.5:22", "proj")) == 1
        assert len(reorch._append_exploit_action(tree, "10.0.0.5:8009", "proj")) == 1
        assert reorch._append_exploit_action(tree, "10.0.0.5:22", "proj") == []