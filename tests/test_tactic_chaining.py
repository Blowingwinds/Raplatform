"""Tests for tacitc-order dependency chaining in the PTT hive loop."""

from __future__ import annotations

from src.domain.storage import SQLiteStore


def _plan_dict() -> dict:
    """Three-tactic plan with no explicit dependencies (typical planner output)."""
    def action(action_id: str) -> dict:
        return {
            "action_id": action_id,
            "name": action_id,
            "description": action_id,
            "target_refs": ["*"],
            "expected_outputs": ["service.exposed"],
            "risk_level": "low",
        }

    return {
        "goal": "test",
        "tactics": [
            {
                "tactic_id": "reconnaissance",
                "name": "Reconnaissance",
                "techniques": [{
                    "technique_id": "T1595",
                    "name": "Active Scanning",
                    "actions": [action("act-recon")],
                }],
            },
            {
                "tactic_id": "discovery",
                "name": "Discovery",
                "techniques": [{
                    "technique_id": "T1046",
                    "name": "Network Service Discovery",
                    "actions": [action("act-discover")],
                }],
            },
            {
                "tactic_id": "initial-access",
                "name": "Initial Access",
                "techniques": [{
                    "technique_id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "actions": [action("act-vuln")],
                }],
            },
        ],
    }


class TestTacticChaining:
    def _orch_with_plan(self, store):
        from src.agents.hive.crews import FakeCrewRunner
        from src.agents.hive.orchestrator import HiveOrchestrator
        from src.domain.models import Scope
        from src.planner.ptt_schema import PTTTree
        from src.planner.provider import PlanRequest, plan_from_dict

        scope = Scope(
            scope_id="scope-chain", project_id="proj-chain", target_type="ip",
            target="10.0.0.5", authorization_ref="auth-1",
        )
        store.save_scope(scope)

        orch = HiveOrchestrator(
            store, project_id="proj-chain", scope_id="scope-chain",
            session_id="sess-chain", max_rounds=1, crew_runner=FakeCrewRunner(),
        )
        orch._tool_hints = lambda action, capability_id=None: []

        request = PlanRequest(
            goal="test", scope=scope, project_id="proj-chain",
            available_techniques=["T1595", "T1046", "T1190"],
        )
        plan = plan_from_dict(_plan_dict(), request, generated_by="mock")
        orch._tree = PTTTree.from_plan(plan)
        return orch

    def test_chaining_creates_tactic_order_dependencies(self):
        store = SQLiteStore(":memory:")
        orch = self._orch_with_plan(store)
        orch._chain_tactics_in_order()

        actions = {a.action_id: a for a in orch._tree.plan.all_actions()}
        assert actions["act-recon"].depends_on == []
        assert actions["act-discover"].depends_on == ["act-recon"]
        # Dependencies accumulate: initial-access waits for all prior tactics
        assert actions["act-vuln"].depends_on == ["act-recon", "act-discover"]
        store.close()

    def test_only_first_tactic_is_ready_initially(self):
        store = SQLiteStore(":memory:")
        orch = self._orch_with_plan(store)
        orch._chain_tactics_in_order()

        ready = {a.action_id for a in orch._tree.ready_actions()}
        assert ready == {"act-recon"}
        store.close()

    def test_explicit_dependencies_are_preserved(self):
        store = SQLiteStore(":memory:")
        orch = self._orch_with_plan(store)
        # Simulate a planner that already declared a dependency
        for tactic in orch._tree.plan.tactics:
            for tech in tactic.techniques:
                for act in tech.actions:
                    if act.action_id == "act-vuln":
                        act.depends_on = ["act-recon"]
        orch._chain_tactics_in_order()

        actions = {a.action_id: a for a in orch._tree.plan.all_actions()}
        assert actions["act-vuln"].depends_on == ["act-recon"]  # untouched
        store.close()