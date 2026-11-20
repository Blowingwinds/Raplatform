"""Regression: a pruned action inside the round-start ready snapshot must be skipped."""

from __future__ import annotations

from src.domain.storage import SQLiteStore


def test_dispatch_skips_action_pruned_mid_round():
    """Earlier failure/skip in the same loop must not crash later dispatches."""
    from src.agents.hive.crews import FakeCrewRunner
    from src.agents.hive.orchestrator import HiveOrchestrator
    from src.planner.ptt_schema import PTTNodeStatus

    store = SQLiteStore(":memory:")
    orch = HiveOrchestrator(
        store, project_id="p-prune", scope_id="s-prune", session_id="sess-prune",
        max_rounds=1, crew_runner=FakeCrewRunner(),
    )
    orch._tool_hints = lambda action, capability_id=None: []
    orch._chain_tactics_in_order = lambda: None

    dispatched: list[str] = []
    original = orch._dispatch_action

    def dispatch_and_prune(action, capability_id):
        dispatched.append(action.action_id)
        # Simulate "an earlier action failed and pruned its dependents"
        for aid, status in list(orch._tree.node_states.items()):
            if aid != action.action_id and status == PTTNodeStatus.READY:
                orch._tree.node_states[aid] = PTTNodeStatus.SKIPPED
        return original(action, capability_id)

    orch._dispatch_action = dispatch_and_prune

    summary = orch.run(seed_targets=["10.0.0.5"])  # must not raise

    assert len(dispatched) == 1, f"expected one dispatch, got {dispatched}"
    assert summary.rounds >= 1
    store.close()