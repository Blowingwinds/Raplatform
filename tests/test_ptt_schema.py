"""Tests for PTT schema models — validation, state transitions, flattening."""

import pytest
from pydantic import ValidationError as PydanticValidationError

from src.domain.models import RiskLevel
from src.planner.ptt_schema import (
    ActionContract,
    ActionNode,
    PTTNodeStatus,
    PTTPlan,
    PTTTree,
    TacticNode,
    TechniqueNode,
)


# ── helpers ──────────────────────────────────────────────────────────────

_SENTINEL = object()

def _make_action(
    action_id: str = "act-1",
    technique_id: str = "T1046",
    expected_outputs: object = _SENTINEL,
    risk_level: str = "low",
) -> ActionContract:
    return ActionContract(
        action_id=action_id,
        name="Test Action",
        description="A test action",
        technique_id=technique_id,
        target_refs=["192.168.1.0/24"],
        expected_outputs=["service.exposed"] if expected_outputs is _SENTINEL else expected_outputs,
        risk_level=RiskLevel(risk_level),
    )


def _make_plan(
    goal: str = "发现资产",
    tactics: list[TacticNode] | None = None,
) -> PTTPlan:
    if tactics is None:
        tactics = [
            TacticNode(
                tactic_id="reconnaissance",
                name="Reconnaissance",
                techniques=[
                    TechniqueNode(
                        technique_id="T1595",
                        name="Active Scanning",
                        actions=[_make_action("act-scan", technique_id="T1595")],
                    )
                ],
            )
        ]
    return PTTPlan(
        plan_id="plan-test",
        goal=goal,
        normalized_goal=goal,
        project_id="proj-1",
        scope_id="scope-1",
        tactics=tactics,
    )


# ── ActionContract ───────────────────────────────────────────────────────

class TestActionContract:
    def test_valid_action(self):
        act = _make_action()
        assert act.action_id == "act-1"
        assert act.risk_level == RiskLevel.LOW

    def test_empty_expected_outputs_rejected(self):
        with pytest.raises(PydanticValidationError):
            _make_action(expected_outputs=[])

    def test_missing_expected_outputs_rejected(self):
        with pytest.raises(PydanticValidationError, match="expected_outputs"):
            ActionContract(
                action_id="act-x",
                name="Bad",
                description="No outputs",
                technique_id="T1046",
                target_refs=["x"],
                risk_level=RiskLevel.LOW,
            )

    def test_empty_target_refs_rejected(self):
        with pytest.raises(PydanticValidationError):
            ActionContract(
                action_id="act-x",
                name="Bad",
                description="No targets",
                technique_id="T1046",
                target_refs=[],
                expected_outputs=["service.exposed"],
                risk_level=RiskLevel.LOW,
            )

    def test_side_effects_and_stop_conditions(self):
        act = ActionContract(
            action_id="act-verify",
            name="Verify",
            description="Verify vuln",
            technique_id="T1059",
            target_refs=["*"],
            expected_outputs=["vulnerability.detected"],
            risk_level=RiskLevel.HIGH,
            side_effects=["may trigger WAF"],
            stop_conditions=["timeout 120s"],
        )
        assert act.side_effects == ["may trigger WAF"]
        assert act.stop_conditions == ["timeout 120s"]


# ── PTTPlan ──────────────────────────────────────────────────────────────

class TestPTTPlan:
    def test_valid_plan(self):
        plan = _make_plan()
        assert plan.plan_id == "plan-test"
        assert len(plan.tactics) == 1

    def test_empty_tactics_rejected(self):
        with pytest.raises(PydanticValidationError):
            PTTPlan(
                plan_id="p", goal="g", normalized_goal="g",
                project_id="p", scope_id="s",
                tactics=[],
            )

    def test_technique_without_actions_rejected(self):
        with pytest.raises(PydanticValidationError):
            PTTPlan(
                plan_id="p", goal="g", normalized_goal="g",
                project_id="p", scope_id="s",
                tactics=[
                    TacticNode(
                        tactic_id="reconnaissance",
                        name="R",
                        techniques=[
                            TechniqueNode(
                                technique_id="T1046",
                                name="N",
                                actions=[],
                            )
                        ],
                    )
                ],
            )

    def test_all_actions_flattens(self):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery",
                name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="NSD",
                        actions=[
                            _make_action("a1", "T1046"),
                            _make_action("a2", "T1046"),
                        ],
                    ),
                    TechniqueNode(
                        technique_id="T1018", name="RSD",
                        actions=[_make_action("a3", "T1018")],
                    ),
                ],
            ),
        ])
        actions = plan.all_actions()
        assert len(actions) == 3
        assert {a.action_id for a in actions} == {"a1", "a2", "a3"}

    def test_all_techniques_flattens(self):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(technique_id="T1046", name="A", actions=[_make_action("a1", "T1046")]),
                    TechniqueNode(technique_id="T1018", name="B", actions=[_make_action("a2", "T1018")]),
                ],
            ),
        ])
        techs = plan.all_techniques()
        assert len(techs) == 2

    def test_technique_ids(self):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(technique_id="T1046", name="A", actions=[_make_action("a1", "T1046")]),
                    TechniqueNode(technique_id="T1046", name="B", actions=[_make_action("a2", "T1046")]),
                    TechniqueNode(technique_id="T1018", name="C", actions=[_make_action("a3", "T1018")]),
                ],
            ),
        ])
        assert plan.technique_ids() == {"T1046", "T1018"}

    def test_tactic_ids(self):
        plan = _make_plan(tactics=[
            TacticNode(tactic_id="reconnaissance", name="R",
                       techniques=[TechniqueNode(technique_id="T1595", name="A", actions=[_make_action("a1", "T1595")])]),
            TacticNode(tactic_id="discovery", name="D",
                       techniques=[TechniqueNode(technique_id="T1046", name="B", actions=[_make_action("a2", "T1046")])]),
        ])
        assert plan.tactic_ids() == {"reconnaissance", "discovery"}


# ── ActionNode (runtime) ─────────────────────────────────────────────────

class TestActionNode:
    def test_initial_state_is_planned(self):
        node = ActionNode(action=_make_action())
        assert node.status == PTTNodeStatus.PLANNED

    def test_mark_ready(self):
        node = ActionNode(action=_make_action())
        node.mark_ready()
        assert node.status == PTTNodeStatus.READY

    def test_mark_running(self):
        node = ActionNode(action=_make_action())
        node.mark_ready()
        node.mark_running()
        assert node.status == PTTNodeStatus.RUNNING

    def test_mark_succeeded(self):
        node = ActionNode(action=_make_action())
        node.mark_ready()
        node.mark_running()
        node.mark_succeeded(evidence_refs=["ev-1"], summary="Done")
        assert node.status == PTTNodeStatus.SUCCEEDED
        assert node.evidence_refs == ["ev-1"]
        assert node.result_summary == "Done"

    def test_mark_failed(self):
        node = ActionNode(action=_make_action())
        node.mark_failed("timeout")
        assert node.status == PTTNodeStatus.FAILED
        assert node.result_summary == "timeout"

    def test_mark_blocked(self):
        node = ActionNode(action=_make_action())
        node.mark_blocked("scope denied")
        assert node.status == PTTNodeStatus.BLOCKED

    def test_mark_skipped(self):
        node = ActionNode(action=_make_action())
        node.mark_skipped("pruned")
        assert node.status == PTTNodeStatus.SKIPPED

    def test_cannot_mark_ready_twice(self):
        node = ActionNode(action=_make_action())
        node.mark_ready()
        with pytest.raises(ValueError, match="READY"):
            node.mark_ready()

    def test_cannot_mark_running_from_succeeded(self):
        node = ActionNode(action=_make_action())
        node.mark_succeeded()
        with pytest.raises(ValueError, match="RUNNING"):
            node.mark_running()


# ── PTTTree (live tree) ──────────────────────────────────────────────────

class TestPTTTree:
    def test_from_plan_all_planned(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        assert len(tree.node_states) == 1
        assert tree.node_states["act-scan"] == PTTNodeStatus.PLANNED

    def test_ready_actions_empty_initially(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        assert tree.ready_actions() == []

    def test_planned_actions(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        planned = tree.planned_actions()
        assert len(planned) == 1
        assert planned[0].action_id == "act-scan"

    def test_set_status(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        tree.set_status("act-scan", PTTNodeStatus.READY)
        assert tree.node_states["act-scan"] == PTTNodeStatus.READY
        assert len(tree.ready_actions()) == 1

    def test_set_unknown_action_raises(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        with pytest.raises(ValueError, match="Unknown action_id"):
            tree.set_status("nonexistent", PTTNodeStatus.READY)

    def test_add_dynamic_node(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        new_node = ActionNode(action=_make_action("act-dyn-1"))
        tree.add_dynamic_node(new_node)
        assert "act-dyn-1" in tree.node_states
        assert "act-dyn-1" in tree.dynamic_nodes

    def test_add_duplicate_dynamic_node_raises(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        new_node = ActionNode(action=_make_action("act-scan"))  # same ID as plan
        with pytest.raises(ValueError, match="already exists"):
            tree.add_dynamic_node(new_node)

    def test_is_complete_when_all_terminal(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        tree.set_status("act-scan", PTTNodeStatus.SUCCEEDED)
        assert tree.is_complete()

    def test_is_not_complete_when_planned_remain(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        assert not tree.is_complete()

    def test_progress_stats(self):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="A",
                        actions=[
                            _make_action("a1", "T1046"),
                            _make_action("a2", "T1046"),
                        ],
                    ),
                ],
            ),
        ])
        tree = PTTTree.from_plan(plan)
        tree.set_status("a1", PTTNodeStatus.SUCCEEDED)
        tree.set_status("a2", PTTNodeStatus.BLOCKED)
        stats = tree.progress()
        assert stats["total"] == 2
        assert stats["planned"] == 0
        assert stats["succeeded"] == 1
        assert stats["blocked"] == 1

    def test_succeeded_actions(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        tree.set_status("act-scan", PTTNodeStatus.SUCCEEDED)
        assert len(tree.succeeded_actions()) == 1

    def test_blocked_actions(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        tree.set_status("act-scan", PTTNodeStatus.BLOCKED)
        assert len(tree.blocked_actions()) == 1

    def test_summary(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        summary = tree.summary()
        assert summary["goal"] == "发现资产"
        assert summary["tactics"] == 1
        assert summary["techniques"] == 1
        assert summary["actions"] == 1
        assert summary["progress"]["total"] == 1

    # ── dynamic nodes + all_actions queries ─────────────────────────────

    def test_dynamic_node_appears_in_ready_actions(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        dyn = ActionNode(action=_make_action("act-dyn-1"))
        tree.add_dynamic_node(dyn)
        tree.set_status("act-dyn-1", PTTNodeStatus.READY)
        ready = tree.ready_actions()
        assert len(ready) == 1
        assert ready[0].action_id == "act-dyn-1"

    def test_dynamic_node_appears_in_planned_actions(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        dyn = ActionNode(action=_make_action("act-dyn-1"))
        tree.add_dynamic_node(dyn)
        planned = tree.planned_actions()
        assert len(planned) == 2  # static + dynamic
        assert {a.action_id for a in planned} == {"act-scan", "act-dyn-1"}

    # ── recompute_ready ─────────────────────────────────────────────────

    def test_recompute_ready_no_deps(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        promoted = tree.recompute_ready()
        assert promoted == 1
        assert tree.node_states["act-scan"] == PTTNodeStatus.READY
        assert len(tree.ready_actions()) == 1

    def test_recompute_ready_with_satisfied_deps(self):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="A",
                        actions=[
                            _make_action("a1", "T1046"),
                            ActionContract(
                                action_id="a2", name="Second",
                                description="Depends on a1",
                                technique_id="T1046",
                                target_refs=["*"],
                                expected_outputs=["fingerprint.detected"],
                                risk_level=RiskLevel.LOW,
                                depends_on=["a1"],
                            ),
                        ],
                    ),
                ],
            ),
        ])
        tree = PTTTree.from_plan(plan)
        # First recompute: a1 READY (no deps), a2 stays PLANNED (dep not satisfied)
        promoted = tree.recompute_ready()
        assert promoted == 1
        assert tree.node_states["a1"] == PTTNodeStatus.READY
        assert tree.node_states["a2"] == PTTNodeStatus.PLANNED
        # Mark a1 SUCCEEDED, then recompute: a2 → READY
        tree.set_status("a1", PTTNodeStatus.SUCCEEDED)
        promoted2 = tree.recompute_ready()
        assert promoted2 == 1
        assert tree.node_states["a2"] == PTTNodeStatus.READY

    def test_recompute_ready_dep_skipped_is_satisfied(self):
        """A SKIPPED dependency counts as satisfied."""
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="A",
                        actions=[
                            _make_action("a1", "T1046"),
                            ActionContract(
                                action_id="a2", name="Second",
                                description="Depends on a1",
                                technique_id="T1046",
                                target_refs=["*"],
                                expected_outputs=["fingerprint.detected"],
                                risk_level=RiskLevel.LOW,
                                depends_on=["a1"],
                            ),
                        ],
                    ),
                ],
            ),
        ])
        tree = PTTTree.from_plan(plan)
        tree.recompute_ready()  # a1 → READY
        tree.set_status("a1", PTTNodeStatus.SKIPPED)  # skipped also counts
        promoted = tree.recompute_ready()
        assert promoted == 1
        assert tree.node_states["a2"] == PTTNodeStatus.READY

    def test_recompute_ready_idempotent(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        assert tree.recompute_ready() == 1
        # Second call: already READY, no-op
        assert tree.recompute_ready() == 0

    # ── prune_dependents ────────────────────────────────────────────────

    def test_prune_dependents_marks_children_skipped(self):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="A",
                        actions=[
                            _make_action("parent", "T1046"),
                            ActionContract(
                                action_id="child", name="Child",
                                description="Depends on parent",
                                technique_id="T1190",
                                target_refs=["*"],
                                expected_outputs=["vulnerability.detected"],
                                risk_level=RiskLevel.MEDIUM,
                                depends_on=["parent"],
                            ),
                        ],
                    ),
                ],
            ),
        ])
        tree = PTTTree.from_plan(plan)
        tree.recompute_ready()  # parent → READY
        pruned = tree.prune_dependents("parent")
        assert pruned == 1
        assert tree.node_states["child"] == PTTNodeStatus.SKIPPED

    def test_prune_dependents_recursive(self):
        """Prune should cascade through dependency chain."""
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="A",
                        actions=[
                            _make_action("a1", "T1046"),
                            ActionContract(
                                action_id="a2", name="A2",
                                description="Dep on a1", technique_id="T1190",
                                target_refs=["*"],
                                expected_outputs=["vulnerability.detected"],
                                risk_level=RiskLevel.MEDIUM,
                                depends_on=["a1"],
                            ),
                            ActionContract(
                                action_id="a3", name="A3",
                                description="Dep on a2", technique_id="T1210",
                                target_refs=["*"],
                                expected_outputs=["credential.validated"],
                                risk_level=RiskLevel.HIGH,
                                depends_on=["a2"],
                            ),
                        ],
                    ),
                ],
            ),
        ])
        tree = PTTTree.from_plan(plan)
        tree.recompute_ready()
        # Prune a1 → a2 skipped → a3 skipped
        pruned = tree.prune_dependents("a1")
        assert pruned == 2
        assert tree.node_states["a2"] == PTTNodeStatus.SKIPPED
        assert tree.node_states["a3"] == PTTNodeStatus.SKIPPED

    def test_prune_does_not_touch_already_terminal(self):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="A",
                        actions=[
                            _make_action("parent", "T1046"),
                            ActionContract(
                                action_id="child", name="Child",
                                description="Dep on parent", technique_id="T1190",
                                target_refs=["*"],
                                expected_outputs=["vulnerability.detected"],
                                risk_level=RiskLevel.MEDIUM,
                                depends_on=["parent"],
                            ),
                        ],
                    ),
                ],
            ),
        ])
        tree = PTTTree.from_plan(plan)
        tree.set_status("child", PTTNodeStatus.SUCCEEDED)  # already terminal
        pruned = tree.prune_dependents("parent")
        assert pruned == 0  # not re-pruned

    # ── get_node ────────────────────────────────────────────────────────

    def test_get_node_static(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        node = tree.get_node("act-scan")
        assert node.action.action_id == "act-scan"
        assert node.status == PTTNodeStatus.PLANNED
        assert node.parent_action_id is None

    def test_get_node_dynamic(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        dyn = ActionNode(
            action=_make_action("act-dyn-1"),
            parent_action_id="act-scan",
            status=PTTNodeStatus.READY,
        )
        tree.add_dynamic_node(dyn)
        node = tree.get_node("act-dyn-1")
        assert node.action.action_id == "act-dyn-1"
        assert node.status == PTTNodeStatus.READY
        assert node.parent_action_id == "act-scan"

    def test_get_node_unknown_raises(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        with pytest.raises(ValueError, match="Unknown action_id"):
            tree.get_node("nonexistent")

    # ── tree-level mark helpers ─────────────────────────────────────────

    def test_mark_running_tree_level(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        tree.recompute_ready()
        tree.mark_running("act-scan")
        assert tree.node_states["act-scan"] == PTTNodeStatus.RUNNING

    def test_mark_succeeded_tree_level(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        tree.recompute_ready()
        tree.mark_succeeded("act-scan", evidence_refs=["ev-1"], summary="ok")
        assert tree.node_states["act-scan"] == PTTNodeStatus.SUCCEEDED

    def test_mark_failed_prunes_dependents(self):
        plan = _make_plan(tactics=[
            TacticNode(
                tactic_id="discovery", name="D",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046", name="A",
                        actions=[
                            _make_action("parent", "T1046"),
                            ActionContract(
                                action_id="child", name="Child",
                                description="Dep on parent", technique_id="T1190",
                                target_refs=["*"],
                                expected_outputs=["vulnerability.detected"],
                                risk_level=RiskLevel.MEDIUM,
                                depends_on=["parent"],
                            ),
                        ],
                    ),
                ],
            ),
        ])
        tree = PTTTree.from_plan(plan)
        tree.mark_failed("parent", reason="timeout")
        assert tree.node_states["parent"] == PTTNodeStatus.FAILED
        assert tree.node_states["child"] == PTTNodeStatus.SKIPPED

    def test_mark_blocked_tree_level(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        tree.mark_blocked("act-scan", reason="waiting_approval")
        assert tree.node_states["act-scan"] == PTTNodeStatus.BLOCKED

    # ── _all_action_ids ─────────────────────────────────────────────────

    def test_all_action_ids_includes_dynamic(self):
        plan = _make_plan()
        tree = PTTTree.from_plan(plan)
        tree.add_dynamic_node(ActionNode(action=_make_action("act-dyn-1")))
        ids = tree._all_action_ids()
        assert ids == {"act-scan", "act-dyn-1"}

    # ── depends_on field ────────────────────────────────────────────────

    def test_action_contract_with_depends_on(self):
        act = _make_action("act-with-deps")
        act2 = ActionContract(
            action_id="act-child",
            name="Child",
            description="Has deps",
            technique_id="T1190",
            target_refs=["*"],
            expected_outputs=["vulnerability.detected"],
            risk_level=RiskLevel.MEDIUM,
            depends_on=["act-with-deps"],
        )
        assert act2.depends_on == ["act-with-deps"]
        # No deps by default
        assert act.depends_on == []