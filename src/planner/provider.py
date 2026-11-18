"""Planner Provider interface and Mock implementation.

The Provider abstraction separates PTT plan generation from the specific
LLM backend. Phase 4 ships with MockProvider; real LLM adapter(s) come in Phase 5.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from src.domain.models import Scope
from src.planner.errors import NoMatchingScenarioError
from src.planner.ptt_schema import (
    ActionContract,
    PTTPlan,
    PTTTree,
    TacticNode,
    TechniqueNode,
)

# Path to mock scenarios
_SCENARIOS_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "mock_scenarios.json"


# ── plan request ─────────────────────────────────────────────────────────

@dataclass
class PlanRequest:
    """Input to a Planner Provider — everything it needs to generate a plan."""

    goal: str
    scope: Scope
    project_id: str
    available_techniques: list[str]
    context: dict[str, Any] | None = None  # optional blackboard context


# ── provider protocol ────────────────────────────────────────────────────

class PlannerProvider(Protocol):
    """Protocol for PTT plan generation backends.

    Real LLM implementations (OpenAI, Anthropic) will implement this in Phase 5.
    """

    def plan(self, request: PlanRequest) -> PTTPlan:
        """Generate a PTT plan from a natural-language goal."""
        ...


# ── mock provider ────────────────────────────────────────────────────────

class MockProvider:
    """Deterministic mock planner — matches NL goal to preset scenarios via fuzzy keywords.

    Loads scenarios from ``data/mock_scenarios.json`` and returns the best
    match. No LLM required — stable for offline testing and demos.

    Usage::

        provider = MockProvider()
        plan = provider.plan(PlanRequest(
            goal="发现授权网段的资产和服务",
            scope=scope,
            project_id="proj-1",
            available_techniques=["T1046", "T1595", ...],
        ))
    """

    def __init__(self, scenarios_path: str | Path | None = None) -> None:
        path = Path(scenarios_path) if scenarios_path else _SCENARIOS_PATH
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        self._scenarios: list[dict[str, Any]] = raw.get("scenarios", [])

    def plan(self, request: PlanRequest) -> PTTPlan:
        """Find the best-matching scenario and return a PTTPlan."""
        scenario = self._match(request.goal)
        return self._build_plan(scenario, request)

    # ── internal ───────────────────────────────────────────────────────

    def _match(self, goal: str) -> dict[str, Any]:
        """Fuzzy keyword matching — find the scenario with most keyword hits."""
        goal_lower = goal.lower()
        best: dict[str, Any] | None = None
        best_score = 0
        tried: list[str] = []

        for scenario in self._scenarios:
            keywords: list[str] = scenario.get("keywords", [])
            # Score: count of keywords found in goal, weighted by keyword length
            score = sum(
                len(kw) for kw in keywords
                if kw.lower() in goal_lower
            )
            tried.extend(kw for kw in keywords if kw.lower() in goal_lower)
            if score > best_score:
                best_score = score
                best = scenario

        if best is None:
            raise NoMatchingScenarioError(goal, tried_keywords=list(set(tried)))

        return best

    def _build_plan(self, scenario: dict[str, Any], request: PlanRequest) -> PTTPlan:
        """Convert a scenario dict into a validated PTTPlan."""
        import uuid

        plan_data = scenario["plan"]
        tactics: list[TacticNode] = []

        for t_data in plan_data.get("tactics", []):
            techniques: list[TechniqueNode] = []
            for tech_data in t_data.get("techniques", []):
                actions: list[ActionContract] = []
                for act_data in tech_data.get("actions", []):
                    # Resolve '*' target_refs to scope target
                    resolved_targets = self._resolve_targets(
                        act_data.get("target_refs", ["*"]), request.scope
                    )
                    actions.append(ActionContract(
                        action_id=act_data["action_id"],
                        name=act_data["name"],
                        description=act_data.get("description", ""),
                        technique_id=act_data["technique_id"],
                        target_refs=resolved_targets,
                        expected_outputs=act_data.get("expected_outputs", []),
                        risk_level=act_data.get("risk_level", "low"),
                        side_effects=act_data.get("side_effects", []),
                        stop_conditions=act_data.get("stop_conditions", []),
                    ))
                if actions:
                    techniques.append(TechniqueNode(
                        technique_id=tech_data["technique_id"],
                        name=tech_data.get("name", tech_data["technique_id"]),
                        actions=actions,
                    ))
            if techniques:
                tactics.append(TacticNode(
                    tactic_id=t_data["tactic_id"],
                    name=t_data.get("name", t_data["tactic_id"]),
                    techniques=techniques,
                ))

        return PTTPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:12]}",
            goal=request.goal,
            normalized_goal=plan_data.get("goal", request.goal),
            project_id=request.project_id,
            scope_id=request.scope.scope_id,
            tactics=tactics,
            generated_by="mock",
        )

    @staticmethod
    def _resolve_targets(target_refs: list[str], scope: Scope) -> list[str]:
        """Replace '*' wildcard with actual scope target."""
        resolved: list[str] = []
        for ref in target_refs:
            if ref == "*":
                resolved.append(scope.target)
            else:
                resolved.append(ref)
        return resolved


# ── helper: match to tree ────────────────────────────────────────────────

def plan_to_tree(plan: PTTPlan) -> PTTTree:
    """Convert a freshly generated PTTPlan into a live PTTTree.

    All actions start in PLANNED state; the hive will mark them READY
    as dependencies are satisfied.
    """
    return PTTTree.from_plan(plan)