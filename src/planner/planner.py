"""Planner — orchestrates PTT plan generation and validation.

The Planner is the entry point for turning a natural-language goal into a
validated, executable PTT tree. It:
1. Takes user input + scope + agent registry
2. Calls a Provider (Mock or LLM) to generate a PTTPlan
3. Validates the plan against ATT&CK, scope, risk, and capability rules
4. Returns a live PTTTree ready for hive execution, or a PlanRejection
"""

from __future__ import annotations

from src.agents.registry import AgentRegistry
from src.domain.models import RiskLevel, Scope
from src.domain.storage import SQLiteStore
from src.planner.attack_kb import AttackKB
from src.planner.contract import PTTValidator
from src.planner.errors import NoMatchingScenarioError, PlanRejection, ValidationError
from src.planner.provider import MockProvider, PlanRequest, PlannerProvider
from src.planner.ptt_schema import PTTPlan, PTTTree
from src.policy.guard import PolicyGuard


class Planner:
    """Orchestrates PTT plan generation with validation.

    Usage::

        store = SQLiteStore(":memory:")
        planner = Planner(store)
        tree = await planner.generate(
            goal="发现授权网段的资产和服务",
            scope=scope,
            registry=registry,
        )
        # tree is a validated PTTTree ready for hive execution
    """

    def __init__(
        self,
        store: SQLiteStore,
        *,
        provider: PlannerProvider | None = None,
        attack_kb: AttackKB | None = None,
        max_risk: RiskLevel = RiskLevel.HIGH,
    ) -> None:
        self._store = store
        self._guard = PolicyGuard(store, demo_mode=True)
        self._kb = attack_kb or AttackKB()
        self._provider = provider or MockProvider()
        self._validator = PTTValidator(self._kb, self._guard)
        self._max_risk = max_risk

    # ── public API ─────────────────────────────────────────────────────

    def generate(
        self,
        goal: str,
        scope: Scope,
        registry: AgentRegistry,
        *,
        project_id: str = "default",
        context: dict | None = None,
    ) -> PTTTree:
        """Generate a validated PTT tree from a natural-language goal.

        Args:
            goal: Natural-language penetration testing goal.
            scope: Authorized target scope.
            registry: Agent registry for capability matching.
            project_id: Project identifier.
            context: Optional blackboard context (for re-planning).

        Returns:
            A validated PTTTree ready for hive execution.

        Raises:
            PlanRejection: If the generated plan fails any validation layer.
        """
        # ── collect available techniques from registry ───────────────
        capabilities = registry.list_all()
        available_techniques: list[str] = []
        for cap in capabilities:
            available_techniques.extend(cap.techniques)
        available_techniques = list(set(available_techniques))

        # ── build request ────────────────────────────────────────────
        request = PlanRequest(
            goal=goal,
            scope=scope,
            project_id=project_id,
            available_techniques=available_techniques,
            context=context,
        )

        # ── call provider ────────────────────────────────────────────
        try:
            plan = self._provider.plan(request)
        except NoMatchingScenarioError as e:
            raise PlanRejection([
                ValidationError(
                    code="NO_MATCHING_SCENARIO",
                    message=str(e),
                )
            ]) from e

        # ── validate ─────────────────────────────────────────────────
        result = self._validator.validate(
            plan,
            scope,
            available_techniques=available_techniques,
            max_risk=self._max_risk,
        )
        result.raise_if_failed()

        # ── wrap as live tree ────────────────────────────────────────
        tree = PTTTree.from_plan(plan)

        # Mark all actions as READY (no dependency ordering in Phase 4)
        for action in plan.all_actions():
            tree.node_states[action.action_id] = tree.node_states[action.action_id]

        return tree

    def plan_only(self, goal: str, scope: Scope, registry: AgentRegistry,
                  *, project_id: str = "default") -> PTTPlan:
        """Generate and validate a plan, returning the raw PTTPlan (no tree wrapper).

        Useful for CLI display and serialization.
        """
        tree = self.generate(goal, scope, registry, project_id=project_id)
        return tree.plan

    # ── convenience: reject invalid plans ─────────────────────────────

    def validate_existing(
        self,
        plan: PTTPlan,
        scope: Scope,
        *,
        available_techniques: list[str] | None = None,
    ) -> bool:
        """Validate an externally-provided PTTPlan. Returns True if valid."""
        result = self._validator.validate(
            plan, scope,
            available_techniques=available_techniques,
            max_risk=self._max_risk,
        )
        return result.passed