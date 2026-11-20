"""AgentRouter — select the best agent capability for an ActionContract.

The router sits between the PTT planner and the hive dispatch loop. Given an
action and a target type, it picks the registered capability best suited to
execute it, while respecting risk gates and lease-based concurrency limits.

Routing algorithm (see ``AgentRouter.route``):
  1. Build a candidate pool via ``registry.find_best`` using the action's
     technique id and the requested target type — caps that match *both*
     score higher than caps that match only one.
  2. Risk gate: drop any cap whose ``risk_level`` exceeds the action's
     ``risk_level`` (LOW < MEDIUM < HIGH < CRITICAL).
  3. Load gate: for each candidate, count active leases via
     ``lease.active_count_for_capability``.  If ``active >= max_concurrency``
     the candidate is marked deferred.
  4. Highest overlap score wins; tie-break: lower risk_level, then lower load.
  5. If every candidate is at max concurrency (or the pool is empty), the
     decision is returned with ``deferred=True`` so the hive can suspend-wait.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.agents.registry import AgentRegistry
from src.domain.lease_service import LeaseService
from src.domain.models import AgentCapability, RiskLevel
from src.planner.ptt_schema import ActionContract

# Risk ordering: LOW < MEDIUM < HIGH < CRITICAL.
# Mirrors the risk_order dict pattern used in registry.py.
_RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


@dataclass
class RouteDecision:
    """The outcome of a routing call.

    Attributes:
        capability_id: Id of the selected capability, or "" when no candidate
            matched (deferred).
        score: Overlap score that decided the winner (technique + target).
        reasons: Human-readable trace of why this cap was chosen / deferred.
        deferred: True when blocked by lease concurrency or no candidates.
    """

    capability_id: str
    score: float
    reasons: list[str] = field(default_factory=list)
    deferred: bool = False  # True when blocked by lease concurrency


class AgentRouter:
    """Select the best agent capability for an ActionContract."""

    def __init__(self, registry: AgentRegistry, lease: LeaseService) -> None:
        self._registry = registry
        self._lease = lease

    def route(
        self,
        action: ActionContract,
        *,
        target_type: str,
        session_id: str,
        prefer: str | None = None,
    ) -> RouteDecision:
        """Select the best agent for an action.

        Algorithm:
        1. registry.find_by_techniques([action.technique_id], risk_max=action.risk_level)
           ∩ registry.find_by_target_type(target_type) — scored via find_best so
           caps matching both technique and target rank above caps matching one.
        2. Risk gate: filter out caps with risk_level > action.risk_level.
        3. Load score: for each candidate, count active leases via
           lease.active_count_for_capability(cap_id). If active >= max_concurrency
           the candidate is deferred.
        4. Technique/target overlap score (from find_best).
        5. *prefer* (optional capability id) gets a dominant bonus — ATT&CK
           techniques overlap across capabilities (T1595 is claimed by four),
           so the caller's output-type hint disambiguates.
        6. Highest score wins; tie-break: lower risk_level, then lower load.
        """
        risk_max = action.risk_level

        # Step 1 — candidate pool with overlap scoring.
        # find_best does OR matching (technique ∪ target) and sorts by overlap
        # count desc. Caps matching both score 2; caps matching one score 1.
        scored = self._registry.find_best(
            techniques=[action.technique_id],
            target_types=[target_type],
            risk_max=risk_max,
        )

        # Step 2 — risk gate (defensive; find_best already applied risk_max).
        candidates: list[AgentCapability] = [
            c for c in scored
            if _RISK_ORDER.get(c.risk_level, 99) <= _RISK_ORDER.get(risk_max, 99)
        ]

        # The preferred capability may be absent from the technique/target pool
        # (planners often express "vuln probing" with T1046, only claimed by the
        # recon agent). Pull it in explicitly so the hint can win — risk gate
        # still applies.
        if prefer:
            preferred_cap = self._registry.get(prefer)
            if (
                preferred_cap is not None
                and _RISK_ORDER.get(preferred_cap.risk_level, 99) <= _RISK_ORDER.get(risk_max, 99)
                and all(c.capability_id != prefer for c in candidates)
            ):
                candidates.append(preferred_cap)

        if not candidates:
            return RouteDecision(
                capability_id="",
                score=0.0,
                reasons=["no matching capabilities"],
                deferred=True,
            )

        # Steps 3 + 4 + 5 — load, score, tie-break.
        tech_id = action.technique_id
        ranked: list[tuple[AgentCapability, float, int, bool, list[str]]] = []
        all_deferred = True

        for cap in candidates:
            tech_overlap = 1 if tech_id in cap.techniques else 0
            target_overlap = 1 if target_type in cap.target_types else 0
            prefer_hit = prefer is not None and cap.capability_id == prefer
            score = float(tech_overlap + target_overlap) + (100.0 if prefer_hit else 0.0)
            load = self._lease.active_count_for_capability(cap.capability_id)
            at_max = load >= cap.max_concurrency
            if not at_max:
                all_deferred = False

            reasons = [
                f"technique_overlap={tech_overlap}",
                f"target_overlap={target_overlap}",
                f"load={load}/{cap.max_concurrency}",
                f"risk={cap.risk_level.value}",
            ]
            if prefer_hit:
                reasons.append("preferred_capability")
            if at_max:
                reasons.append("at_max_concurrency")
            ranked.append((cap, score, load, at_max, reasons))

        # Sort: highest score first, then lower risk, then lower load.
        ranked.sort(
            key=lambda r: (
                -r[1],
                _RISK_ORDER.get(r[0].risk_level, 99),
                r[2],
            )
        )

        if all_deferred:
            cap, score, _load, _at_max, reasons = ranked[0]
            return RouteDecision(
                capability_id=cap.capability_id,
                score=score,
                reasons=reasons + ["all candidates deferred (max concurrency)"],
                deferred=True,
            )

        # Pick the best available (non-deferred) candidate.
        for cap, score, _load, at_max, reasons in ranked:
            if not at_max:
                return RouteDecision(
                    capability_id=cap.capability_id,
                    score=score,
                    reasons=reasons,
                    deferred=False,
                )

        # Should be unreachable (all_deferred handled above), but keep safe.
        return RouteDecision(
            capability_id="",
            score=0.0,
            reasons=["no available candidates"],
            deferred=True,
        )
