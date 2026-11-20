"""PTT plan validation — multi-layer contract enforcement.

Validation layers (in order):
1. Structural: JSON Schema / Pydantic (done by PTTPlan model itself)
2. ATT&CK legitimacy: every technique_id must be in the knowledge base
3. Platform capability: every technique must be in available_techniques
4. Scope boundary: every action's target_refs must be within authorized scope
5. Risk policy: no action exceeds the max allowed risk level
6. Output contract: every action must declare expected_outputs (enforced by Pydantic)
"""

from __future__ import annotations

from src.domain.models import RiskLevel, Scope
from src.planner.attack_kb import AttackKB
from src.planner.errors import (
    InvalidTechniqueError,
    MissingContractError,
    PlanRejection,
    RiskExceededError,
    ScopeViolationError,
    ValidationError,
)
from src.planner.ptt_schema import PTTPlan
from src.policy.guard import PolicyGuard

# Ordered risk values for comparison
_RISK_ORDER = {
    RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3,
}

# Fact types an action may declare in expected_outputs.
# Must stay a superset of ``blackboard.normalizer.IDENTITY_FIELDS`` (the types
# the blackboard can actually persist) — otherwise a plan passes planning and
# then silently loses facts at ingestion.
ALLOWED_FACT_TYPES: frozenset[str] = frozenset({
    "asset.discovered",
    "subdomain.discovered",
    "service.exposed",
    "network.relation",
    "fingerprint.detected",
    "vulnerability.detected",
    "credential.validated",
})


class PTTValidator:
    """Validates a PTT plan against ATT&CK knowledge, scope, risk, and capability rules.

    Usage::

        kb = AttackKB()
        guard = PolicyGuard(store)
        validator = PTTValidator(kb, guard)
        result = validator.validate(plan, scope, available_techniques=["T1046", ...])
        if not result.passed:
            raise PlanRejection(result.errors)
    """

    def __init__(self, attack_kb: AttackKB, guard: PolicyGuard) -> None:
        self._kb = attack_kb
        self._guard = guard

    def validate(
        self,
        plan: PTTPlan,
        scope: Scope,
        *,
        available_techniques: list[str] | None = None,
        max_risk: RiskLevel = RiskLevel.HIGH,
    ) -> ValidationResult:
        """Run all validation layers against the plan.

        Args:
            plan: The PTT plan to validate.
            scope: The authorized scope for target enforcement.
            available_techniques: Platform-registered technique IDs (for capability check).
            max_risk: Maximum allowed risk level for any action.

        Returns a ValidationResult with pass/fail and any errors found.
        """
        errors: list[ValidationError] = []

        # ── layer 1: ATT&CK legitimacy ─────────────────────────────────
        self._validate_attack_legitimacy(plan, errors)

        # ── layer 2: platform capability ───────────────────────────────
        if available_techniques is not None:
            self._validate_capability_match(plan, available_techniques, errors)

        # ── layer 3: scope boundary ────────────────────────────────────
        self._validate_scope(plan, scope, errors)

        # ── layer 4: risk policy ───────────────────────────────────────
        self._validate_risk(plan, max_risk, errors)

        # ── layer 5: output contract ───────────────────────────────────
        # (Pydantic already enforces non-empty expected_outputs, but we
        #  add semantic checks here)
        self._validate_output_contract(plan, errors)

        return ValidationResult(
            passed=len(errors) == 0,
            errors=errors,
        )

    # ── individual layers ──────────────────────────────────────────────

    def _validate_attack_legitimacy(
        self, plan: PTTPlan, errors: list[ValidationError],
    ) -> None:
        """Every technique_id must be in the ATT&CK knowledge base."""
        for i, tactic in enumerate(plan.tactics):
            # Validate tactic
            if not self._kb.validate_tactic(tactic.tactic_id):
                errors.append(ValidationError(
                    code="UNKNOWN_TACTIC",
                    message=f"Unknown ATT&CK tactic: '{tactic.tactic_id}'",
                    path=f"$.tactics[{i}]",
                ))

            for j, technique in enumerate(tactic.techniques):
                if not self._kb.validate_technique(technique.technique_id):
                    errors.append(ValidationError(
                        code="UNKNOWN_TECHNIQUE",
                        message=f"Unknown ATT&CK technique: '{technique.technique_id}'",
                        path=f"$.tactics[{i}].techniques[{j}]",
                    ))

                # Cross-check: technique should belong to the parent tactic
                expected_tactic = self._kb.tactic_for(technique.technique_id)
                if expected_tactic and expected_tactic != tactic.tactic_id:
                    errors.append(ValidationError(
                        code="TACTIC_MISMATCH",
                        message=(
                            f"Technique '{technique.technique_id}' belongs to tactic "
                            f"'{expected_tactic}', not '{tactic.tactic_id}'"
                        ),
                        path=f"$.tactics[{i}].techniques[{j}]",
                    ))

    def _validate_capability_match(
        self, plan: PTTPlan, available_techniques: list[str],
        errors: list[ValidationError],
    ) -> None:
        """Every technique in the plan must be in the platform's registered capabilities."""
        available_set = set(available_techniques)
        for i, tactic in enumerate(plan.tactics):
            for j, technique in enumerate(tactic.techniques):
                if technique.technique_id not in available_set:
                    errors.append(ValidationError(
                        code="CAPABILITY_MISSING",
                        message=(
                            f"Technique '{technique.technique_id}' ({technique.name}) "
                            f"has no registered agent capability"
                        ),
                        path=f"$.tactics[{i}].techniques[{j}]",
                    ))

    def _validate_scope(
        self, plan: PTTPlan, scope: Scope, errors: list[ValidationError],
    ) -> None:
        """Every action's target_refs must be within the authorized scope."""
        for i, tactic in enumerate(plan.tactics):
            for j, technique in enumerate(tactic.techniques):
                for k, action in enumerate(technique.actions):
                    for t, target in enumerate(action.target_refs):
                        if target == "*":
                            # Wildcard is acceptable — means "all in-scope targets"
                            continue
                        if not self._guard.validate_scope(scope.scope_id, target):
                            errors.append(ValidationError(
                                code="SCOPE_VIOLATION",
                                message=(
                                    f"Action '{action.action_id}' targets '{target}' "
                                    f"which is outside authorized scope '{scope.scope_id}'"
                                ),
                                path=f"$.tactics[{i}].techniques[{j}].actions[{k}].target_refs[{t}]",
                            ))

    def _validate_risk(
        self, plan: PTTPlan, max_risk: RiskLevel, errors: list[ValidationError],
    ) -> None:
        """No action's risk level may exceed the max allowed."""
        max_val = _RISK_ORDER.get(max_risk, 2)
        for i, tactic in enumerate(plan.tactics):
            for j, technique in enumerate(tactic.techniques):
                for k, action in enumerate(technique.actions):
                    action_val = _RISK_ORDER.get(action.risk_level, 0)
                    if action_val > max_val:
                        errors.append(ValidationError(
                            code="RISK_EXCEEDED",
                            message=(
                                f"Action '{action.action_id}' has risk '{action.risk_level.value}' "
                                f"which exceeds max allowed '{max_risk.value}'"
                            ),
                            path=f"$.tactics[{i}].techniques[{j}].actions[{k}]",
                        ))

    def _validate_output_contract(
        self, plan: PTTPlan, errors: list[ValidationError],
    ) -> None:
        """Semantic checks on expected_outputs beyond Pydantic's non-empty check."""
        valid_fact_types = ALLOWED_FACT_TYPES
        for i, tactic in enumerate(plan.tactics):
            for j, technique in enumerate(tactic.techniques):
                for k, action in enumerate(technique.actions):
                    # Check each output is a known fact type
                    invalid_outputs = [
                        o for o in action.expected_outputs
                        if o not in valid_fact_types
                    ]
                    if invalid_outputs:
                        errors.append(ValidationError(
                            code="UNKNOWN_FACT_TYPE",
                            message=(
                                f"Action '{action.action_id}' declares unknown "
                                f"expected_output(s): {invalid_outputs}"
                            ),
                            path=f"$.tactics[{i}].techniques[{j}].actions[{k}].expected_outputs",
                        ))


# ── validation result ────────────────────────────────────────────────────

class ValidationResult:
    """Immutable result of PTT plan validation."""

    def __init__(self, passed: bool, errors: list[ValidationError]) -> None:
        self.passed = passed
        self.errors = errors

    def raise_if_failed(self) -> None:
        """If validation failed, raise PlanRejection."""
        if not self.passed:
            raise PlanRejection(self.errors)

    def __bool__(self) -> bool:
        return self.passed