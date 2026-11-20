"""Authorization scope and risk-policy enforcement for MCP calls."""

from __future__ import annotations

from src.domain.models import RiskLevel, Scope
from src.domain.storage import SQLiteStore

_HIGH_RISK_THRESHOLD: set[RiskLevel] = {RiskLevel.HIGH, RiskLevel.CRITICAL}


class PolicyGuard:
    def __init__(self, store: SQLiteStore, *, demo_mode: bool = False) -> None:
        self._store = store
        self._demo_mode = demo_mode

    # ------------------------------------------------------------------
    # scope
    # ------------------------------------------------------------------
    def validate_scope(self, scope_id: str, target: str) -> bool:
        scope = self._store.get_scope(scope_id)
        if scope is None:
            return False
        return _target_matches_scope(target, scope)

    def scope_from_id(self, scope_id: str) -> Scope | None:
        return self._store.get_scope(scope_id)

    # ------------------------------------------------------------------
    # risk
    # ------------------------------------------------------------------
    def is_high_risk(self, risk_level: RiskLevel) -> bool:
        return risk_level in _HIGH_RISK_THRESHOLD

    def needs_approval(self, risk_level: RiskLevel) -> bool:
        if self._demo_mode:
            return False
        return self.is_high_risk(risk_level)


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------
def _target_matches_scope(target: str, scope: Scope) -> bool:
    """Naive scope matching: wildcard, exact match, or suffix match (subdomains)."""
    if not target:
        return False
    target_lower = target.strip().lower()
    scope_lower = scope.target.strip().lower()

    # Wildcard scope — the auto-created per-run scope authorizes its seed targets
    if scope_lower == "*":
        return True

    if target_lower == scope_lower:
        return True
    if scope.target_type in ("domain", "hostname") and target_lower.endswith(
        "." + scope_lower
    ):
        return True
    return False