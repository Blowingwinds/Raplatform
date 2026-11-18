"""Planner-specific error types for PTT planning and validation."""

from __future__ import annotations

from dataclasses import dataclass, field


class PTTError(Exception):
    """Base error for all PTT planning failures."""


@dataclass
class ValidationError:
    """A single validation failure with machine-readable code and human message."""

    code: str
    message: str
    path: str = ""  # JSON path to the failing node, e.g. "$.tactics[0].techniques[1]"

    def __str__(self) -> str:
        return f"[{self.code}] {self.path}: {self.message}" if self.path else f"[{self.code}] {self.message}"


class PlanRejection(PTTError):
    """Raised when a PTT plan fails validation and cannot be accepted."""

    def __init__(self, errors: list[ValidationError]) -> None:
        self.errors = errors
        detail = "; ".join(str(e) for e in errors)
        super().__init__(f"PTT plan rejected: {detail}")


class InvalidTechniqueError(PTTError):
    """A technique ID is not in the ATT&CK knowledge base."""

    def __init__(self, technique_id: str) -> None:
        super().__init__(f"Unknown ATT&CK technique: {technique_id}")


class ScopeViolationError(PTTError):
    """An action targets something outside the authorized scope."""

    def __init__(self, target: str, scope_id: str) -> None:
        super().__init__(
            f"Target '{target}' is outside authorized scope '{scope_id}'"
        )


class MissingContractError(PTTError):
    """An action is missing the required output contract."""

    def __init__(self, action_id: str) -> None:
        super().__init__(
            f"Action '{action_id}' has no expected_outputs — output contract required"
        )


class RiskExceededError(PTTError):
    """An action's risk level exceeds what the scope or policy allows."""

    def __init__(self, action_id: str, risk: str, max_allowed: str) -> None:
        super().__init__(
            f"Action '{action_id}' risk '{risk}' exceeds max allowed '{max_allowed}'"
        )


class NoMatchingScenarioError(PTTError):
    """Mock Provider could not find a scenario matching the user's goal."""

    def __init__(self, goal: str, tried_keywords: list[str] | None = None) -> None:
        detail = f"No mock scenario matched goal: '{goal}'"
        if tried_keywords:
            detail += f" (tried keywords: {tried_keywords})"
        super().__init__(detail)