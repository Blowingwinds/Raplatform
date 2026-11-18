"""PTT planning module — Goal → Tactic → Technique → Action tree generation.

Public API:
- ``Planner`` — orchestrates plan generation and validation
- ``MockProvider`` — deterministic mock for offline testing
- ``PTTPlan`` / ``PTTTree`` — static plan and live tree models
- ``AttackKB`` — static ATT&CK knowledge base
- ``PTTValidator`` — multi-layer plan validation
"""

from src.planner.attack_kb import AttackKB
from src.planner.contract import PTTValidator, ValidationResult
from src.planner.errors import (
    InvalidTechniqueError,
    MissingContractError,
    NoMatchingScenarioError,
    PlanRejection,
    RiskExceededError,
    ScopeViolationError,
    ValidationError,
)
from src.planner.planner import Planner
from src.planner.provider import MockProvider, PlanRequest, PlannerProvider, plan_to_tree
from src.planner.ptt_schema import (
    ActionContract,
    ActionNode,
    PTTNodeStatus,
    PTTPlan,
    PTTTree,
    TacticNode,
    TechniqueNode,
)

__all__ = [
    # Planner
    "Planner",
    # Provider
    "PlannerProvider",
    "MockProvider",
    "PlanRequest",
    "plan_to_tree",
    # Schema
    "PTTPlan",
    "PTTTree",
    "TacticNode",
    "TechniqueNode",
    "ActionContract",
    "ActionNode",
    "PTTNodeStatus",
    # Validation
    "PTTValidator",
    "ValidationResult",
    # Errors
    "PlanRejection",
    "InvalidTechniqueError",
    "ScopeViolationError",
    "MissingContractError",
    "RiskExceededError",
    "NoMatchingScenarioError",
    "ValidationError",
    # Knowledge
    "AttackKB",
]