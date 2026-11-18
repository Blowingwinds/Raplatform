"""ATT&CK knowledge base — minimal static subset for MVP constraint checking.

This is NOT a complete ATT&CK KB or RAG system. It provides just enough
information to:
- Validate technique IDs against the known set
- Resolve technique → tactic mapping
- Look up risk level and expected outputs per technique
- Enumerate techniques available per tactic
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.domain.models import RiskLevel

# Path to the static JSON knowledge base
_KB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "attack_kb.json"


class AttackKB:
    """Static ATT&CK knowledge base loaded from a JSON file.

    Usage::

        kb = AttackKB()
        kb.validate_technique("T1046")   # → True
        kb.validate_technique("T9999")   # → False
        kb.tactic_for("T1046")           # → "discovery"
        kb.risk_for("T1046")             # → RiskLevel.LOW
        kb.expected_outputs("T1595")     # → ["asset.discovered", ...]
    """

    def __init__(self, kb_path: str | Path | None = None) -> None:
        path = Path(kb_path) if kb_path else _KB_PATH
        with open(path, encoding="utf-8") as fh:
            self._data: dict[str, Any] = json.load(fh)

        self._tactics: dict[str, dict] = self._data.get("tactics", {})
        self._techniques: dict[str, dict] = self._data.get("techniques", {})

    # ── technique queries ──────────────────────────────────────────────

    def validate_technique(self, technique_id: str) -> bool:
        """Check if a technique ID exists in the knowledge base."""
        return technique_id in self._techniques

    def technique_name(self, technique_id: str) -> str | None:
        """Return the human-readable name for a technique, or None."""
        tech = self._techniques.get(technique_id)
        return tech["name"] if tech else None

    def tactic_for(self, technique_id: str) -> str | None:
        """Return the tactic ID this technique belongs to, or None."""
        tech = self._techniques.get(technique_id)
        return tech.get("tactic") if tech else None

    def risk_for(self, technique_id: str) -> RiskLevel | None:
        """Return the risk level associated with a technique."""
        tech = self._techniques.get(technique_id)
        if not tech:
            return None
        risk_str = tech.get("risk", "low")
        try:
            return RiskLevel(risk_str)
        except ValueError:
            return None

    def target_types_for(self, technique_id: str) -> list[str]:
        """Return valid target types for a technique."""
        tech = self._techniques.get(technique_id)
        return list(tech.get("target_types", [])) if tech else []

    def expected_outputs(self, technique_id: str) -> list[str]:
        """Return expected output fact types for a technique."""
        tech = self._techniques.get(technique_id)
        return list(tech.get("expected_outputs", [])) if tech else []

    def technique_description(self, technique_id: str) -> str:
        """Return the description for a technique."""
        tech = self._techniques.get(technique_id)
        return tech.get("description", "") if tech else ""

    # ── tactic queries ─────────────────────────────────────────────────

    def validate_tactic(self, tactic_id: str) -> bool:
        """Check if a tactic ID exists."""
        return tactic_id in self._tactics

    def tactic_name(self, tactic_id: str) -> str | None:
        """Return the human-readable name for a tactic."""
        tac = self._tactics.get(tactic_id)
        return tac["name"] if tac else None

    def techniques_for_tactic(self, tactic_id: str) -> list[str]:
        """Return all technique IDs under a given tactic."""
        tac = self._tactics.get(tactic_id)
        return list(tac.get("techniques", [])) if tac else []

    # ── aggregate queries ──────────────────────────────────────────────

    def all_tactic_ids(self) -> list[str]:
        return list(self._tactics.keys())

    def all_technique_ids(self) -> list[str]:
        return list(self._techniques.keys())

    def tactics_for_techniques(self, technique_ids: list[str]) -> dict[str, str]:
        """Map technique_id → tactic_id for each known technique."""
        return {
            tid: self.tactic_for(tid)
            for tid in technique_ids
            if self.validate_technique(tid)
        }

    def available_techniques(self, *, max_risk: RiskLevel = RiskLevel.HIGH) -> list[str]:
        """Return all technique IDs at or below the max risk level."""
        risk_order = {
            RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3,
        }
        max_val = risk_order.get(max_risk, 99)
        return [
            tid for tid, tech in self._techniques.items()
            if risk_order.get(RiskLevel(tech.get("risk", "low")), 99) <= max_val
        ]