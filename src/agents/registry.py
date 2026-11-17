"""Agent capability registry — register, discover, and manage agents."""

from src.domain.models import AgentCapability, RiskLevel
from src.domain.storage import SQLiteStore


class AgentRegistry:
    def __init__(self, store: SQLiteStore) -> None:
        self._store = store

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def register(self, capability: AgentCapability) -> None:
        existing = self._store.get_capability(capability.capability_id)
        if existing is not None:
            raise ValueError(
                f"agent {capability.capability_id} is already registered"
            )
        self._store.save_capability(capability)

    def unregister(self, capability_id: str) -> None:
        capability = self._store.get_capability(capability_id)
        if capability is None:
            raise ValueError(f"agent {capability_id} is not registered")
        self._store.delete_capability(capability_id)

    def get(self, capability_id: str) -> AgentCapability | None:
        return self._store.get_capability(capability_id)

    def list_all(self) -> list[AgentCapability]:
        return self._store.list_capabilities()

    # ------------------------------------------------------------------
    # matching
    # ------------------------------------------------------------------
    def find_by_techniques(
        self,
        techniques: list[str],
        *,
        risk_max: RiskLevel = RiskLevel.CRITICAL,
    ) -> list[AgentCapability]:
        risk_order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1,
                      RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}
        return [
            c for c in self.list_all()
            if any(t in c.techniques for t in techniques)
            and risk_order.get(c.risk_level, 99) <= risk_order.get(risk_max, 99)
        ]

    def find_by_target_type(
        self,
        target_type: str,
        *,
        risk_max: RiskLevel = RiskLevel.CRITICAL,
    ) -> list[AgentCapability]:
        risk_order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1,
                      RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}
        return [
            c for c in self.list_all()
            if target_type in c.target_types
            and risk_order.get(c.risk_level, 99) <= risk_order.get(risk_max, 99)
        ]

    def find_best(
        self,
        *,
        techniques: list[str] | None = None,
        target_types: list[str] | None = None,
        risk_max: RiskLevel = RiskLevel.HIGH,
    ) -> list[AgentCapability]:
        candidates = self.list_all()
        risk_order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1,
                      RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}

        def _score(cap: AgentCapability) -> int:
            s = 0
            if techniques:
                s += len(set(cap.techniques) & set(techniques))
            if target_types:
                s += len(set(cap.target_types) & set(target_types))
            return s

        matched = [
            c for c in candidates
            if risk_order.get(c.risk_level, 99) <= risk_order.get(risk_max, 99)
            and (
                (techniques is None and target_types is None)
                or (techniques and any(t in c.techniques for t in techniques))
                or (target_types and any(t in c.target_types for t in target_types))
            )
        ]
        matched.sort(key=_score, reverse=True)
        return matched