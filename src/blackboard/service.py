"""Business rules for publishing shared target facts."""

from src.domain.models import BlackboardEvent, BlackboardFact, Evidence
from src.domain.storage import SQLiteStore


class BlackboardService:
    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def save_evidence(self, evidence: Evidence) -> None:
        self.store.save_evidence(evidence)

    def publish_fact(self, fact: BlackboardFact) -> BlackboardEvent:
        if self.store.get_evidence(fact.evidence_ref) is None:
            raise ValueError(f"evidence {fact.evidence_ref} does not exist")

        previous = self.store.get_fact(fact.fact_id)
        if previous is None:
            event_type = "fact.created"
            self.store.save_fact(fact)
        else:
            if fact.version <= previous.version:
                raise ValueError(f"fact {fact.fact_id} version must increase")
            event_type = "fact.updated"
            self.store.update_fact(fact)

        events = self.store.list_blackboard_events(fact.project_id)
        event = BlackboardEvent(
            event_id=f"blackboard-event-{fact.fact_id}-v{fact.version}",
            project_id=fact.project_id,
            fact_id=fact.fact_id,
            event_type=event_type,
            fact_version=fact.version,
            sequence=(events[-1].sequence + 1) if events else 1,
        )
        self.store.save_blackboard_event(event)
        return event

    def snapshot(self, project_id: str) -> list[BlackboardFact]:
        return self.store.list_facts(project_id)

    def events_since(self, project_id: str, after_sequence: int = 0) -> list[BlackboardEvent]:
        return self.store.list_blackboard_events(project_id, after_sequence)

    def evidence_for_fact(self, fact_id: str) -> Evidence:
        fact = self.store.get_fact(fact_id)
        if fact is None:
            raise ValueError(f"fact {fact_id} does not exist")
        evidence = self.store.get_evidence(fact.evidence_ref)
        if evidence is None:
            raise ValueError(f"evidence {fact.evidence_ref} does not exist")
        return evidence
