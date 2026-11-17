"""Business rules for publishing shared target facts."""

from datetime import timedelta

from src.blackboard.normalizer import normalize_observations
from src.domain.models import BlackboardEvent, BlackboardFact, Evidence, FactState
from src.domain.storage import SQLiteStore


class BlackboardService:
    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def save_evidence(self, evidence: Evidence) -> None:
        self.store.save_evidence(evidence)

    def ingest_result(self, evidence: Evidence) -> list[BlackboardEvent]:
        facts = normalize_observations(evidence)
        self.save_evidence(evidence)
        events = []
        for fact in facts:
            previous = self.store.get_fact(fact.fact_id)
            fact.version = previous.version + 1 if previous else 1
            events.append(self.publish_fact(fact))
        return events

    def publish_fact(self, fact: BlackboardFact) -> BlackboardEvent:
        evidence = self.store.get_evidence(fact.evidence_ref)
        if evidence is None:
            raise ValueError(f"evidence {fact.evidence_ref} does not exist")
        if (evidence.project_id, evidence.session_id, evidence.agent_id) != (
            fact.project_id, fact.session_id, fact.source_agent
        ):
            raise ValueError("evidence does not match fact execution")
        if fact.state is FactState.CONFLICTED:
            raise ValueError("an observation cannot declare a conflict state")

        previous = self.store.get_fact(fact.fact_id)
        if previous is None:
            event_type = "fact.created"
            current = fact
        else:
            if fact.version <= previous.version:
                raise ValueError(f"fact {fact.fact_id} version must increase")
            if (previous.project_id, previous.fact_type, previous.asset_ref) != (
                fact.project_id, fact.fact_type, fact.asset_ref
            ):
                raise ValueError("fact identity cannot change across versions")
            if previous.state is FactState.CONFLICTED:
                event_type = "fact.resolved"
                current = fact
            elif (
                previous.state is not fact.state
                and previous.source_agent != fact.source_agent
                and abs(fact.observed_at - previous.observed_at) <= timedelta(minutes=10)
            ):
                event_type = "fact.conflicted"
                current = previous.model_copy(deep=True)
                current.version = fact.version
                current.state = FactState.CONFLICTED
            else:
                event_type = "fact.invalidated" if fact.state is FactState.INVALIDATED else "fact.updated"
                current = fact

        events = self.store.list_blackboard_events(fact.project_id)
        event = BlackboardEvent(
            event_id=f"blackboard-event-{fact.fact_id}-v{fact.version}",
            project_id=fact.project_id,
            fact_id=fact.fact_id,
            event_type=event_type,
            fact_version=fact.version,
            sequence=(events[-1].sequence + 1) if events else 1,
            observation=fact,
            current_fact=current,
        )
        self.store.record_fact_event(current, event, exists=previous is not None)
        return event

    def snapshot(
        self,
        project_id: str,
        *,
        asset_ref: str | None = None,
        service_ref: str | None = None,
        fact_type: str | None = None,
        min_version: int | None = None,
    ) -> list[BlackboardFact]:
        facts = self.store.list_facts(project_id)
        if asset_ref is not None:
            facts = [fact for fact in facts if fact.asset_ref == asset_ref]
        if service_ref is not None:
            facts = [
                fact for fact in facts
                if fact.data.get("service_ref") == service_ref
                or (
                    fact.fact_type == "service.exposed"
                    and f"{fact.data.get('protocol')}:{fact.data.get('port')}" == service_ref
                )
            ]
        if fact_type is not None:
            facts = [fact for fact in facts if fact.fact_type == fact_type]
        if min_version is not None:
            facts = [fact for fact in facts if fact.version >= min_version]
        return facts

    def events_since(self, project_id: str, after_sequence: int = 0) -> list[BlackboardEvent]:
        return self.store.list_blackboard_events(project_id, after_sequence)

    def history(self, fact_id: str) -> list[BlackboardEvent]:
        fact = self.store.get_fact(fact_id)
        if fact is None:
            raise ValueError(f"fact {fact_id} does not exist")
        return [event for event in self.events_since(fact.project_id) if event.fact_id == fact_id]

    def fact_at_version(self, fact_id: str, version: int) -> BlackboardFact | None:
        for event in self.history(fact_id):
            if event.fact_version == version:
                return event.current_fact
        return None

    def evidence_history_for_fact(self, fact_id: str) -> list[Evidence]:
        evidence = []
        seen = set()
        for event in self.history(fact_id):
            if event.observation is None or event.observation.evidence_ref in seen:
                continue
            item = self.store.get_evidence(event.observation.evidence_ref)
            if item is None:
                raise ValueError(f"evidence {event.observation.evidence_ref} does not exist")
            evidence.append(item)
            seen.add(item.evidence_id)
        return evidence

    def evidence_for_fact(self, fact_id: str) -> Evidence:
        fact = self.store.get_fact(fact_id)
        if fact is None:
            raise ValueError(f"fact {fact_id} does not exist")
        evidence = self.store.get_evidence(fact.evidence_ref)
        if evidence is None:
            raise ValueError(f"evidence {fact.evidence_ref} does not exist")
        return evidence
