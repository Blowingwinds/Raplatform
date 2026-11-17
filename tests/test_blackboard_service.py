import pytest
import sqlite3
from datetime import datetime, timezone

from src.blackboard.service import BlackboardService
from src.domain import models
from src.domain.models import BlackboardEvent, BlackboardFact, Evidence
from src.domain.storage import SQLiteStore


def make_evidence(evidence_id: str = "evidence-001") -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        project_id="project-001",
        session_id="session-001",
        task_id="task-001",
        agent_id="recon-agent",
        kind="mcp.response",
        raw_payload={"hosts": [{"ip": "10.10.20.15", "ports": [443]}]},
        captured_at=datetime(2026, 11, 17, 8, 0, tzinfo=timezone.utc),
    )


def make_fact(fact_id: str = "fact-001", version: int = 1, evidence_ref: str = "evidence-001") -> BlackboardFact:
    return BlackboardFact(
        fact_id=fact_id,
        project_id="project-001",
        fact_type="service.exposed",
        asset_ref="asset:10.10.20.15",
        data={"protocol": "tcp", "port": 443, "service": "nginx"},
        confidence=0.94,
        source_agent="recon-agent",
        session_id="session-001",
        evidence_ref=evidence_ref,
        version=version,
        observed_at=datetime(2026, 11, 17, 8, 0, tzinfo=timezone.utc),
    )


def test_publish_fact_requires_existing_evidence_and_emits_increment(tmp_path):
    store = SQLiteStore(tmp_path / "raplatform.db")
    service = BlackboardService(store)
    service.save_evidence(make_evidence())

    event = service.publish_fact(make_fact())

    assert event.event_type == "fact.created"
    assert event.fact_version == 1
    assert event.sequence == 1
    assert service.snapshot("project-001") == [make_fact()]
    assert service.evidence_for_fact("fact-001") == make_evidence()
    assert service.events_since("project-001", after_sequence=0) == [event]


def test_publish_fact_rejects_missing_evidence(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))

    with pytest.raises(ValueError, match="evidence evidence-missing does not exist"):
        service.publish_fact(make_fact(evidence_ref="evidence-missing"))


def test_publish_fact_updates_only_with_a_newer_version(tmp_path):
    store = SQLiteStore(tmp_path / "raplatform.db")
    service = BlackboardService(store)
    service.save_evidence(make_evidence())
    service.publish_fact(make_fact())

    with pytest.raises(ValueError, match="fact fact-001 version must increase"):
        service.publish_fact(make_fact(version=1))

    updated = make_fact(version=2)
    updated.data["service"] = "nginx/1.25"
    event = service.publish_fact(updated)

    assert event.event_type == "fact.updated"
    assert event.fact_version == 2
    assert service.snapshot("project-001")[0].data["service"] == "nginx/1.25"
    assert [item.sequence for item in service.events_since("project-001", after_sequence=1)] == [2]


def test_repeated_fact_keeps_each_observation_and_evidence(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))
    first = make_fact()
    second = make_fact(version=2, evidence_ref="evidence-002")
    second.data["service"] = "nginx/1.25"
    service.save_evidence(make_evidence())
    service.save_evidence(make_evidence("evidence-002"))

    service.publish_fact(first)
    service.publish_fact(second)

    assert service.snapshot("project-001")[0].version == 2
    assert [event.observation.data["service"] for event in service.history("fact-001")] == [
        "nginx", "nginx/1.25"
    ]
    assert [item.evidence_id for item in service.evidence_history_for_fact("fact-001")] == [
        "evidence-001", "evidence-002"
    ]


def test_opposing_agent_observation_marks_conflict_without_replacing_prior_claim(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))
    service.save_evidence(make_evidence())
    other_evidence = make_evidence("evidence-002")
    other_evidence.agent_id = "verification-agent"
    other_evidence.session_id = "session-002"
    service.save_evidence(other_evidence)
    service.publish_fact(make_fact())

    opposing = make_fact(version=2, evidence_ref="evidence-002")
    opposing.source_agent = "verification-agent"
    opposing.session_id = "session-002"
    opposing.state = models.FactState.INVALIDATED
    opposing.data["service"] = "closed"
    event = service.publish_fact(opposing)

    current = service.snapshot("project-001")[0]
    assert current.state is models.FactState.CONFLICTED
    assert current.data["service"] == "nginx"
    assert event.event_type == "fact.conflicted"
    assert event.observation == opposing
    assert [item.evidence_id for item in service.evidence_history_for_fact("fact-001")] == [
        "evidence-001", "evidence-002"
    ]


def test_same_agent_can_invalidate_fact_after_retest(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))
    service.save_evidence(make_evidence())
    service.save_evidence(make_evidence("evidence-002"))
    service.publish_fact(make_fact())

    invalidated = make_fact(version=2, evidence_ref="evidence-002")
    invalidated.state = models.FactState.INVALIDATED
    event = service.publish_fact(invalidated)

    assert event.event_type == "fact.invalidated"
    assert service.snapshot("project-001")[0].state is models.FactState.INVALIDATED


def test_fact_must_reference_evidence_from_same_execution(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))
    service.save_evidence(make_evidence())
    fact = make_fact()
    fact.session_id = "session-other"

    with pytest.raises(ValueError, match="does not match fact execution"):
        service.publish_fact(fact)


def test_fact_versions_return_current_state_at_each_event(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))
    service.save_evidence(make_evidence())
    opposing_evidence = make_evidence("evidence-002")
    opposing_evidence.agent_id = "verification-agent"
    opposing_evidence.session_id = "session-002"
    service.save_evidence(opposing_evidence)
    service.publish_fact(make_fact())
    opposing = make_fact(version=2, evidence_ref="evidence-002")
    opposing.source_agent = "verification-agent"
    opposing.session_id = "session-002"
    opposing.state = models.FactState.INVALIDATED
    service.publish_fact(opposing)

    assert service.fact_at_version("fact-001", 1).state is models.FactState.ACTIVE
    assert service.fact_at_version("fact-001", 2).state is models.FactState.CONFLICTED
    assert service.fact_at_version("fact-001", 3) is None


def test_snapshot_filters_by_asset_service_type_and_version(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))
    service.save_evidence(make_evidence())
    service.publish_fact(make_fact())
    other = make_fact("fact-002")
    other.asset_ref = "asset:10.10.20.16"
    other.data["port"] = 80
    service.publish_fact(other)

    assert [fact.fact_id for fact in service.snapshot("project-001", asset_ref="asset:10.10.20.15")] == ["fact-001"]
    assert [fact.fact_id for fact in service.snapshot("project-001", service_ref="tcp:443")] == ["fact-001"]
    assert len(service.snapshot("project-001", fact_type="service.exposed")) == 2
    assert service.snapshot("project-001", min_version=2) == []


def test_fact_and_event_write_roll_back_together(tmp_path):
    store = SQLiteStore(tmp_path / "raplatform.db")
    service = BlackboardService(store)
    service.save_evidence(make_evidence())
    store.save_blackboard_event(
        BlackboardEvent(
            event_id="blackboard-event-fact-001-v1",
            project_id="project-001",
            fact_id="fact-001",
            event_type="fact.created",
            fact_version=1,
        )
    )

    with pytest.raises(sqlite3.IntegrityError):
        service.publish_fact(make_fact())

    assert store.get_fact("fact-001") is None
