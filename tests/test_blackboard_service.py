import pytest
from datetime import datetime, timezone

from src.blackboard.service import BlackboardService
from src.domain.models import BlackboardFact, Evidence
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
