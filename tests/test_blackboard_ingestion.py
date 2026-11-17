from datetime import datetime, timezone

import pytest

from src.blackboard.service import BlackboardService
from src.domain import models
from src.domain.models import Evidence
from src.domain.storage import SQLiteStore


OBSERVED_AT = "2026-11-17T08:00:00Z"


def make_evidence(evidence_id: str, agent_id: str, observations: list[dict]) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        project_id="project-001",
        session_id=f"session-{evidence_id}",
        task_id="task-001",
        agent_id=agent_id,
        kind="agent.result",
        raw_payload={"tool_output": {"format": "nmap.xml", "content": "<nmaprun/>"}, "observations": observations},
        captured_at=datetime(2026, 11, 17, 8, 0, tzinfo=timezone.utc),
    )


def observation(fact_type: str, asset_ref: str, data: dict, state: str = "active") -> dict:
    return {
        "fact_type": fact_type,
        "asset_ref": asset_ref,
        "data": data,
        "confidence": 0.9,
        "state": state,
        "observed_at": OBSERVED_AT,
    }


def test_mock_agent_result_publishes_six_fact_types_with_one_evidence(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))
    observations = [
        observation("asset.discovered", "asset:10.10.20.15", {"ip": "10.10.20.15"}),
        observation("subdomain.discovered", "domain:example.test", {"hostname": "api.example.test"}),
        observation("service.exposed", "asset:10.10.20.15", {"protocol": "tcp", "port": 443, "service": "https"}),
        observation("network.relation", "domain:api.example.test", {"relation": "resolves_to", "peer_ref": "asset:10.10.20.15"}),
        observation("vulnerability.detected", "asset:10.10.20.15", {"vulnerability_id": "LAB-001", "service_ref": "tcp:443", "severity": "high"}),
        observation("credential.validated", "asset:10.10.20.15", {"credential_type": "password", "principal": "lab-user", "credential": "demo-password", "service_ref": "tcp:443"}),
    ]

    events = service.ingest_result(make_evidence("evidence-001", "recon-agent", observations))

    facts = service.snapshot("project-001")
    assert len(events) == len(facts) == 6
    assert {fact.fact_type for fact in facts} == {item["fact_type"] for item in observations}
    assert next(fact for fact in facts if fact.fact_type == "credential.validated").data["credential"] == "demo-password"
    assert all(service.evidence_for_fact(fact.fact_id).evidence_id == "evidence-001" for fact in facts)
    assert [event.sequence for event in service.events_since("project-001")] == list(range(1, 7))


def test_same_semantic_fact_from_other_agent_keeps_stable_id_and_versions(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))
    first = observation("service.exposed", "asset:10.10.20.15", {"protocol": "tcp", "port": 443, "service": "https"})
    second = observation("service.exposed", "asset:10.10.20.15", {"service": "nginx", "port": 443, "protocol": "tcp"})

    service.ingest_result(make_evidence("evidence-001", "recon-agent", [first]))
    service.ingest_result(make_evidence("evidence-002", "other-agent", [second]))

    facts = service.snapshot("project-001")
    assert len(facts) == 1
    assert facts[0].version == 2
    assert facts[0].data["service"] == "nginx"
    assert [event.event_type for event in service.history(facts[0].fact_id)] == ["fact.created", "fact.updated"]
    assert [item.evidence_id for item in service.evidence_history_for_fact(facts[0].fact_id)] == [
        "evidence-001", "evidence-002"
    ]


def test_opposite_state_from_other_agent_is_conflicted_and_preserves_observations(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))
    present = observation("service.exposed", "asset:10.10.20.15", {"protocol": "tcp", "port": 443, "service": "https"})
    absent = observation("service.exposed", "asset:10.10.20.15", {"protocol": "tcp", "port": 443}, "invalidated")

    service.ingest_result(make_evidence("evidence-001", "recon-agent", [present]))
    service.ingest_result(make_evidence("evidence-002", "verify-agent", [absent]))

    fact = service.snapshot("project-001")[0]
    assert fact.state is models.FactState.CONFLICTED
    assert fact.data["service"] == "https"
    assert [event.observation.state for event in service.history(fact.fact_id)] == [
        models.FactState.ACTIVE, models.FactState.INVALIDATED
    ]


def test_custom_fact_type_requires_identity_and_can_be_ingested(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))
    custom = observation("web.endpoint", "asset:10.10.20.15", {"path": "/admin"})
    custom["identity"] = {"path": "/admin"}

    service.ingest_result(make_evidence("evidence-001", "recon-agent", [custom]))

    assert service.snapshot("project-001")[0].fact_type == "web.endpoint"


def test_missing_identity_field_rejects_result_before_evidence_is_saved(tmp_path):
    store = SQLiteStore(tmp_path / "raplatform.db")
    service = BlackboardService(store)
    missing_port = observation("service.exposed", "asset:10.10.20.15", {"protocol": "tcp"})

    with pytest.raises(ValueError, match="missing identity field: port"):
        service.ingest_result(make_evidence("evidence-001", "recon-agent", [missing_port]))

    assert store.get_evidence("evidence-001") is None


def test_service_identity_normalizes_protocol_and_port_across_agents(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))
    first = observation("service.exposed", "asset:10.10.20.15", {"protocol": "TCP", "port": "443"})
    second = observation("service.exposed", "asset:10.10.20.15", {"protocol": "tcp", "port": 443})

    service.ingest_result(make_evidence("evidence-001", "recon-agent", [first]))
    service.ingest_result(make_evidence("evidence-002", "verify-agent", [second]))

    facts = service.snapshot("project-001")
    assert len(facts) == 1
    assert facts[0].version == 2
    assert facts[0].data["protocol"] == "tcp"
    assert facts[0].data["port"] == 443


def test_retest_resolves_conflict_and_keeps_all_three_evidence_items(tmp_path):
    service = BlackboardService(SQLiteStore(tmp_path / "raplatform.db"))
    present = observation("service.exposed", "asset:10.10.20.15", {"protocol": "tcp", "port": 443})
    absent = observation("service.exposed", "asset:10.10.20.15", {"protocol": "tcp", "port": 443}, "invalidated")

    service.ingest_result(make_evidence("evidence-001", "recon-agent", [present]))
    service.ingest_result(make_evidence("evidence-002", "verify-agent", [absent]))
    events = service.ingest_result(make_evidence("evidence-003", "verify-agent", [absent]))

    fact = service.snapshot("project-001")[0]
    assert fact.state is models.FactState.INVALIDATED
    assert events[0].event_type == "fact.resolved"
    assert len(service.evidence_history_for_fact(fact.fact_id)) == 3
