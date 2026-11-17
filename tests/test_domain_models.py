import pytest
from pydantic import ValidationError

from src.domain.models import (
    ActionConstraints,
    AgentCapability,
    AuditEvent,
    BlackboardEvent,
    BlackboardFact,
    Evidence,
    ExecutionSession,
    Lease,
    Project,
    Scope,
    RiskLevel,
    SessionStatus,
    TaskLevel,
    TaskNode,
)


def test_action_task_requires_structured_contract_fields():
    task = TaskNode(
        task_id="task-action-001",
        project_id="project-001",
        level=TaskLevel.ACTION,
        name="Discover network services",
        technique_id="T1046",
        intent="Discover reachable services in the authorized scope",
        target_refs=["scope-001"],
        constraints=ActionConstraints(
            authorized_scope_only=True,
            max_concurrency=4,
            timeout_seconds=300,
        ),
        expected_outputs=["asset", "port", "service", "evidence"],
        risk_level=RiskLevel.LOW,
    )

    assert task.level is TaskLevel.ACTION
    assert task.constraints.authorized_scope_only is True
    assert task.expected_outputs == ["asset", "port", "service", "evidence"]


def test_action_task_rejects_missing_expected_outputs():
    with pytest.raises(ValidationError):
        TaskNode(
            task_id="task-action-002",
            project_id="project-001",
            level=TaskLevel.ACTION,
            name="Incomplete action",
            technique_id="T1046",
            intent="Missing an output contract",
            target_refs=["scope-001"],
            constraints=ActionConstraints(),
            expected_outputs=[],
            risk_level=RiskLevel.LOW,
        )


def test_blackboard_fact_links_normalized_state_to_raw_evidence():
    fact = BlackboardFact(
        fact_id="fact-001",
        project_id="project-001",
        fact_type="service.exposed",
        asset_ref="asset:10.10.20.15",
        data={"protocol": "tcp", "port": 443, "service": "nginx"},
        confidence=0.94,
        source_agent="recon-agent",
        session_id="session-001",
        evidence_ref="evidence-001",
    )

    evidence = Evidence(
        evidence_id="evidence-001",
        project_id="project-001",
        session_id="session-001",
        task_id="task-action-001",
        agent_id="recon-agent",
        kind="mcp.response",
        raw_payload={"hosts": [{"ip": "10.10.20.15", "ports": [443]}]},
    )

    assert fact.evidence_ref == evidence.evidence_id
    assert fact.data["port"] == 443
    assert evidence.raw_payload["hosts"][0]["ip"] == "10.10.20.15"


def test_blackboard_fact_rejects_confidence_outside_unit_interval():
    with pytest.raises(ValidationError):
        BlackboardFact(
            fact_id="fact-002",
            project_id="project-001",
            fact_type="asset.discovered",
            asset_ref="asset:10.10.20.16",
            data={},
            confidence=1.2,
            source_agent="recon-agent",
            session_id="session-001",
            evidence_ref="evidence-002",
        )


def test_agent_capability_declares_mcp_contract_and_limits():
    capability = AgentCapability(
        capability_id="network-service-discovery",
        name="Network service discovery",
        techniques=["T1046"],
        target_types=["ip", "cidr", "hostname"],
        input_schema="service-discovery-input-v1",
        output_schema="service-discovery-result-v1",
        risk_level=RiskLevel.LOW,
        side_effects=["network_probe"],
        max_concurrency=4,
    )

    assert capability.input_schema == "service-discovery-input-v1"
    assert capability.max_concurrency == 4


def test_project_scope_session_lease_and_audit_contracts_keep_authorization_context():
    project = Project(project_id="project-001", name="Demo assessment")
    scope = Scope(
        scope_id="scope-001",
        project_id=project.project_id,
        target_type="cidr",
        target="10.10.20.0/24",
        authorization_ref="approval-001",
    )
    session = ExecutionSession(
        session_id="session-001",
        project_id=project.project_id,
        task_id="task-001",
        agent_id="recon-agent",
        status=SessionStatus.RUNNING,
    )
    lease = Lease(
        lease_id="lease-001",
        project_id=project.project_id,
        resource_ref="asset:10.10.20.15",
        holder_session_id=session.session_id,
        expires_at="2026-11-17T16:30:00Z",
    )
    event = BlackboardEvent(
        event_id="blackboard-event-001",
        project_id=project.project_id,
        fact_id="fact-001",
        event_type="fact.created",
        fact_version=1,
    )
    audit = AuditEvent(
        audit_id="audit-001",
        project_id=project.project_id,
        event_type="mcp.call",
        actor_type="agent",
        actor_id="recon-agent",
        resource_ref="scope:scope-001",
        details={"capability_id": "network-service-discovery"},
    )

    assert scope.authorization_ref == "approval-001"
    assert session.status is SessionStatus.RUNNING
    assert lease.holder_session_id == session.session_id
    assert event.fact_version == 1
    assert audit.details["capability_id"] == "network-service-discovery"
