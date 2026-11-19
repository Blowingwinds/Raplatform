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
from src.domain.storage import SQLiteStore


def test_sqlite_store_round_trips_task_agent_fact_and_evidence(tmp_path):
    store = SQLiteStore(tmp_path / "raplatform.db")
    task = TaskNode(
        task_id="task-001",
        project_id="project-001",
        level=TaskLevel.ACTION,
        name="Discover services",
        technique_id="T1046",
        intent="Discover services in scope",
        target_refs=["scope-001"],
        constraints=ActionConstraints(timeout_seconds=120),
        expected_outputs=["asset", "service"],
        risk_level=RiskLevel.LOW,
    )
    capability = AgentCapability(
        capability_id="service-discovery",
        name="Service discovery",
        techniques=["T1046"],
        target_types=["cidr"],
        input_schema="service-discovery-input-v1",
        output_schema="service-discovery-result-v1",
        risk_level=RiskLevel.LOW,
    )
    evidence = Evidence(
        evidence_id="evidence-001",
        project_id="project-001",
        session_id="session-001",
        task_id="task-001",
        agent_id="recon-agent",
        kind="mcp.response",
        raw_payload={"hosts": [{"ip": "10.10.20.15"}]},
    )
    fact = BlackboardFact(
        fact_id="fact-001",
        project_id="project-001",
        fact_type="asset.discovered",
        asset_ref="asset:10.10.20.15",
        data={"ip": "10.10.20.15"},
        confidence=0.9,
        source_agent="recon-agent",
        session_id="session-001",
        evidence_ref="evidence-001",
    )

    store.save_task(task)
    store.save_capability(capability)
    store.save_evidence(evidence)
    store.save_fact(fact)

    assert store.get_task("task-001") == task
    assert store.get_capability("service-discovery") == capability
    assert store.get_evidence("evidence-001") == evidence
    assert store.get_fact("fact-001") == fact


def test_sqlite_store_rejects_duplicate_identifiers(tmp_path):
    store = SQLiteStore(tmp_path / "raplatform.db")
    task = TaskNode(
        task_id="task-duplicate",
        project_id="project-001",
        level=TaskLevel.GOAL,
        name="Goal",
        intent="Test duplicate protection",
        target_refs=["scope-001"],
    )

    store.save_task(task)

    try:
        store.save_task(task)
    except ValueError as exc:
        assert str(exc) == "task task-duplicate already exists"
    else:
        raise AssertionError("duplicate task should be rejected")


def test_sqlite_store_round_trips_project_scope_session_lease_events(tmp_path):
    store = SQLiteStore(tmp_path / "raplatform.db")
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
    blackboard_event = BlackboardEvent(
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

    store.save_project(project)
    store.save_scope(scope)
    store.save_session(session)
    store.save_lease(lease)
    store.save_blackboard_event(blackboard_event)
    store.save_audit_event(audit)

    assert store.get_project(project.project_id) == project
    assert store.get_scope(scope.scope_id) == scope
    assert store.get_session(session.session_id) == session
    assert store.get_lease(lease.lease_id) == lease
    assert store.get_blackboard_event(blackboard_event.event_id) == blackboard_event
    assert store.get_audit_event(audit.audit_id) == audit


def test_sqlite_store_round_trips_ptt_tree(tmp_path):
    from src.planner.ptt_schema import (
        ActionContract,
        PTTPlan,
        PTTTree,
        PTTNodeStatus,
        TacticNode,
        TechniqueNode,
    )

    store = SQLiteStore(tmp_path / "raplatform.db")
    action = ActionContract(
        action_id="act-001",
        name="Discover services",
        description="Port scan in scope",
        technique_id="T1046",
        target_refs=["scope-001"],
        expected_outputs=["service.exposed"],
        risk_level=RiskLevel.LOW,
    )
    plan = PTTPlan(
        plan_id="plan-001",
        goal="Map exposed services",
        normalized_goal="map exposed services",
        project_id="project-001",
        scope_id="scope-001",
        tactics=[
            TacticNode(
                tactic_id="reconnaissance",
                name="Reconnaissance",
                techniques=[
                    TechniqueNode(
                        technique_id="T1046",
                        name="Network Service Scanning",
                        actions=[action],
                    ),
                ],
            ),
        ],
    )
    tree = PTTTree.from_plan(plan)
    tree.set_status("act-001", PTTNodeStatus.READY)

    store.save_ptt_tree(plan.project_id, tree.to_persistable())
    loaded = store.get_ptt_tree(plan.project_id)
    assert loaded is not None
    restored = PTTTree.from_persistable(loaded)

    assert restored == tree
    assert restored.plan.plan_id == "plan-001"
    assert restored.node_states["act-001"] == PTTNodeStatus.READY
