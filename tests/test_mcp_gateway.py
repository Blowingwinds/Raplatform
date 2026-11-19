"""Integration tests for MCP Gateway — scope, risk, mock dispatch, and audit."""

import pytest

from src.agents.registry import AgentRegistry
from src.domain.lease_service import LeaseService
from src.domain.models import (
    AgentCapability,
    AuditEvent,
    Project,
    RiskLevel,
    Scope,
)
from src.domain.storage import SQLiteStore
from src.mcp.gateway import MCPGateway
from src.mcp.models import CallRequest, CallResult, CallStatus
from src.mcp.transport import MockTransport, TransportResult
from src.policy.approval import ApprovalGate
from src.policy.guard import PolicyGuard


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store():
    s = SQLiteStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def project(store):
    p = Project(project_id="proj-1", name="test project")
    store.save_project(p)
    return p


@pytest.fixture
def scope(store, project):
    s = Scope(
        scope_id="scope-1",
        project_id=project.project_id,
        target_type="domain",
        target="example.com",
        authorization_ref="ticket-001",
    )
    store.save_scope(s)
    return s


@pytest.fixture
def agent_cap():
    return AgentCapability(
        capability_id="agent-info-gatherer",
        name="Information Gatherer",
        techniques=["T1046", "T1592"],
        target_types=["ip", "domain", "url"],
        input_schema="info_gatherer_input.schema.json",
        output_schema="info_gatherer_output.schema.json",
        risk_level=RiskLevel.LOW,
        side_effects=[],
        max_concurrency=4,
    )


@pytest.fixture
def high_risk_agent():
    return AgentCapability(
        capability_id="agent-rce-verify",
        name="RCE Verifier",
        techniques=["T1203"],
        target_types=["url"],
        input_schema="rce_input.schema.json",
        output_schema="rce_output.schema.json",
        risk_level=RiskLevel.CRITICAL,
        side_effects=["executes code on target"],
        max_concurrency=1,
    )


@pytest.fixture
def mock_transport():
    return MockTransport(canned={
        "agent-info-gatherer": TransportResult(
            raw_output={"observations": [{"fact_type": "asset.discovered",
                                          "asset_ref": "192.168.1.1",
                                          "data": {"ip": "192.168.1.1"},
                                          "confidence": 0.9}]},
        ),
    })


@pytest.fixture
def gateway(store, mock_transport):
    registry = AgentRegistry(store)
    guard = PolicyGuard(store)
    return MCPGateway(registry=registry, guard=guard, transport=mock_transport)


@pytest.fixture
def registered_gateway(gateway, store, agent_cap):
    registry = AgentRegistry(store)
    registry.register(agent_cap)
    return gateway


# ---------------------------------------------------------------------------
# scope checks
# ---------------------------------------------------------------------------

class TestScopeValidation:

    @pytest.mark.asyncio
    async def test_rejects_missing_scope(self, gateway, agent_cap):
        gateway._registry.register(agent_cap)
        request = CallRequest(
            agent_id="agent-info-gatherer",
            scope_id="nonexistent-scope",
            task_id="task-1",
            project_id="proj-1",
        )
        result = await gateway.execute(request)
        assert result.status == CallStatus.REJECTED_SCOPE
        assert "scope not found" in (result.error or "")

    @pytest.mark.asyncio
    async def test_rejects_wrong_project(self, gateway, agent_cap, scope):
        gateway._registry.register(agent_cap)
        request = CallRequest(
            agent_id="agent-info-gatherer",
            scope_id=scope.scope_id,
            task_id="task-1",
            project_id="wrong-project",
        )
        result = await gateway.execute(request)
        assert result.status == CallStatus.REJECTED_SCOPE


# ---------------------------------------------------------------------------
# risk gates
# ---------------------------------------------------------------------------

class TestRiskGating:

    @pytest.mark.asyncio
    async def test_high_risk_requires_approval(self, gateway, high_risk_agent, scope):
        gateway._registry.register(high_risk_agent)
        request = CallRequest(
            agent_id="agent-rce-verify",
            scope_id=scope.scope_id,
            task_id="task-1",
            project_id=scope.project_id,
            risk_level=RiskLevel.CRITICAL,
        )
        result = await gateway.execute(request)
        assert result.status == CallStatus.WAITING_APPROVAL

    @pytest.mark.asyncio
    async def test_low_risk_passes_through(self, registered_gateway, scope):
        request = CallRequest(
            agent_id="agent-info-gatherer",
            scope_id=scope.scope_id,
            task_id="task-1",
            project_id=scope.project_id,
            risk_level=RiskLevel.LOW,
        )
        result = await registered_gateway.execute(request)
        assert result.status == CallStatus.SUCCEEDED


# ---------------------------------------------------------------------------
# mock dispatch
# ---------------------------------------------------------------------------

class TestMockDispatch:

    @pytest.mark.asyncio
    async def test_mock_result_returned(self, registered_gateway, scope):
        request = CallRequest(
            agent_id="agent-info-gatherer",
            scope_id=scope.scope_id,
            task_id="task-1",
            project_id=scope.project_id,
            risk_level=RiskLevel.LOW,
        )
        result = await registered_gateway.execute(request)
        assert result.status == CallStatus.SUCCEEDED
        assert result.result is not None
        assert "observations" in result.result


# ---------------------------------------------------------------------------
# audit trail
# ---------------------------------------------------------------------------

class TestAuditTrail:

    @pytest.mark.asyncio
    async def test_success_call_produces_audit(self, registered_gateway, scope):
        request = CallRequest(
            agent_id="agent-info-gatherer",
            scope_id=scope.scope_id,
            task_id="task-1",
            project_id=scope.project_id,
            risk_level=RiskLevel.LOW,
        )
        result = await registered_gateway.execute(request)
        event_types = [a["event_type"] for a in result.audit_events]
        assert "gateway.dispatch" in event_types
        assert "gateway.completed" in event_types

    @pytest.mark.asyncio
    async def test_risk_blocked_produces_audit(self, gateway, high_risk_agent, scope):
        gateway._registry.register(high_risk_agent)
        request = CallRequest(
            agent_id="agent-rce-verify",
            scope_id=scope.scope_id,
            task_id="task-1",
            project_id=scope.project_id,
            risk_level=RiskLevel.CRITICAL,
        )
        result = await gateway.execute(request)
        event_types = [a["event_type"] for a in result.audit_events]
        assert "gateway.risk_blocked" in event_types


# ---------------------------------------------------------------------------
# transport failure
# ---------------------------------------------------------------------------

class TestTransportFailure:

    @pytest.mark.asyncio
    async def test_failing_transport_returns_failed(self, store, scope):
        # a mock that always fails
        failing = MockTransport(canned={
            "agent-info-gatherer": TransportResult(
                raw_output={},
                exit_code=1,
                stderr="tool not found",
            ),
        })
        registry = AgentRegistry(store)
        guard = PolicyGuard(store)
        gw = MCPGateway(registry=registry, guard=guard, transport=failing)

        ag = AgentCapability(
            capability_id="agent-info-gatherer",
            name="IG", techniques=["T1046"], target_types=["ip"],
            input_schema="in.json", output_schema="out.json",
            risk_level=RiskLevel.LOW, max_concurrency=1,
        )
        registry.register(ag)

        request = CallRequest(
            agent_id="agent-info-gatherer",
            scope_id=scope.scope_id,
            task_id="task-1",
            project_id=scope.project_id,
            risk_level=RiskLevel.LOW,
        )
        result = await gw.execute(request)
        assert result.status == CallStatus.FAILED
        assert "tool not found" in (result.error or "")


# ---------------------------------------------------------------------------
# edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    @pytest.mark.asyncio
    async def test_unregistered_agent_rejected(self, gateway, scope):
        request = CallRequest(
            agent_id="unknown-agent",
            scope_id=scope.scope_id,
            task_id="task-1",
            project_id=scope.project_id,
            risk_level=RiskLevel.LOW,
        )
        result = await gateway.execute(request)
        assert result.status == CallStatus.REJECTED_SCOPE  # agent not found = scope reject
        assert "not registered" in (result.error or "")

    @pytest.mark.asyncio
    async def test_result_includes_timestamps(self, registered_gateway, scope):
        request = CallRequest(
            agent_id="agent-info-gatherer",
            scope_id=scope.scope_id,
            task_id="task-1",
            project_id=scope.project_id,
            risk_level=RiskLevel.LOW,
        )
        result = await registered_gateway.execute(request)
        assert result.started_at is not None
        assert result.finished_at is not None
        assert result.finished_at >= result.started_at


# ---------------------------------------------------------------------------
# HITL approval + lease integration (Module 8)
# ---------------------------------------------------------------------------

class TestApprovalAndLease:

    @pytest.fixture
    def approval_gateway(self, store, mock_transport):
        registry = AgentRegistry(store)
        guard = PolicyGuard(store)
        gate = ApprovalGate(store, demo_mode=False)
        return MCPGateway(
            registry=registry,
            guard=guard,
            transport=mock_transport,
            approval_gate=gate,
        )

    @pytest.mark.asyncio
    async def test_high_risk_with_approval_gate_creates_request(
        self, store, approval_gateway, high_risk_agent, scope,
    ):
        approval_gateway._registry.register(high_risk_agent)
        request = CallRequest(
            agent_id="agent-rce-verify",
            scope_id=scope.scope_id,
            task_id="task-approve-1",
            project_id=scope.project_id,
            risk_level=RiskLevel.CRITICAL,
        )
        result = await approval_gateway.execute(request)
        assert result.status == CallStatus.WAITING_APPROVAL
        # approval request id embedded in error message
        assert result.error is not None
        assert "approval_request_id=approval-" in result.error
        # extract id and confirm the approval record is persisted & pending
        approval_id = result.error.split("approval_request_id=")[1].strip()
        req = store.get_approval(approval_id)
        assert req is not None
        from src.domain.models import ApprovalState
        assert req.state == ApprovalState.PENDING

    @pytest.mark.asyncio
    async def test_high_risk_succeeds_after_approval(
        self, store, approval_gateway, high_risk_agent, scope,
    ):
        approval_gateway._registry.register(high_risk_agent)
        request = CallRequest(
            agent_id="agent-rce-verify",
            scope_id=scope.scope_id,
            task_id="task-approve-2",
            project_id=scope.project_id,
            risk_level=RiskLevel.CRITICAL,
        )
        first = await approval_gateway.execute(request)
        assert first.status == CallStatus.WAITING_APPROVAL
        approval_id = first.error.split("approval_request_id=")[1].strip()

        # Approve via the gate, then re-execute with the *same* CRITICAL risk.
        # The transport has no canned response for this agent, so MockTransport
        # returns an empty-but-success result.
        approval_gateway._approval_gate.approve(approval_id, decided_by="tester")

        result = await approval_gateway.execute(request)
        assert result.status == CallStatus.SUCCEEDED

    @pytest.mark.asyncio
    async def test_lease_conflict_returns_rejected_lease(
        self, store, mock_transport, agent_cap, scope,
    ):
        lease_svc = LeaseService(store)
        # Acquire a lease on a resource held by a *different* session.
        lease_svc.acquire(
            project_id=scope.project_id,
            resource_ref="asset:10.10.20.15",
            session_id="session-other",
            action_id="act-1",
        )

        registry = AgentRegistry(store)
        guard = PolicyGuard(store)
        gw = MCPGateway(
            registry=registry,
            guard=guard,
            transport=mock_transport,
            lease_service=lease_svc,
        )
        registry.register(agent_cap)

        request = CallRequest(
            agent_id="agent-info-gatherer",
            scope_id=scope.scope_id,
            task_id="task-lease-1",
            project_id=scope.project_id,
            risk_level=RiskLevel.LOW,
            resource_ref="asset:10.10.20.15",
        )
        result = await gw.execute(request)
        assert result.status == CallStatus.REJECTED_LEASE
        assert "held by session" in (result.error or "")