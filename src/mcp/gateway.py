"""MCP Gateway — validates, audits, and dispatches Agent calls."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from src.agents.registry import AgentRegistry
from src.domain.models import AuditEvent, RiskLevel
from src.mcp.models import CallRequest, CallResult, CallStatus
from src.mcp.transport import Transport
from src.policy.guard import PolicyGuard

if TYPE_CHECKING:
    from src.domain.lease_service import LeaseService
    from src.policy.approval import ApprovalGate


class MCPGateway:
    def __init__(
        self,
        registry: AgentRegistry,
        guard: PolicyGuard,
        transport: Transport,
        lease_service: "LeaseService | None" = None,
        approval_gate: "ApprovalGate | None" = None,
    ) -> None:
        self._registry = registry
        self._guard = guard
        self._transport = transport
        self._lease_service = lease_service
        self._approval_gate = approval_gate

    async def execute(self, request: CallRequest) -> CallResult:
        call_id = f"call-{uuid.uuid4().hex[:12]}"
        started = datetime.now(timezone.utc)
        audit: list[AuditEvent] = []

        # ---- 1. scope check -------------------------------------------------
        scope = self._guard.scope_from_id(request.scope_id)
        if scope is None:
            return self._rejected(call_id, request.agent_id, CallStatus.REJECTED_SCOPE,
                                  "scope not found", audit, started)

        if scope.project_id != request.project_id:
            return self._rejected(call_id, request.agent_id, CallStatus.REJECTED_SCOPE,
                                  "scope does not belong to project", audit, started)

        # ---- 2. agent lookup -------------------------------------------------
        capability = self._registry.get(request.agent_id)
        if capability is None:
            return self._rejected(call_id, request.agent_id, CallStatus.REJECTED_SCOPE,
                                  f"agent {request.agent_id} not registered", audit, started)

        # ---- 3. risk gate ----------------------------------------------------
        if self._guard.needs_approval(request.risk_level):
            # If an approval has already been granted for this action, skip
            # the WAITING_APPROVAL return and proceed to dispatch.
            already_granted = (
                self._approval_gate is not None
                and self._approval_gate.is_granted(request.task_id)
            )
            if not already_granted:
                approval_req_id: str | None = None
                if self._approval_gate is not None:
                    approval_req = self._approval_gate.request(
                        action_id=request.task_id,
                        capability_id=request.agent_id,
                        session_id=request.scope_id,
                        project_id=request.project_id,
                        risk_level=request.risk_level,
                        resource_refs=[request.resource_ref] if request.resource_ref else None,
                        reason=f"call {call_id} risk_level={request.risk_level.value}",
                    )
                    approval_req_id = approval_req.request_id
                audit.append(self._make_audit(
                    request.project_id, "gateway.risk_blocked", "gateway",
                    request.agent_id, f"call {call_id}",
                    {"risk_level": request.risk_level.value,
                     "approval_request_id": approval_req_id},
                ))
                reason = "risk level requires approval"
                if approval_req_id is not None:
                    reason = f"risk level requires approval; approval_request_id={approval_req_id}"
                return CallResult(
                    call_id=call_id,
                    status=CallStatus.WAITING_APPROVAL,
                    agent_id=request.agent_id,
                    error=reason,
                    audit_events=[a.model_dump(mode="json") for a in audit],
                    started_at=started,
                )
            audit.append(self._make_audit(
                request.project_id, "gateway.risk_approved", "gateway",
                request.agent_id, f"call {call_id}",
                {"risk_level": request.risk_level.value,
                 "action_id": request.task_id},
            ))

        # ---- 4. concurrency / lease check -----------------------------------
        if request.max_concurrency < 1:
            return self._rejected(call_id, request.agent_id, CallStatus.REJECTED_LEASE,
                                  "max_concurrency must be >= 1", audit, started)

        if self._lease_service is not None and request.resource_ref:
            held = self._lease_service.is_held(request.project_id, request.resource_ref)
            if held is not None and held.holder_session_id != request.scope_id:
                audit.append(self._make_audit(
                    request.project_id, "gateway.lease_conflict", "gateway",
                    request.agent_id, request.resource_ref,
                    {"holder_session_id": held.holder_session_id,
                     "lease_id": held.lease_id},
                ))
                return self._rejected(
                    call_id, request.agent_id, CallStatus.REJECTED_LEASE,
                    f"resource {request.resource_ref} held by session "
                    f"{held.holder_session_id}",
                    audit, started,
                )

        # ---- 5. dispatch ----------------------------------------------------
        audit.append(self._make_audit(
            request.project_id, "gateway.dispatch", "gateway",
            request.agent_id, call_id,
            {"params_keys": list(request.params.keys())},
        ))

        try:
            transport_result = await self._transport.call(
                agent_id=request.agent_id,
                params=request.params,
                timeout_seconds=request.timeout_seconds,
            )
        except Exception as exc:
            return self._rejected(call_id, request.agent_id, CallStatus.FAILED,
                                  str(exc), audit, started)

        if transport_result.exit_code != 0:
            return CallResult(
                call_id=call_id,
                status=CallStatus.FAILED,
                agent_id=request.agent_id,
                result=transport_result.raw_output,
                error=transport_result.stderr or f"exit code {transport_result.exit_code}",
                audit_events=[a.model_dump(mode="json") for a in audit],
                started_at=started,
                finished_at=datetime.now(timezone.utc),
            )

        audit.append(self._make_audit(
            request.project_id, "gateway.completed", "gateway",
            request.agent_id, call_id,
            {"result_keys": list(transport_result.raw_output.keys())},
        ))

        return CallResult(
            call_id=call_id,
            status=CallStatus.SUCCEEDED,
            agent_id=request.agent_id,
            result=transport_result.raw_output,
            audit_events=[a.model_dump(mode="json") for a in audit],
            started_at=started,
            finished_at=datetime.now(timezone.utc),
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _rejected(
        self, call_id: str, agent_id: str, status: CallStatus,
        reason: str, audit: list[AuditEvent], started: datetime,
    ) -> CallResult:
        return CallResult(
            call_id=call_id,
            status=status,
            agent_id=agent_id,
            error=reason,
            audit_events=[a.model_dump(mode="json") for a in audit],
            started_at=started,
            finished_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _make_audit(
        project_id: str, event_type: str, actor_type: str,
        actor_id: str, resource_ref: str, details: dict,
    ) -> AuditEvent:
        return AuditEvent(
            audit_id=f"audit-{uuid.uuid4().hex[:12]}",
            project_id=project_id,
            event_type=event_type,
            actor_type=actor_type,
            actor_id=actor_id,
            resource_ref=resource_ref,
            details=details,
        )