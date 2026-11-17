"""MCP Gateway — validates, audits, and dispatches Agent calls."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from src.agents.registry import AgentRegistry
from src.domain.models import AuditEvent, RiskLevel
from src.mcp.models import CallRequest, CallResult, CallStatus
from src.mcp.transport import Transport
from src.policy.guard import PolicyGuard


class MCPGateway:
    def __init__(
        self,
        registry: AgentRegistry,
        guard: PolicyGuard,
        transport: Transport,
    ) -> None:
        self._registry = registry
        self._guard = guard
        self._transport = transport

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
            audit.append(self._make_audit(
                request.project_id, "gateway.risk_blocked", "gateway",
                request.agent_id, f"call {call_id}",
                {"risk_level": request.risk_level.value},
            ))
            return CallResult(
                call_id=call_id,
                status=CallStatus.WAITING_APPROVAL,
                agent_id=request.agent_id,
                audit_events=[a.model_dump(mode="json") for a in audit],
                started_at=started,
            )

        # ---- 4. concurrency / lease check (stub) ----------------------------
        # Full lease check in phase 5; here we just note the limit.
        if request.max_concurrency < 1:
            return self._rejected(call_id, request.agent_id, CallStatus.REJECTED_LEASE,
                                  "max_concurrency must be >= 1", audit, started)

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