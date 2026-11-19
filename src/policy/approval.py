"""HITL Approval Gate — human-in-the-loop state machine for risky actions.

Design decision #5: async approval via CLI commands.
High-risk actions require explicit approval before execution. The gate creates
pending requests; the CLI (or API) approves/rejects them; the orchestrator
checks `is_granted` before dispatching.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from src.domain.models import ApprovalRequest, ApprovalState, RiskLevel
from src.domain.storage import SQLiteStore


class ApprovalGate:
    """Manages the HITL approval workflow for high-risk actions.

    In demo_mode, all requests are auto-approved (skip the human step).

    Usage::

        gate = ApprovalGate(store, demo_mode=False)
        req = gate.request(
            action=action_contract,
            capability_id="exploit-verifier",
            session_id="sess-1",
            resource_refs=["example.com"],
        )
        # ... later (CLI) ...
        gate.approve(req.request_id, decided_by="cli-user")
        # ... orchestrator checks ...
        if gate.is_granted("act-verify"):
            ...  # dispatch
    """

    def __init__(
        self,
        store: SQLiteStore,
        *,
        demo_mode: bool = False,
        ttl_seconds: int = 3600,
    ) -> None:
        self._store = store
        self._demo_mode = demo_mode
        self._ttl_seconds = ttl_seconds

    # ── request lifecycle ──────────────────────────────────────────────

    def request(
        self,
        *,
        action_id: str,
        capability_id: str,
        session_id: str,
        project_id: str,
        risk_level: RiskLevel,
        resource_refs: list[str] | None = None,
        reason: str = "",
    ) -> ApprovalRequest:
        """Create a new approval request. Auto-approves in demo mode."""
        req = ApprovalRequest(
            request_id=f"approval-{uuid.uuid4().hex[:16]}",
            project_id=project_id,
            action_id=action_id,
            capability_id=capability_id,
            risk_level=risk_level,
            resource_refs=resource_refs or [],
            requested_by_session_id=session_id,
            reason=reason or f"High-risk action {action_id} requires approval",
        )

        if self._demo_mode:
            req.state = ApprovalState.APPROVED
            req.decided_at = datetime.now(timezone.utc)
            req.decided_by = "demo-auto"
            # Auto-expire in demo mode is longer
            # No expiry needed; approved is permanent

        self._store.save_approval(req)
        return req

    def approve(self, request_id: str, decided_by: str = "cli") -> ApprovalRequest:
        """Approve a pending request."""
        req = self._get_or_raise(request_id)
        if req.state != ApprovalState.PENDING:
            raise ValueError(f"Approval {request_id} is {req.state.value}, not pending")
        req.state = ApprovalState.APPROVED
        req.decided_at = datetime.now(timezone.utc)
        req.decided_by = decided_by
        self._store.update_approval(req)
        return req

    def reject(self, request_id: str, decided_by: str = "cli",
               reason: str = "") -> ApprovalRequest:
        """Reject a pending request."""
        req = self._get_or_raise(request_id)
        if req.state != ApprovalState.PENDING:
            raise ValueError(f"Approval {request_id} is {req.state.value}, not pending")
        req.state = ApprovalState.REJECTED
        req.decided_at = datetime.now(timezone.utc)
        req.decided_by = decided_by
        if reason:
            req.reason = reason
        self._store.update_approval(req)
        return req

    # ── query ──────────────────────────────────────────────────────────

    def is_granted(self, action_id: str) -> bool:
        """Check if an action has an active approval grant."""
        pending = self._store.list_pending_approvals("")  # scan all
        # Find approved request for this action_id
        import json
        rows = self._store._connection.execute(
            "SELECT payload FROM approval_requests"
        ).fetchall()
        for row in rows:
            req = ApprovalRequest.model_validate(json.loads(row["payload"]))
            if req.action_id == action_id and req.state == ApprovalState.APPROVED:
                return True
        return False

    def pending_for(self, project_id: str) -> list[ApprovalRequest]:
        """List all pending approval requests for a project."""
        return self._store.list_pending_approvals(project_id)

    def sweep_expired(self) -> int:
        """Mark PENDING requests past their TTL as EXPIRED. Returns count swept."""
        import json
        rows = self._store._connection.execute(
            "SELECT payload FROM approval_requests"
        ).fetchall()
        now = datetime.now(timezone.utc)
        swept = 0
        for row in rows:
            req = ApprovalRequest.model_validate(json.loads(row["payload"]))
            if req.state == ApprovalState.PENDING:
                age = now - req.created_at
                if age.total_seconds() > self._ttl_seconds:
                    req.state = ApprovalState.EXPIRED
                    self._store.update_approval(req)
                    swept += 1
        return swept

    # ── internal ───────────────────────────────────────────────────────

    def _get_or_raise(self, request_id: str) -> ApprovalRequest:
        req = self._store.get_approval(request_id)
        if req is None:
            raise ValueError(f"Approval request {request_id} not found")
        return req