"""Tests for ApprovalGate HITL state machine."""

import pytest

from src.domain.models import ApprovalState, RiskLevel
from src.domain.storage import SQLiteStore
from src.policy.approval import ApprovalGate


@pytest.fixture
def store():
    s = SQLiteStore(":memory:")
    yield s
    s.close()


class TestApprovalGate:
    def test_request_creates_pending(self, store):
        gate = ApprovalGate(store, demo_mode=False)
        req = gate.request(
            action_id="act-verify",
            capability_id="exploit-verifier",
            session_id="s1",
            project_id="p1",
            risk_level=RiskLevel.HIGH,
        )
        assert req.state == ApprovalState.PENDING
        assert req.action_id == "act-verify"

    def test_demo_mode_auto_approves(self, store):
        gate = ApprovalGate(store, demo_mode=True)
        req = gate.request(
            action_id="act-1", capability_id="c1",
            session_id="s1", project_id="p1",
            risk_level=RiskLevel.HIGH,
        )
        assert req.state == ApprovalState.APPROVED
        assert req.decided_by == "demo-auto"

    def test_approve_from_pending(self, store):
        gate = ApprovalGate(store, demo_mode=False)
        req = gate.request(
            action_id="act-1", capability_id="c1",
            session_id="s1", project_id="p1",
            risk_level=RiskLevel.HIGH,
        )
        approved = gate.approve(req.request_id, decided_by="tester")
        assert approved.state == ApprovalState.APPROVED
        assert approved.decided_by == "tester"

    def test_reject_from_pending(self, store):
        gate = ApprovalGate(store, demo_mode=False)
        req = gate.request(
            action_id="act-1", capability_id="c1",
            session_id="s1", project_id="p1",
            risk_level=RiskLevel.HIGH,
        )
        rejected = gate.reject(req.request_id, reason="too risky")
        assert rejected.state == ApprovalState.REJECTED
        assert rejected.reason == "too risky"

    def test_is_granted_after_approve(self, store):
        gate = ApprovalGate(store, demo_mode=False)
        req = gate.request(
            action_id="act-verify", capability_id="c1",
            session_id="s1", project_id="p1",
            risk_level=RiskLevel.HIGH,
        )
        assert not gate.is_granted("act-verify")
        gate.approve(req.request_id)
        assert gate.is_granted("act-verify")

    def test_is_granted_after_reject(self, store):
        gate = ApprovalGate(store, demo_mode=False)
        req = gate.request(
            action_id="act-1", capability_id="c1",
            session_id="s1", project_id="p1",
            risk_level=RiskLevel.HIGH,
        )
        gate.reject(req.request_id)
        assert not gate.is_granted("act-1")

    def test_pending_for(self, store):
        gate = ApprovalGate(store, demo_mode=False)
        gate.request(action_id="a1", capability_id="c1",
                     session_id="s1", project_id="p1",
                     risk_level=RiskLevel.HIGH)
        gate.request(action_id="a2", capability_id="c2",
                     session_id="s1", project_id="p1",
                     risk_level=RiskLevel.HIGH)
        pending = gate.pending_for("p1")
        assert len(pending) == 2

    def test_sweep_expired(self, store):
        gate = ApprovalGate(store, demo_mode=False, ttl_seconds=1)
        req = gate.request(
            action_id="act-1", capability_id="c1",
            session_id="s1", project_id="p1",
            risk_level=RiskLevel.HIGH,
        )
        # Manually backdate created_at
        from datetime import datetime, timedelta, timezone
        req.created_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        import json
        store._connection.execute(
            "UPDATE approval_requests SET payload = ? WHERE request_id = ?",
            (json.dumps(req.model_dump(mode="json"), ensure_ascii=False),
             req.request_id),
        )
        store._connection.commit()
        swept = gate.sweep_expired()
        assert swept == 1

    def test_cannot_approve_already_decided(self, store):
        gate = ApprovalGate(store, demo_mode=False)
        req = gate.request(
            action_id="act-1", capability_id="c1",
            session_id="s1", project_id="p1",
            risk_level=RiskLevel.HIGH,
        )
        gate.approve(req.request_id)
        with pytest.raises(ValueError, match="not pending"):
            gate.approve(req.request_id)

    def test_unknown_request_raises(self, store):
        gate = ApprovalGate(store)
        with pytest.raises(ValueError, match="not found"):
            gate.approve("nonexistent")