"""Tests for LeaseService."""

from datetime import datetime, timedelta, timezone

import pytest

from src.domain.lease_service import LeaseService
from src.domain.models import Lease, LeaseStatus
from src.domain.storage import SQLiteStore


@pytest.fixture
def store():
    s = SQLiteStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def svc(store):
    return LeaseService(store)


class TestLeaseAcquire:
    def test_first_acquire_grants(self, svc):
        result = svc.acquire(
            project_id="p1", resource_ref="example.com",
            session_id="s1", action_id="act-1",
        )
        assert result.acquired is True
        assert result.strategy == "granted"
        assert result.lease is not None
        assert result.lease.resource_ref == "example.com"
        assert result.lease.status == LeaseStatus.ACTIVE

    def test_same_session_renews(self, svc):
        r1 = svc.acquire(project_id="p1", resource_ref="x.com",
                         session_id="s1", action_id="act-1")
        r2 = svc.acquire(project_id="p1", resource_ref="x.com",
                         session_id="s1", action_id="act-2")
        assert r2.acquired is True
        assert r2.strategy == "renewed"

    def test_different_session_suspend_wait(self, svc):
        r1 = svc.acquire(project_id="p1", resource_ref="x.com",
                         session_id="s1", action_id="act-1")
        assert r1.acquired
        r2 = svc.acquire(project_id="p1", resource_ref="x.com",
                         session_id="s2", action_id="act-2")
        assert r2.acquired is False
        assert r2.strategy == "suspend_wait"
        assert r2.conflict is not None

    def test_release_then_reacquire(self, svc):
        r1 = svc.acquire(project_id="p1", resource_ref="x.com",
                         session_id="s1", action_id="act-1")
        svc.release(r1.lease.lease_id)
        r2 = svc.acquire(project_id="p1", resource_ref="x.com",
                         session_id="s2", action_id="act-2")
        assert r2.acquired is True
        assert r2.strategy == "granted"

    def test_release_for_action(self, svc):
        svc.acquire(project_id="p1", resource_ref="x.com",
                    session_id="s1", action_id="act-target")
        svc.release_for_action("act-target")
        # After release, re-acquire should work
        r = svc.acquire(project_id="p1", resource_ref="x.com",
                        session_id="s2", action_id="act-new")
        assert r.acquired is True


class TestLeaseQuery:
    def test_is_held_active(self, svc):
        svc.acquire(project_id="p1", resource_ref="x.com",
                    session_id="s1", action_id="act-1")
        held = svc.is_held("p1", "x.com")
        assert held is not None
        assert held.resource_ref == "x.com"

    def test_is_held_free(self, svc):
        held = svc.is_held("p1", "unused.com")
        assert held is None

    def test_is_held_after_release(self, svc):
        r = svc.acquire(project_id="p1", resource_ref="x.com",
                        session_id="s1", action_id="act-1")
        svc.release(r.lease.lease_id)
        held = svc.is_held("p1", "x.com")
        assert held is None


class TestLeaseSweep:
    def test_sweep_expired(self, svc):
        r = svc.acquire(project_id="p1", resource_ref="x.com",
                        session_id="s1", action_id="act-1", ttl_seconds=1)
        # Manually expire
        r.lease.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        import json
        svc._store._connection.execute(
            "UPDATE leases SET payload = ? WHERE lease_id = ?",
            (json.dumps(r.lease.model_dump(mode="json"), ensure_ascii=False),
             r.lease.lease_id),
        )
        svc._store._connection.commit()
        swept = svc.sweep_expired()
        assert swept == 1
        held = svc.is_held("p1", "x.com")
        assert held is None