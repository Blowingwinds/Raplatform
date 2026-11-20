"""Lease Service — acquire, release, and manage resource leases.

Design decision #3: target-level leases with suspend-wait strategy.
A lease prevents two sessions from operating on the same resource concurrently.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from src.domain.models import Lease, LeaseStatus
from src.domain.storage import SQLiteStore


@dataclass
class LeaseAcquireResult:
    acquired: bool
    lease: Lease | None = None
    conflict: Lease | None = None
    strategy: str = ""  # "granted" | "suspend_wait" | "renewed"


class LeaseService:
    """Manages resource leases for the hive orchestrator.

    Usage::

        store = SQLiteStore(":memory:")
        svc = LeaseService(store)
        result = svc.acquire(
            project_id="p1", resource_ref="example.com",
            session_id="s1", action_id="act-1",
        )
        if result.acquired:
            ...  # proceed
        else:
            ...  # suspend_wait — retry next round
    """

    def __init__(self, store: SQLiteStore) -> None:
        self._store = store

    # ── acquire / release ──────────────────────────────────────────────

    def acquire(
        self,
        *,
        project_id: str,
        resource_ref: str,
        session_id: str,
        action_id: str,
        ttl_seconds: int = 600,
        capability_id: str | None = None,
    ) -> LeaseAcquireResult:
        """Try to acquire a lease on a resource. Returns decision + lease or conflict."""
        # Check for existing active leases on this resource
        existing = self._store.list_leases_for_resource(project_id, resource_ref)
        active = [
            l for l in existing
            if l.status == LeaseStatus.ACTIVE and l.expires_at > datetime.now(timezone.utc)
        ]

        # Same session already holds it — renew
        for active_lease in active:
            if active_lease.holder_session_id == session_id:
                active_lease.expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
                if capability_id:
                    active_lease.capability_id = capability_id
                self._store.update_lease(active_lease)
                return LeaseAcquireResult(
                    acquired=True, lease=active_lease, strategy="renewed",
                )

        # Different session holds it — conflict
        if active:
            return LeaseAcquireResult(
                acquired=False, conflict=active[0], strategy="suspend_wait",
            )

        # No conflicts — grant new lease
        lease = Lease(
            lease_id=f"lease-{uuid.uuid4().hex[:16]}",
            project_id=project_id,
            resource_ref=resource_ref,
            holder_session_id=session_id,
            action_id=action_id,
            capability_id=capability_id,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
            status=LeaseStatus.ACTIVE,
        )
        self._store.save_lease(lease)
        return LeaseAcquireResult(acquired=True, lease=lease, strategy="granted")

    def release(self, lease_id: str) -> None:
        """Release a lease (mark as RELEASED)."""
        lease = self._store.get_lease(lease_id)
        if lease is None:
            return
        lease.status = LeaseStatus.RELEASED
        self._store.update_lease(lease)

    def release_for_action(self, action_id: str) -> None:
        """Release all leases held by a specific action."""
        for lease in self._store.list_all_leases():
            if lease.action_id == action_id and lease.status == LeaseStatus.ACTIVE:
                lease.status = LeaseStatus.RELEASED
                self._store.update_lease(lease)

    def renew(self, lease_id: str, ttl_seconds: int = 600) -> Lease | None:
        """Extend a lease's expiry."""
        lease = self._store.get_lease(lease_id)
        if lease is None:
            return None
        lease.expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        self._store.update_lease(lease)
        return lease

    # ── query ──────────────────────────────────────────────────────────

    def is_held(self, project_id: str, resource_ref: str) -> Lease | None:
        """Return the active lease on a resource, or None if free."""
        existing = self._store.list_leases_for_resource(project_id, resource_ref)
        active = [
            l for l in existing
            if l.status == LeaseStatus.ACTIVE and l.expires_at > datetime.now(timezone.utc)
        ]
        return active[0] if active else None

    def active_count_for_capability(
        self, capability_id: str, project_id: str | None = None,
    ) -> int:
        """Count active, unexpired leases genuinely held by *capability_id*.

        Leases carry an explicit ``capability_id`` set at acquire time; leases
        without one are ignored so unrelated holds never inflate the count.
        """
        now = datetime.now(timezone.utc)
        count = 0
        for lease in self._store.list_all_leases():
            if lease.status != LeaseStatus.ACTIVE or lease.expires_at <= now:
                continue
            if lease.capability_id != capability_id:
                continue
            if project_id is not None and lease.project_id != project_id:
                continue
            count += 1
        return count

    def sweep_expired(self) -> int:
        """Mark all expired leases as EXPIRED. Returns count swept."""
        now = datetime.now(timezone.utc)
        swept = 0
        for lease in self._store.list_all_leases():
            if lease.status == LeaseStatus.ACTIVE and lease.expires_at <= now:
                lease.status = LeaseStatus.EXPIRED
                self._store.update_lease(lease)
                swept += 1
        return swept