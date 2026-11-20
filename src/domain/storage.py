"""Small SQLite persistence boundary for the first prototype."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import TypeVar

from .models import (
    AgentCapability,
    ApprovalRequest,
    AuditEvent,
    BlackboardEvent,
    BlackboardFact,
    Evidence,
    ExecutionSession,
    Lease,
    Project,
    Scope,
    TaskNode,
)


ModelT = TypeVar("ModelT")


class SQLiteStore:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.database_path)
        self._connection.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS capabilities (
                capability_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS facts (
                fact_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS projects (
                project_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scopes (
                scope_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS leases (
                lease_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blackboard_events (
                event_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                audit_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approval_requests (
                request_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ptt_trees (
                project_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            """
        )
        self._connection.commit()

    def _save(self, table: str, identifier_column: str, identifier: str, payload: dict) -> None:
        try:
            self._connection.execute(
                f"INSERT INTO {table} ({identifier_column}, payload) VALUES (?, ?)",
                (identifier, json.dumps(payload, ensure_ascii=False)),
            )
            self._connection.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"{identifier_column.removesuffix('_id')} {identifier} already exists") from exc

    def _get(self, table: str, identifier_column: str, identifier: str, model_type: type[ModelT]) -> ModelT | None:
        row = self._connection.execute(
            f"SELECT payload FROM {table} WHERE {identifier_column} = ?",
            (identifier,),
        ).fetchone()
        if row is None:
            return None
        return model_type.model_validate(json.loads(row["payload"]))  # type: ignore[attr-defined]

    def save_task(self, task: TaskNode) -> None:
        self._save("tasks", "task_id", task.task_id, task.model_dump(mode="json"))

    def get_task(self, task_id: str) -> TaskNode | None:
        return self._get("tasks", "task_id", task_id, TaskNode)

    def save_capability(self, capability: AgentCapability) -> None:
        self._save("capabilities", "capability_id", capability.capability_id, capability.model_dump(mode="json"))

    def get_capability(self, capability_id: str) -> AgentCapability | None:
        return self._get("capabilities", "capability_id", capability_id, AgentCapability)

    def delete_capability(self, capability_id: str) -> None:
        cursor = self._connection.execute(
            "DELETE FROM capabilities WHERE capability_id = ?", (capability_id,)
        )
        if cursor.rowcount != 1:
            raise ValueError(f"capability {capability_id} does not exist")
        self._connection.commit()

    def list_capabilities(self) -> list[AgentCapability]:
        rows = self._connection.execute("SELECT payload FROM capabilities ORDER BY capability_id").fetchall()
        return [AgentCapability.model_validate(json.loads(row["payload"])) for row in rows]

    def save_evidence(self, evidence: Evidence) -> None:
        self._save("evidence", "evidence_id", evidence.evidence_id, evidence.model_dump(mode="json"))

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        return self._get("evidence", "evidence_id", evidence_id, Evidence)

    def save_fact(self, fact: BlackboardFact) -> None:
        self._save("facts", "fact_id", fact.fact_id, fact.model_dump(mode="json"))

    def update_fact(self, fact: BlackboardFact) -> None:
        cursor = self._connection.execute(
            "UPDATE facts SET payload = ? WHERE fact_id = ?",
            (json.dumps(fact.model_dump(mode="json"), ensure_ascii=False), fact.fact_id),
        )
        if cursor.rowcount != 1:
            raise ValueError(f"fact {fact.fact_id} does not exist")
        self._connection.commit()

    def record_fact_event(self, fact: BlackboardFact, event: BlackboardEvent, *, exists: bool) -> None:
        with self._connection:
            if exists:
                cursor = self._connection.execute(
                    "UPDATE facts SET payload = ? WHERE fact_id = ?",
                    (json.dumps(fact.model_dump(mode="json"), ensure_ascii=False), fact.fact_id),
                )
                if cursor.rowcount != 1:
                    raise ValueError(f"fact {fact.fact_id} does not exist")
            else:
                self._connection.execute(
                    "INSERT INTO facts (fact_id, payload) VALUES (?, ?)",
                    (fact.fact_id, json.dumps(fact.model_dump(mode="json"), ensure_ascii=False)),
                )
            self._connection.execute(
                "INSERT INTO blackboard_events (event_id, payload) VALUES (?, ?)",
                (event.event_id, json.dumps(event.model_dump(mode="json"), ensure_ascii=False)),
            )

    def get_fact(self, fact_id: str) -> BlackboardFact | None:
        return self._get("facts", "fact_id", fact_id, BlackboardFact)

    def list_facts(self, project_id: str) -> list[BlackboardFact]:
        rows = self._connection.execute("SELECT payload FROM facts ORDER BY fact_id").fetchall()
        return [
            fact
            for row in rows
            if (fact := BlackboardFact.model_validate(json.loads(row["payload"]))).project_id == project_id
        ]

    def save_project(self, project: Project) -> None:
        self._save("projects", "project_id", project.project_id, project.model_dump(mode="json"))

    def get_project(self, project_id: str) -> Project | None:
        return self._get("projects", "project_id", project_id, Project)

    def save_scope(self, scope: Scope) -> None:
        self._save("scopes", "scope_id", scope.scope_id, scope.model_dump(mode="json"))

    def get_scope(self, scope_id: str) -> Scope | None:
        return self._get("scopes", "scope_id", scope_id, Scope)

    def save_session(self, session: ExecutionSession) -> None:
        self._save("sessions", "session_id", session.session_id, session.model_dump(mode="json"))

    def get_session(self, session_id: str) -> ExecutionSession | None:
        return self._get("sessions", "session_id", session_id, ExecutionSession)

    def save_lease(self, lease: Lease) -> None:
        self._save("leases", "lease_id", lease.lease_id, lease.model_dump(mode="json"))

    def get_lease(self, lease_id: str) -> Lease | None:
        return self._get("leases", "lease_id", lease_id, Lease)

    def save_blackboard_event(self, event: BlackboardEvent) -> None:
        self._save("blackboard_events", "event_id", event.event_id, event.model_dump(mode="json"))

    def get_blackboard_event(self, event_id: str) -> BlackboardEvent | None:
        return self._get("blackboard_events", "event_id", event_id, BlackboardEvent)

    def list_blackboard_events(self, project_id: str, after_sequence: int = 0) -> list[BlackboardEvent]:
        rows = self._connection.execute("SELECT payload FROM blackboard_events").fetchall()
        events = [
            event
            for row in rows
            if (event := BlackboardEvent.model_validate(json.loads(row["payload"]))).project_id == project_id
            and event.sequence > after_sequence
        ]
        return sorted(events, key=lambda event: event.sequence)

    def save_audit_event(self, event: AuditEvent) -> None:
        self._save("audit_events", "audit_id", event.audit_id, event.model_dump(mode="json"))

    def get_audit_event(self, audit_id: str) -> AuditEvent | None:
        return self._get("audit_events", "audit_id", audit_id, AuditEvent)

    # ── lease query methods ─────────────────────────────────────────────────

    def list_leases_for_resource(self, project_id: str, resource_ref: str) -> list[Lease]:
        rows = self._connection.execute("SELECT payload FROM leases").fetchall()
        return [
            lease
            for row in rows
            if (lease := Lease.model_validate(json.loads(row["payload"]))).project_id == project_id
            and lease.resource_ref == resource_ref
        ]

    def list_leases_for_session(self, session_id: str) -> list[Lease]:
        rows = self._connection.execute("SELECT payload FROM leases").fetchall()
        return [
            lease
            for row in rows
            if (lease := Lease.model_validate(json.loads(row["payload"]))).holder_session_id == session_id
        ]

    def delete_lease(self, lease_id: str) -> None:
        cursor = self._connection.execute(
            "DELETE FROM leases WHERE lease_id = ?", (lease_id,)
        )
        if cursor.rowcount == 0:
            raise ValueError(f"lease {lease_id} does not exist")
        self._connection.commit()

    def update_lease(self, lease: Lease) -> None:
        cursor = self._connection.execute(
            "UPDATE leases SET payload = ? WHERE lease_id = ?",
            (json.dumps(lease.model_dump(mode="json"), ensure_ascii=False), lease.lease_id),
        )
        if cursor.rowcount != 1:
            raise ValueError(f"lease {lease.lease_id} does not exist")
        self._connection.commit()

    def list_leases(self, project_id: str) -> list[Lease]:
        rows = self._connection.execute("SELECT payload FROM leases").fetchall()
        return [
            lease
            for row in rows
            if (lease := Lease.model_validate(json.loads(row["payload"]))).project_id == project_id
        ]

    def list_all_leases(self) -> list[Lease]:
        """Return every lease row regardless of project (service-level sweeps)."""
        rows = self._connection.execute("SELECT payload FROM leases").fetchall()
        return [Lease.model_validate(json.loads(row["payload"])) for row in rows]

    # ── approval methods ───────────────────────────────────────────────────

    def save_approval(self, request: ApprovalRequest) -> None:
        self._save("approval_requests", "request_id", request.request_id,
                    request.model_dump(mode="json"))

    def get_approval(self, request_id: str) -> ApprovalRequest | None:
        return self._get("approval_requests", "request_id", request_id, ApprovalRequest)

    def list_pending_approvals(self, project_id: str) -> list[ApprovalRequest]:
        rows = self._connection.execute("SELECT payload FROM approval_requests").fetchall()
        return [
            req
            for row in rows
            if (req := ApprovalRequest.model_validate(json.loads(row["payload"]))).project_id == project_id
            and req.state.value == "pending"
        ]

    def update_approval(self, request: ApprovalRequest) -> None:
        cursor = self._connection.execute(
            "UPDATE approval_requests SET payload = ? WHERE request_id = ?",
            (json.dumps(request.model_dump(mode="json"), ensure_ascii=False), request.request_id),
        )
        if cursor.rowcount != 1:
            raise ValueError(f"approval {request.request_id} does not exist")
        self._connection.commit()

    def update_session(self, session: ExecutionSession) -> None:
        cursor = self._connection.execute(
            "UPDATE sessions SET payload = ? WHERE session_id = ?",
            (json.dumps(session.model_dump(mode="json"), ensure_ascii=False), session.session_id),
        )
        if cursor.rowcount != 1:
            raise ValueError(f"session {session.session_id} does not exist")
        self._connection.commit()

    # ── ptt tree persistence ────────────────────────────────────────────────

    def save_ptt_tree(self, project_id: str, tree_payload: dict) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO ptt_trees (project_id, payload) VALUES (?, ?)",
            (project_id, json.dumps(tree_payload, ensure_ascii=False)),
        )
        self._connection.commit()

    def get_ptt_tree(self, project_id: str) -> dict | None:
        row = self._connection.execute(
            "SELECT payload FROM ptt_trees WHERE project_id = ?", (project_id,)
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["payload"])

    def close(self) -> None:
        self._connection.close()
