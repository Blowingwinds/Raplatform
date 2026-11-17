"""Core contracts shared by planning, execution, and blackboard modules."""

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskLevel(StrEnum):
    GOAL = "goal"
    TACTIC = "tactic"
    TECHNIQUE = "technique"
    ACTION = "action"


class TaskStatus(StrEnum):
    PLANNED = "planned"
    READY = "ready"
    WAITING_APPROVAL = "waiting_approval"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class SessionStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DomainModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Project(DomainModel):
    project_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = ""


class Scope(DomainModel):
    scope_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    target_type: str = Field(min_length=1)
    target: str = Field(min_length=1)
    authorization_ref: str = Field(min_length=1)


class ExecutionSession(DomainModel):
    session_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    status: SessionStatus = SessionStatus.CREATED


class Lease(DomainModel):
    lease_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    resource_ref: str = Field(min_length=1)
    holder_session_id: str = Field(min_length=1)
    expires_at: datetime


class BlackboardEvent(DomainModel):
    event_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    fact_id: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    fact_version: int = Field(ge=1)
    sequence: int = Field(default=1, ge=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditEvent(DomainModel):
    audit_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    actor_type: str = Field(min_length=1)
    actor_id: str = Field(min_length=1)
    resource_ref: str = Field(min_length=1)
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ActionConstraints(DomainModel):
    authorized_scope_only: bool = True
    max_concurrency: int = Field(default=1, ge=1, le=64)
    timeout_seconds: int = Field(default=300, ge=1, le=86_400)


class TaskNode(DomainModel):
    task_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    parent_task_id: str | None = None
    level: TaskLevel
    name: str = Field(min_length=1)
    technique_id: str | None = None
    intent: str = Field(min_length=1)
    target_refs: list[str] = Field(min_length=1)
    constraints: ActionConstraints = Field(default_factory=ActionConstraints)
    expected_outputs: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    status: TaskStatus = TaskStatus.PLANNED

    @field_validator("expected_outputs")
    @classmethod
    def action_outputs_are_required(cls, value: list[str], info: Any) -> list[str]:
        if info.data.get("level") is TaskLevel.ACTION and not value:
            raise ValueError("action tasks require at least one expected output")
        return value


class AgentCapability(DomainModel):
    capability_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    techniques: list[str] = Field(min_length=1)
    target_types: list[str] = Field(min_length=1)
    input_schema: str = Field(min_length=1)
    output_schema: str = Field(min_length=1)
    risk_level: RiskLevel
    side_effects: list[str] = Field(default_factory=list)
    max_concurrency: int = Field(default=1, ge=1, le=64)


class BlackboardFact(DomainModel):
    fact_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    fact_type: str = Field(min_length=1)
    asset_ref: str = Field(min_length=1)
    data: dict[str, Any]
    confidence: float = Field(ge=0.0, le=1.0)
    source_agent: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    evidence_ref: str = Field(min_length=1)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: int = Field(default=1, ge=1)


class Evidence(DomainModel):
    evidence_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    raw_payload: dict[str, Any]
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
