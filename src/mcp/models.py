"""MCP Gateway request / response and call status models."""

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.domain.models import RiskLevel


class CallStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED_SCOPE = "rejected_scope"
    REJECTED_RISK = "rejected_risk"
    REJECTED_LEASE = "rejected_lease"
    WAITING_APPROVAL = "waiting_approval"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class CallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1)
    scope_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.LOW
    timeout_seconds: int = Field(default=300, ge=1, le=86_400)
    max_concurrency: int = Field(default=1, ge=1, le=64)
    resource_ref: str | None = Field(
        default=None,
        description="Optional resource reference for lease checking (e.g. 'asset:10.10.20.15').",
    )


class CallResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    call_id: str = Field(min_length=1)
    status: CallStatus
    agent_id: str = Field(min_length=1)
    result: dict[str, Any] | None = None
    error: str | None = None
    audit_events: list[dict[str, Any]] = Field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None