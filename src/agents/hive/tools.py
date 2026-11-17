"""HiveTool — CrewAI-compatible sync wrapper that routes through MCPGateway + captures observations.

Each HiveTool is a ``crewai.tools.BaseTool`` subclass so CrewAI accepts it as
an Agent tool.  Internally it:
1. Builds a CallRequest and routes through the real MCPGateway security chain.
2. Bridges async → sync for CrewAI compatibility.
3. Captures tool output as Evidence and queues it for blackboard ingestion.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from crewai.tools import BaseTool

from src.domain.models import Evidence, RiskLevel
from src.mcp.gateway import MCPGateway
from src.mcp.models import CallRequest, CallResult, CallStatus

logger = logging.getLogger("hive.tools")

# Type alias for async tool functions
AsyncTool = Callable[..., Awaitable[dict[str, Any]]]
# Type alias for observation factories
ObsFactory = Callable[..., list[dict[str, Any]]]

# Keys whose values must be lists (tool functions expect list[str])
_LIST_KEYS = frozenset({"targets", "ports", "record_types", "fingerprints"})


@dataclass
class CrewContext:
    """Shared context passed through one crew run — carries identities + pending evidence."""

    project_id: str
    scope_id: str
    session_id: str
    task_id: str
    pending_evidence: list[Evidence] = field(default_factory=list)

    def make_evidence(
        self,
        agent_id: str,
        tool_output: dict[str, Any],
        observations: list[dict[str, Any]],
    ) -> Evidence:
        return Evidence(
            evidence_id=f"ev-{uuid.uuid4().hex[:12]}",
            project_id=self.project_id,
            session_id=self.session_id,
            task_id=self.task_id,
            agent_id=agent_id,
            kind="agent.result",
            raw_payload={
                "tool_output": tool_output,
                "observations": observations,
            },
        )


class HiveTool(BaseTool):
    """A CrewAI-compatible tool that routes through the MCPGateway security chain.

    Inherits from ``crewai.tools.BaseTool`` so CrewAI accepts it as an Agent tool.
    """

    # ── BaseTool fields (declared as type annotations for Pydantic) ──
    name: str = ""
    description: str = ""

    # ── internal state (not part of BaseTool schema) ──
    _func: AsyncTool | None = None
    _agent_id: str = ""
    _risk_level: RiskLevel = RiskLevel.LOW
    _gateway: MCPGateway | None = None
    _ctx: CrewContext | None = None
    _observation_factory: ObsFactory | None = None
    _arg_map: dict[str, str] | None = None

    def __init__(
        self,
        *,
        name: str,
        description: str,
        func: AsyncTool,
        agent_id: str,
        risk_level: RiskLevel,
        gateway: MCPGateway,
        ctx: CrewContext,
        observation_factory: ObsFactory | None = None,
        arg_map: dict[str, str] | None = None,
    ) -> None:
        super().__init__(name=name, description=description)
        self._func = func
        self._agent_id = agent_id
        self._risk_level = risk_level
        self._gateway = gateway
        self._ctx = ctx
        self._observation_factory = observation_factory
        self._arg_map = arg_map or {}

    # ── CrewAI BaseTool protocol ─────────────────────────────────────
    def _run(self, **kwargs: Any) -> Any:
        """Sync entry point — CrewAI calls this."""
        return _run_async(self._call_async(**kwargs))

    async def _call_async(self, **kwargs: Any) -> dict[str, Any]:
        # Map CrewAI kwargs to gateway params
        params: dict[str, Any] = {"_tool_name": self.name}
        if self._arg_map:
            for crew_key, gw_key in self._arg_map.items():
                if crew_key in kwargs:
                    params[gw_key] = kwargs.pop(crew_key)
        # Pass any unmapped kwargs directly
        params.update(kwargs)

        # Wrap string values in lists for keys that expect list[str]
        for key in _LIST_KEYS:
            if key in params and isinstance(params[key], str):
                params[key] = [params[key]]

        request = CallRequest(
            agent_id=self._agent_id,
            scope_id=self._ctx.scope_id if self._ctx else "default",
            task_id=self._ctx.task_id if self._ctx else "default",
            project_id=self._ctx.project_id if self._ctx else "default",
            params=params,
            risk_level=self._risk_level,
        )

        if self._gateway is None:
            return {"status": "error", "error": "gateway not configured"}

        try:
            result: CallResult = await self._gateway.execute(request)
        except Exception as exc:
            logger.error("Gateway execution failed: %s", exc)
            return {"status": "error", "error": str(exc)}

        # Handle non-success statuses
        if result.status == CallStatus.WAITING_APPROVAL:
            return {"status": "waiting_approval", "risk_level": self._risk_level.value}
        if result.status in (
            CallStatus.REJECTED_SCOPE,
            CallStatus.REJECTED_RISK,
            CallStatus.REJECTED_LEASE,
        ):
            return {"status": result.status.value, "error": result.error}
        if result.status == CallStatus.FAILED:
            return {"status": "failed", "error": result.error}

        # Success: capture observations
        tool_output = result.result or {}
        observations: list[dict[str, Any]] = []

        if self._observation_factory is not None:
            try:
                observations = self._observation_factory(tool_output, **params)
            except Exception as exc:
                logger.warning("Observation factory failed: %s", exc)

        if observations and self._ctx is not None:
            evidence = self._ctx.make_evidence(
                self._agent_id, tool_output, observations,
            )
            self._ctx.pending_evidence.append(evidence)

        return tool_output


# ── async → sync bridge ───────────────────────────────────────────────

def _run_async(coro: Awaitable[Any]) -> Any:
    """Run an async coroutine synchronously, handling nested event loops."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    # Already inside a loop — use a new event loop in a thread
    import concurrent.futures

    def _run_in_new_loop() -> Any:
        new_loop = asyncio.new_event_loop()
        try:
            return new_loop.run_until_complete(coro)
        finally:
            new_loop.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_run_in_new_loop)
        return future.result(timeout=300)


# ── builder helper ─────────────────────────────────────────────────────

def make_hive_tool(
    *,
    name: str,
    description: str,
    func: AsyncTool,
    agent_id: str,
    risk_level: RiskLevel,
    gateway: MCPGateway,
    ctx: CrewContext,
    observation_factory: ObsFactory | None = None,
    arg_map: dict[str, str] | None = None,
) -> HiveTool:
    """Convenience factory — same as HiveTool(...) but returns the instance."""
    return HiveTool(
        name=name,
        description=description,
        func=func,
        agent_id=agent_id,
        risk_level=risk_level,
        gateway=gateway,
        ctx=ctx,
        observation_factory=observation_factory,
        arg_map=arg_map,
    )