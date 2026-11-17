"""MCP Transport abstraction — Mock (offline testing), Subprocess, and InProcess."""

from __future__ import annotations

import asyncio
import json
import subprocess
import uuid
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TransportResult:
    raw_output: dict[str, Any]
    exit_code: int = 0
    stderr: str = ""


class Transport(ABC):
    """Abstract transport — agents are called through this interface."""

    @abstractmethod
    async def call(self, agent_id: str, params: dict[str, Any],
                   timeout_seconds: int = 300) -> TransportResult:
        ...

    @abstractmethod
    async def cancel(self, call_id: str) -> None:
        ...


@dataclass
class MockTransport(Transport):
    """Returns canned responses keyed by agent_id. Used for offline tests."""

    canned: dict[str, TransportResult] = field(default_factory=dict)
    last_cancelled: str | None = field(default=None, init=False)

    async def call(self, agent_id: str, params: dict[str, Any],
                   timeout_seconds: int = 300) -> TransportResult:
        if agent_id in self.canned:
            return self.canned[agent_id]
        return TransportResult(
            raw_output={"observations": [], "_mock": True, "_agent": agent_id,
                        "_params": params},
        )

    async def cancel(self, call_id: str) -> None:
        self.last_cancelled = call_id


class SubprocessTransport(Transport):
    """Launches a real MCP server as a subprocess, communicates via stdio JSON-RPC.

    Each agent is an independent MCP stdio server. The transport:
      1. Launches the agent's command (e.g. ``python -m agents.info_gatherer``)
      2. Sends a JSON-RPC ``tools/call`` request
      3. Collects the response and returns it as a TransportResult
    """

    def __init__(self, agent_commands: dict[str, list[str]] | None = None) -> None:
        self._commands = agent_commands or {}
        self._running: dict[str, asyncio.subprocess.Process] = {}

    async def call(self, agent_id: str, params: dict[str, Any],
                   timeout_seconds: int = 300) -> TransportResult:
        command = self._commands.get(agent_id)
        if command is None:
            return TransportResult(
                raw_output={"error": f"no command configured for agent {agent_id}"},
                exit_code=1,
                stderr=f"unknown agent: {agent_id}",
            )

        call_id = str(uuid.uuid4())[:8]
        request = json.dumps({
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": agent_id, "arguments": params},
        })

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._running[agent_id] = proc

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=request.encode("utf-8")),
                timeout=timeout_seconds,
            )

            raw_output: dict[str, Any] = {"raw": stdout.decode("utf-8", errors="replace")}
            try:
                raw_output = json.loads(stdout.decode("utf-8"))
            except json.JSONDecodeError:
                pass

            return TransportResult(
                raw_output=raw_output,
                exit_code=proc.returncode or 0,
                stderr=stderr.decode("utf-8", errors="replace"),
            )
        except asyncio.TimeoutError:
            return TransportResult(
                raw_output={"error": "timeout"},
                exit_code=-1,
                stderr=f"call timed out after {timeout_seconds}s",
            )
        finally:
            self._running.pop(agent_id, None)

    async def cancel(self, call_id: str) -> None:
        for agent_id, proc in list(self._running.items()):
            try:
                proc.kill()
            except Exception:
                pass


class InProcessTransport(Transport):
    """Calls async Python functions directly — no subprocess.

    Maps tool name (or agent_id) to an async callable.  Used by the Hive so
    tools go through the real Gateway security chain without subprocess overhead.

    Lookup order: ``params["_tool_name"]`` → ``agent_id``.
    """

    def __init__(
        self,
        handlers: dict[str, Callable[..., Awaitable[dict[str, Any]]]] | None = None,
    ) -> None:
        self._handlers: dict[str, Callable[..., Awaitable[dict[str, Any]]]] = handlers or {}

    def register(self, key: str, handler: Callable[..., Awaitable[dict[str, Any]]]) -> None:
        self._handlers[key] = handler

    async def call(self, agent_id: str, params: dict[str, Any],
                   timeout_seconds: int = 300) -> TransportResult:
        # Route by _tool_name first (set by HiveTool), fall back to agent_id
        tool_name = params.pop("_tool_name", None)
        lookup_key = tool_name or agent_id
        handler = self._handlers.get(lookup_key)
        if handler is None:
            return TransportResult(
                raw_output={"error": f"no in-process handler for {lookup_key}"},
                exit_code=1,
                stderr=f"unknown tool: {lookup_key}",
            )
        try:
            result = await asyncio.wait_for(handler(**params), timeout=timeout_seconds)
            # Normalize: handlers may return lists or scalars; wrap in dict for Gateway
            if not isinstance(result, dict):
                result = {"result": result}
            return TransportResult(raw_output=result)
        except asyncio.TimeoutError:
            return TransportResult(
                raw_output={"error": "timeout"},
                exit_code=-1,
                stderr=f"call timed out after {timeout_seconds}s",
            )
        except Exception as exc:
            return TransportResult(
                raw_output={"error": str(exc)},
                exit_code=1,
                stderr=str(exc),
            )

    async def cancel(self, call_id: str) -> None:
        pass  # in-process calls cannot be cancelled mid-flight