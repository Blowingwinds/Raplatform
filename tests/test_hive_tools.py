"""Tests for HiveTool + InProcessTransport + Gateway integration."""

import pytest

from src.agents.hive.observation_bridge import ports_to_observations
from src.agents.hive.tools import CrewContext, HiveTool, make_hive_tool
from src.agents.registry import AgentRegistry
from src.domain.models import AgentCapability, RiskLevel, Scope
from src.domain.storage import SQLiteStore
from src.mcp.gateway import MCPGateway
from src.mcp.transport import InProcessTransport, MockTransport, TransportResult
from src.policy.guard import PolicyGuard


@pytest.fixture
def store():
    s = SQLiteStore(":memory:")
    yield s
    s.close()


@pytest.fixture
def ctx(store):
    return CrewContext(
        project_id="proj-1",
        scope_id="scope-1",
        session_id="sess-1",
        task_id="task-1",
    )


@pytest.fixture
def registry(store):
    return AgentRegistry(store)


@pytest.fixture
def guard(store):
    return PolicyGuard(store)


@pytest.fixture
def scope(store):
    s = Scope(
        scope_id="scope-1",
        project_id="proj-1",
        target_type="domain",
        target="*",
        authorization_ref="auth-1",
    )
    store.save_scope(s)
    return s


@pytest.fixture
def transport():
    transport = MockTransport()
    transport.canned["info-gatherer"] = TransportResult(
        raw_output={
            "port": 80, "service": "http", "banner": "nginx",
        },
    )
    return transport


@pytest.fixture
def gateway(registry, guard, transport):
    return MCPGateway(registry, guard, transport)


@pytest.fixture
def registered_cap(registry):
    cap = AgentCapability(
        capability_id="info-gatherer",
        name="Info Gatherer",
        techniques=["T1046"],
        target_types=["ip"],
        input_schema="input.json",
        output_schema="output.json",
        risk_level=RiskLevel.LOW,
    )
    registry.register(cap)
    return cap


# ── tests ─────────────────────────────────────────────────────────────

class TestHiveToolBasic:
    def test_tool_has_name(self):
        tool = HiveTool(
            name="scan_ports",
            description="Scans ports",
            func=lambda **kw: {},
            agent_id="info-gatherer",
            risk_level=RiskLevel.LOW,
            gateway=None,
            ctx=None,
        )
        assert tool.name == "scan_ports"
        # BaseTool doesn't support __call__ — CrewAI calls _run() internally

    def test_make_hive_tool_returns_instance(self, gateway, ctx):
        tool = make_hive_tool(
            name="test_tool",
            description="A test tool",
            func=lambda **kw: {},
            agent_id="info-gatherer",
            risk_level=RiskLevel.LOW,
            gateway=gateway,
            ctx=ctx,
        )
        assert isinstance(tool, HiveTool)
        assert tool.name == "test_tool"


class TestHiveToolGateway:
    def test_low_risk_tool_succeeds(self, gateway, ctx, scope, registered_cap, transport):
        """A LOW-risk tool through a registered agent goes through Gateway → MockTransport."""
        tool = make_hive_tool(
            name="scan_ports",
            description="Scan ports",
            func=lambda **kw: {},
            agent_id="info-gatherer",
            risk_level=RiskLevel.LOW,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: ports_to_observations(
                [output] if isinstance(output, dict) and "port" in output else [],
                kw.get("target", ""),
            ),
            arg_map={"target": "target"},
        )
        # CrewAI calls _run(), not __call__()
        result = tool._run(target="192.168.1.1")
        assert isinstance(result, dict)
        assert result.get("port") == 80 or "status" in result

    def test_tool_captures_evidence(self, gateway, ctx, scope, registered_cap, transport):
        tool = make_hive_tool(
            name="scan_ports",
            description="Scan ports",
            func=lambda **kw: {},
            agent_id="info-gatherer",
            risk_level=RiskLevel.LOW,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: [{"fact_type": "test", "data": output}],
            arg_map={"target": "target"},
        )

        assert len(ctx.pending_evidence) == 0
        tool._run(target="192.168.1.1")
        assert len(ctx.pending_evidence) == 1
        evidence = ctx.pending_evidence[0]
        assert evidence.agent_id == "info-gatherer"
        assert evidence.project_id == "proj-1"
        assert "observations" in evidence.raw_payload

    def test_unregistered_agent_rejected(self, gateway, ctx, scope):
        """Tool with unregistered agent gets REJECTED_SCOPE from gateway."""
        tool = make_hive_tool(
            name="bad_tool",
            description="Bad",
            func=lambda **kw: {},
            agent_id="unregistered-agent",
            risk_level=RiskLevel.LOW,
            gateway=gateway,
            ctx=ctx,
        )
        result = tool._run(target="x")
        assert result["status"] in ("rejected_scope", "error")

    def test_high_risk_waits_for_approval(self, store, ctx):
        """HIGH-risk tool with no approval mechanism returns waiting_approval."""
        s = Scope(scope_id="scope-1", project_id="proj-1", target_type="domain",
                  target="*", authorization_ref="auth-1")
        store.save_scope(s)
        reg = AgentRegistry(store)
        reg.register(AgentCapability(
            capability_id="exploit-verifier", name="Exploit",
            techniques=["T1190"], target_types=["url"],
            input_schema="i.json", output_schema="o.json",
            risk_level=RiskLevel.HIGH,
        ))
        g = PolicyGuard(store)
        transport = MockTransport()
        gw = MCPGateway(reg, g, transport)

        tool = make_hive_tool(
            name="verify_sqli",
            description="Verify SQLi",
            func=lambda **kw: {},
            agent_id="exploit-verifier",
            risk_level=RiskLevel.HIGH,
            gateway=gw,
            ctx=ctx,
        )
        result = tool._run(url="http://target.com")
        assert result["status"] == "waiting_approval"

    def test_rejected_scope_returns_rejected(self, store, ctx):
        """Wrong project scope → rejected_scope."""
        s = Scope(scope_id="scope-1", project_id="OTHER", target_type="domain",
                  target="*", authorization_ref="auth-1")
        store.save_scope(s)
        reg = AgentRegistry(store)
        reg.register(AgentCapability(
            capability_id="info-gatherer", name="IG",
            techniques=["T1046"], target_types=["ip"],
            input_schema="i.json", output_schema="o.json",
            risk_level=RiskLevel.LOW,
        ))
        g = PolicyGuard(store)
        gw = MCPGateway(reg, g, MockTransport())

        tool = make_hive_tool(
            name="scan_ports",
            description="Scan",
            func=lambda **kw: {},
            agent_id="info-gatherer",
            risk_level=RiskLevel.LOW,
            gateway=gw,
            ctx=ctx,
        )
        result = tool._run(target="x")
        assert result["status"] in ("rejected_scope", "error")


class TestInProcessTransport:
    def test_registered_handler_returns_result(self):
        async def my_handler(**params):
            return {"result": params.get("key", "default")}

        transport = InProcessTransport({"agent-a": my_handler})
        import asyncio
        result = asyncio.run(transport.call("agent-a", {"key": "value"}))
        assert result.exit_code == 0
        assert result.raw_output == {"result": "value"}

    def test_unknown_agent_returns_error(self):
        transport = InProcessTransport()
        import asyncio
        result = asyncio.run(transport.call("no-such-agent", {}))
        assert result.exit_code == 1
        assert "error" in result.raw_output or result.stderr

    def test_handler_exception_returns_failed(self):
        async def failing_handler(**params):
            raise ValueError("boom")

        transport = InProcessTransport({"bad": failing_handler})
        import asyncio
        result = asyncio.run(transport.call("bad", {}))
        assert result.exit_code == 1
        assert "boom" in str(result.raw_output.get("error", ""))


class TestCrewContext:
    def test_make_evidence(self, ctx):
        evidence = ctx.make_evidence("agent-1", {"output": "test"}, [{"fact_type": "x"}])
        assert evidence.agent_id == "agent-1"
        assert evidence.project_id == "proj-1"
        assert evidence.kind == "agent.result"
        assert evidence.raw_payload["observations"] == [{"fact_type": "x"}]