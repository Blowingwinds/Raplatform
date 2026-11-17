"""Tests for info_gatherer agent — port scanner, DNS, web tools, MCP server."""

import asyncio
import json

import pytest

from src.agents.info_gatherer.dns_tools import resolve_dns
from src.agents.info_gatherer.port_scanner import _scan_one_port, scan_ports


# ---------------------------------------------------------------------------
# port scanner
# ---------------------------------------------------------------------------
class TestPortScanner:

    @pytest.mark.asyncio
    async def test_scan_closed_port(self):
        result = await _scan_one_port("127.0.0.1", 61001, timeout=0.5)
        assert result.open is False

    @pytest.mark.asyncio
    async def test_scan_returns_dicts(self):
        results = await scan_ports("127.0.0.1", ports=[80, 443, 22], concurrency=3, timeout=1.0)
        assert isinstance(results, list)
        for r in results:
            assert "port" in r
            assert "service" in r

    @pytest.mark.asyncio
    async def test_scan_with_custom_ports(self):
        results = await scan_ports("127.0.0.1", ports=[22, 80], concurrency=2, timeout=1.0)
        for r in results:
            assert r["port"] in (22, 80)


# ---------------------------------------------------------------------------
# DNS resolver
# ---------------------------------------------------------------------------
class TestDNSTools:

    @pytest.mark.asyncio
    async def test_resolve_dns_google(self):
        results = await resolve_dns("dns.google", record_types=["A"])
        assert isinstance(results, list)
        for r in results:
            assert r["type"] == "A"
            assert r["hostname"] == "dns.google"

    @pytest.mark.asyncio
    async def test_resolve_dns_nonexistent(self):
        results = await resolve_dns("this-domain-definitely-does-not-exist-99999.com")
        assert results == []


# ---------------------------------------------------------------------------
# MCP server tool list
# ---------------------------------------------------------------------------
class TestMCPServerTools:

    def test_server_has_expected_tools(self):
        from mcp.types import ListToolsRequest
        from src.agents.info_gatherer.server import server

        handler = server.request_handlers[ListToolsRequest]

        async def _get_tools():
            result = await handler(ListToolsRequest(method="tools/list", params=None))
            return result.root.tools

        tools = asyncio.run(_get_tools())
        tool_names = {t.name for t in tools}
        assert tool_names == {
            "scan_ports", "enumerate_subdomains", "resolve_dns", "discover_endpoints",
        }

    def test_tool_input_schemas_are_valid_json_schema(self):
        from mcp.types import ListToolsRequest
        from src.agents.info_gatherer.server import server

        handler = server.request_handlers[ListToolsRequest]

        async def _get_tools():
            result = await handler(ListToolsRequest(method="tools/list", params=None))
            return result.root.tools

        tools = asyncio.run(_get_tools())
        for tool in tools:
            schema = tool.inputSchema
            assert schema["type"] == "object"
            assert "properties" in schema
            assert "required" in schema

    def test_scan_ports_handler_returns_observations(self):
        from src.agents.info_gatherer.server import handle_tool

        async def _run():
            result = await handle_tool("scan_ports", {
                "target": "127.0.0.1",
                "ports": [80],
            })
            return result

        result = asyncio.run(_run())
        text = result[0].text
        payload = json.loads(text)
        assert "observations" in payload
        for obs in payload["observations"]:
            if len(obs) > 0:
                assert "fact_type" in obs
                assert "asset_ref" in obs
                assert "data" in obs
                assert "confidence" in obs

    def test_enumerate_subdomains_handler(self):
        from src.agents.info_gatherer.server import handle_tool

        async def _run():
            return await handle_tool("enumerate_subdomains", {"domain": "localhost"})

        result = asyncio.run(_run())
        payload = json.loads(result[0].text)
        assert "observations" in payload

    def test_discover_endpoints_handler(self):
        from src.agents.info_gatherer.server import handle_tool

        async def _run():
            return await handle_tool("discover_endpoints", {"base_url": "http://127.0.0.1:1"})

        result = asyncio.run(_run())
        payload = json.loads(result[0].text)
        assert "observations" in payload  # empty if no server, but valid format

    def test_unknown_tool_raises(self):
        from src.agents.info_gatherer.server import handle_tool

        async def _run():
            return await handle_tool("nonexistent", {})

        with pytest.raises(ValueError, match="unknown tool"):
            asyncio.run(_run())