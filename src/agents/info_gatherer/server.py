"""Information Gatherer MCP Server."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from src.agents.hive.observation_bridge import (
    dns_to_observations,
    endpoints_to_observations,
    ports_to_observations,
    subdomains_to_observations,
)
from src.agents.info_gatherer.dns_tools import enumerate_subdomains, resolve_dns
from src.agents.info_gatherer.port_scanner import scan_ports
from src.agents.info_gatherer.web_tools import discover_endpoints

logger = logging.getLogger("info_gatherer")
server = Server("info-gatherer", version="0.1.0")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(name="scan_ports", description="Scan TCP ports on a target. Returns open ports with service names and banners.",
             inputSchema={"type": "object", "properties": {"target": {"type": "string"}, "ports": {"type": "array", "items": {"type": "integer"}}}, "required": ["target"]}),
        Tool(name="enumerate_subdomains", description="Enumerate subdomains via subfinder + DNS + HTTP checks.",
             inputSchema={"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}),
        Tool(name="resolve_dns", description="Resolve DNS records for a hostname.",
             inputSchema={"type": "object", "properties": {"hostname": {"type": "string"}, "record_types": {"type": "array", "items": {"type": "string"}}}, "required": ["hostname"]}),
        Tool(name="discover_endpoints", description="Discover web endpoints via ffuf directory brute-force.",
             inputSchema={"type": "object", "properties": {"base_url": {"type": "string"}}, "required": ["base_url"]}),
    ]


@server.call_tool()
async def handle_tool(tool_name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if tool_name == "scan_ports":
        target = arguments["target"]
        ports = arguments.get("ports")
        results = await scan_ports(target, ports)
        observations = ports_to_observations(results, target)
        return [TextContent(type="text", text=json.dumps({"observations": observations}, ensure_ascii=False))]

    elif tool_name == "enumerate_subdomains":
        results = await enumerate_subdomains(arguments["domain"])
        observations = subdomains_to_observations(results)
        return [TextContent(type="text", text=json.dumps({"observations": observations}, ensure_ascii=False))]

    elif tool_name == "resolve_dns":
        results = await resolve_dns(arguments["hostname"], arguments.get("record_types"))
        observations = dns_to_observations(results)
        return [TextContent(type="text", text=json.dumps({"observations": observations}, ensure_ascii=False))]

    elif tool_name == "discover_endpoints":
        results = await discover_endpoints(arguments["base_url"])
        observations = endpoints_to_observations(results)
        return [TextContent(type="text", text=json.dumps({"observations": observations}, ensure_ascii=False))]

    raise ValueError(f"unknown tool: {tool_name}")


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())