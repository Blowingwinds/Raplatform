"""Shared default agent capabilities — single source of truth.

Used by HiveOrchestrator and CLI plan command.  The list is the canonical
definition; helpers make registration idempotent.
"""

from __future__ import annotations

from typing import Any

from src.agents.registry import AgentRegistry
from src.domain.models import AgentCapability, RiskLevel

DEFAULT_CAPABILITIES: list[dict[str, Any]] = [
    {
        "capability_id": "info-gatherer",
        "name": "Information Gatherer",
        "techniques": ["T1046", "T1592", "T1590", "T1595"],
        "target_types": ["ip", "domain", "url", "hostname"],
        "input_schema": "info_gatherer_input.schema.json",
        "output_schema": "info_gatherer_output.schema.json",
        "risk_level": "low",
        "side_effects": [],
        "max_concurrency": 4,
    },
    {
        "capability_id": "framework-vuln",
        "name": "Framework Vulnerability Specialist",
        "techniques": ["T1190", "T1595", "T1210"],
        "target_types": ["url", "service", "hostname"],
        "input_schema": "framework_vuln_input.schema.json",
        "output_schema": "framework_vuln_output.schema.json",
        "risk_level": "medium",
        "side_effects": ["may trigger WAF alerts"],
        "max_concurrency": 1,
    },
    {
        "capability_id": "web-attack",
        "name": "Web Attack Specialist",
        "techniques": ["T1190", "T1595", "T1059"],
        "target_types": ["url", "service", "endpoint"],
        "input_schema": "web_attack_input.schema.json",
        "output_schema": "web_attack_output.schema.json",
        "risk_level": "high",
        "side_effects": ["may trigger WAF alerts", "active probing"],
        "max_concurrency": 1,
    },
    {
        "capability_id": "component-vuln",
        "name": "Component Vulnerability Specialist",
        "techniques": ["T1190", "T1595", "T1210"],
        "target_types": ["url", "service", "component"],
        "input_schema": "component_vuln_input.schema.json",
        "output_schema": "component_vuln_output.schema.json",
        "risk_level": "medium",
        "side_effects": ["may trigger WAF alerts"],
        "max_concurrency": 1,
    },
    {
        "capability_id": "exploit-verifier",
        "name": "Exploit Verifier",
        "techniques": ["T1190", "T1059", "T1210"],
        "target_types": ["url", "endpoint", "service"],
        "input_schema": "exploit_verifier_input.schema.json",
        "output_schema": "exploit_verifier_output.schema.json",
        "risk_level": "high",
        "side_effects": ["active exploitation", "may modify target state"],
        "max_concurrency": 1,
    },
]

DEFAULT_CAPABILITY_IDS: set[str] = {
    c["capability_id"] for c in DEFAULT_CAPABILITIES
}


def register_default_capabilities(registry: AgentRegistry) -> int:
    """Register all default capabilities — idempotent.

    Returns the number of new capabilities registered.
    """
    count = 0
    for cap_dict in DEFAULT_CAPABILITIES:
        cap_id = cap_dict["capability_id"]
        if registry.get(cap_id) is None:
            cap = AgentCapability(
                capability_id=cap_id,
                name=cap_dict["name"],
                techniques=cap_dict["techniques"],
                target_types=cap_dict["target_types"],
                input_schema=cap_dict["input_schema"],
                output_schema=cap_dict["output_schema"],
                risk_level=RiskLevel(cap_dict["risk_level"]),
                side_effects=cap_dict.get("side_effects", []),
                max_concurrency=cap_dict.get("max_concurrency", 1),
            )
            registry.register(cap)
            count += 1
    return count