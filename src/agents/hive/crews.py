"""Worker bee crew builders — one factory per workergroup.

Each builder returns a ``(Crew, CrewContext)`` tuple.  The Crew is ready to
have ``.tasks`` assigned and ``.kickoff()`` called.  The CrewContext carries
identities for Gateway routing and collects ``pending_evidence`` for blackboard
ingestion after the crew finishes.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol

from crewai import Agent, Crew, Process, Task

from src.agents.hive.observation_bridge import (
    endpoints_to_observations,
    fingerprints_to_observations,
    ports_to_observations,
    python_to_observations,
    sqlmap_to_observations,
    subdomains_to_observations,
    vulnerabilities_to_observations,
)
from src.agents.hive.tools import (
    AsyncTool,
    CrewContext,
    HiveTool,
    ObsFactory,
    make_hive_tool,
)
from src.agents.info_gatherer.dns_tools import enumerate_subdomains, resolve_dns
from src.agents.info_gatherer.port_scanner import scan_ports
from src.agents.info_gatherer.web_tools import discover_endpoints
from src.agents.shared.nuclei_runner import scan_fingerprints, scan_vulnerabilities
from src.agents.shared.python_exec import execute as python_exec
from src.agents.shared.sqlmap_runner import verify_sqli
from src.domain.models import Evidence, RiskLevel
from src.mcp.gateway import MCPGateway


# ── CrewRunner protocol (for testability) ───────────────────────────────

@dataclass
class CrewRunResult:
    """Result from running a crew (real or fake)."""
    output: str = ""
    evidence: list[Evidence] = field(default_factory=list)


class CrewRunner(Protocol):
    """Protocol for running a CrewAI Crew."""

    def run(self, crew: Crew, ctx: CrewContext) -> CrewRunResult:
        ...


@dataclass
class RealCrewRunner:
    """Runs a Crew via ``crew.kickoff()`` — uses real LLM."""
    verbose: bool = False

    def run(self, crew: Crew, ctx: CrewContext) -> CrewRunResult:
        result = crew.kickoff()
        output = str(result) if result else ""
        evidence = list(ctx.pending_evidence)
        ctx.pending_evidence.clear()
        return CrewRunResult(output=output, evidence=evidence)


@dataclass
class FakeCrewRunner:
    """Test runner that directly invokes each Task's tools without an LLM.

    For each task, scans the description for tool-call patterns like
    ``tool_name(key='value')`` and calls ``tool._run(**kwargs)``.

    If ``canned_responses`` has a matching tool name, returns the canned
    string instead of calling the tool (used for deterministic tests).
    """
    canned_responses: dict[str, Any] = field(default_factory=dict)
    verbose: bool = False

    # Pattern: tool_name(key='value', ...) or tool_name(target="value")
    _CALL_RE = re.compile(
        r"(?P<tool>\w+)\s*\((?P<args>[^)]*)\)",
    )
    _KWARG_RE = re.compile(
        r"""(?P<key>\w+)\s*=\s*(?:'(?P<sval>[^']*)'|"(?P<dval>[^"]*)"|(?P<nval>[\w./:]+))""",
    )

    def _extract_tool_calls(self, text: str) -> list[tuple[str, dict[str, Any]]]:
        """Find all ``tool_name(k1='v1', k2='v2')`` patterns in *text*."""
        calls: list[tuple[str, dict[str, Any]]] = []
        for match in self._CALL_RE.finditer(text):
            tool_name = match.group("tool")
            kwargs: dict[str, Any] = {}
            args_str = match.group("args")
            for km in self._KWARG_RE.finditer(args_str):
                key = km.group("key")
                val = km.group("sval") or km.group("dval") or km.group("nval")
                kwargs[key] = val
            calls.append((tool_name, kwargs))
        return calls

    def run(self, crew: Crew, ctx: CrewContext) -> CrewRunResult:
        outputs: list[str] = []
        for task in crew.tasks:
            agent = task.agent
            if agent is None:
                continue

            # Extract tool calls from the task description
            call_specs = self._extract_tool_calls(task.description)

            agent_tools = getattr(agent, 'tools', []) or []
            tools_by_name = {
                getattr(t, 'name', str(t)): t for t in agent_tools
            }

            for tool_name, kwargs in call_specs:
                if tool_name in self.canned_responses:
                    outputs.append(str(self.canned_responses[tool_name]))
                    continue

                tool = tools_by_name.get(tool_name)
                if tool is not None and hasattr(tool, '_run'):
                    try:
                        result = tool._run(**kwargs)
                        outputs.append(str(result))
                        if self.verbose:
                            print(f"  [FakeCrew] {tool_name}({kwargs}) → {str(result)[:200]}")
                    except Exception as exc:
                        outputs.append(f"Error: {exc}")
                        if self.verbose:
                            print(f"  [FakeCrew] {tool_name}({kwargs}) → ERROR: {exc}")
                elif tool is not None:
                    try:
                        result = tool(**kwargs)
                        outputs.append(str(result))
                    except Exception:
                        pass

        evidence = list(ctx.pending_evidence)
        ctx.pending_evidence.clear()
        return CrewRunResult(output="\n".join(outputs), evidence=evidence)


# ── info-gatherer crew ──────────────────────────────────────────────────

def build_info_crew(
    gateway: MCPGateway,
    ctx: CrewContext,
    *,
    llm_model: str = "gpt-4o",
    verbose: bool = False,
) -> tuple[Crew, CrewContext]:
    """Build the Information Gatherer worker bee crew.

    One agent with four tools: scan_ports, resolve_dns, enumerate_subdomains,
    discover_endpoints.  All LOW risk.
    """
    tools = [
        make_hive_tool(
            name="scan_ports",
            description="Scan TCP ports on a target host. Returns open ports with service names and banners.",
            func=scan_ports,
            agent_id="info-gatherer",
            risk_level=RiskLevel.LOW,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: ports_to_observations(
                output.get("result", output) if isinstance(output, dict) else [],
                kw.get("target", ""),
            ),
            arg_map={"target": "target", "ports": "ports"},
        ),
        make_hive_tool(
            name="resolve_dns",
            description="Resolve DNS records (A, AAAA, CNAME, MX, NS, TXT) for a hostname.",
            func=resolve_dns,
            agent_id="info-gatherer",
            risk_level=RiskLevel.LOW,
            gateway=gateway,
            ctx=ctx,
            observation_factory=None,  # DNS results are informational
            arg_map={"hostname": "hostname", "record_types": "record_types"},
        ),
        make_hive_tool(
            name="enumerate_subdomains",
            description="Enumerate subdomains for a domain using subfinder + DNS + HTTP verification.",
            func=enumerate_subdomains,
            agent_id="info-gatherer",
            risk_level=RiskLevel.LOW,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: subdomains_to_observations(
                output if isinstance(output, list) else output.get("result", []),
            ),
            arg_map={"domain": "domain"},
        ),
        make_hive_tool(
            name="discover_endpoints",
            description="Discover web endpoints/directories using ffuf brute-force.",
            func=discover_endpoints,
            agent_id="info-gatherer",
            risk_level=RiskLevel.LOW,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: endpoints_to_observations(
                output if isinstance(output, list) else output.get("result", []),
            ),
            arg_map={"base_url": "base_url", "wordlist": "wordlist"},
        ),
    ]

    agent = Agent(
        role="Information Gatherer Bee",
        goal=(
            "Gather comprehensive information about target systems. "
            "Scan ports, resolve DNS, enumerate subdomains, and discover web endpoints. "
            "Report all findings as structured observations on the blackboard."
        ),
        backstory=(
            "You are a reconnaissance specialist — the first wave of the hive. "
            "Your job is to map the attack surface: what services are running, "
            "what subdomains exist, what endpoints are exposed. "
            "Every piece of data you collect feeds the vulnerability detection bees. "
            "Be thorough but efficient — focus on what matters for the next phase."
        ),
        tools=tools,
        llm=llm_model,
        verbose=verbose,
        allow_delegation=False,
    )

    crew = Crew(
        agents=[agent],
        tasks=[],
        process=Process.sequential,
        verbose=verbose,
    )

    return crew, ctx


# ── vuln-detector crew ──────────────────────────────────────────────────

def build_vuln_crew(
    gateway: MCPGateway,
    ctx: CrewContext,
    *,
    llm_model: str = "gpt-4o",
    verbose: bool = False,
) -> tuple[Crew, CrewContext]:
    """Build the Vulnerability Detector worker bee crew.

    Three specialist agents: framework_vuln, web_attack, component_vuln.
    """
    # ── framework vuln agent ──
    fw_tools = [
        make_hive_tool(
            name="scan_fingerprints",
            description="Run nuclei technology fingerprint scan (tech-detect) against a target.",
            func=scan_fingerprints,
            agent_id="framework-vuln",
            risk_level=RiskLevel.LOW,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: fingerprints_to_observations(
                output.get("result", output) if isinstance(output, dict) else [],
            ),
            arg_map={"target": "targets"},
        ),
        make_hive_tool(
            name="scan_vulnerabilities",
            description="Run nuclei vulnerability scan with specific tags against a target.",
            func=scan_vulnerabilities,
            agent_id="framework-vuln",
            risk_level=RiskLevel.MEDIUM,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: vulnerabilities_to_observations(
                output.get("result", output) if isinstance(output, dict) else [],
            ),
            arg_map={"target": "targets", "tags": "tags"},
        ),
        make_hive_tool(
            name="execute_python",
            description="Execute a Python script in a sandbox for custom vulnerability checks.",
            func=python_exec,
            agent_id="framework-vuln",
            risk_level=RiskLevel.HIGH,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: python_to_observations(
                output, kw.get("target", ""),
            ),
            arg_map={"code": "code", "target": "target"},
        ),
    ]

    framework_agent = Agent(
        role="Framework Vulnerability Specialist Bee",
        goal=(
            "Detect vulnerabilities in web frameworks and runtimes. "
            "Analyze technology fingerprints (Spring, Django, Laravel, Struts, Rails, Express, Flask, "
            "Apache, Nginx, IIS, Tomcat, PHP, Java, Python) and identify known CVEs and misconfigurations."
        ),
        backstory=(
            "You are a veteran security researcher specializing in framework and runtime vulnerabilities. "
            "You maintain deep knowledge of CVE databases for all major frameworks. "
            "Your first instinct on seeing a fingerprint is to cross-reference it with known exploits. "
            "You never scan blindly — you let the fingerprint guide your attack."
        ),
        tools=fw_tools,
        llm=llm_model,
        verbose=verbose,
        allow_delegation=False,
    )

    # ── web attack agent ──
    web_tools = [
        make_hive_tool(
            name="scan_vulnerabilities",
            description="Run nuclei vulnerability scan for web vulnerabilities (sqli, xss, ssrf, ssti, lfi, etc).",
            func=scan_vulnerabilities,
            agent_id="web-attack",
            risk_level=RiskLevel.MEDIUM,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: vulnerabilities_to_observations(
                output.get("result", output) if isinstance(output, dict) else [],
            ),
            arg_map={"target": "targets", "tags": "tags"},
        ),
        make_hive_tool(
            name="verify_sqli",
            description="Verify SQL injection using sqlmap (--batch --risk 2 --level 3).",
            func=verify_sqli,
            agent_id="web-attack",
            risk_level=RiskLevel.HIGH,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: sqlmap_to_observations(
                output, kw.get("url", ""),
            ),
            arg_map={"url": "url", "timeout": "timeout"},
        ),
        make_hive_tool(
            name="execute_python",
            description="Execute a Python script in a sandbox for custom web attack tests.",
            func=python_exec,
            agent_id="web-attack",
            risk_level=RiskLevel.MEDIUM,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: python_to_observations(
                output, kw.get("target", ""),
            ),
            arg_map={"code": "code", "target": "target"},
        ),
    ]

    web_agent = Agent(
        role="Web Attack Specialist Bee",
        goal=(
            "Find and verify common web vulnerabilities: SQL injection, XSS, SSRF, SSTI, "
            "LFI/RFI path traversal, open redirect, CORS misconfiguration, file upload bypass, "
            "and authentication/authorization flaws."
        ),
        backstory=(
            "You are a battle-hardened web application penetration tester. "
            "You've seen every kind of web vulnerability and know exactly how to verify each one. "
            "You prefer targeted attacks over broad scans — when you see a login form, "
            "you think SQLi bypass; when you see a file upload, you think type juggling. "
            "You always verify findings before reporting them."
        ),
        tools=web_tools,
        llm=llm_model,
        verbose=verbose,
        allow_delegation=False,
    )

    # ── component vuln agent ──
    comp_tools = [
        make_hive_tool(
            name="scan_vulnerabilities",
            description="Run nuclei vulnerability scan targeting components, plugins, and services.",
            func=scan_vulnerabilities,
            agent_id="component-vuln",
            risk_level=RiskLevel.MEDIUM,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: vulnerabilities_to_observations(
                output.get("result", output) if isinstance(output, dict) else [],
            ),
            arg_map={"target": "targets", "tags": "tags"},
        ),
        make_hive_tool(
            name="scan_fingerprints",
            description="Run nuclei technology fingerprint scan to identify component versions.",
            func=scan_fingerprints,
            agent_id="component-vuln",
            risk_level=RiskLevel.LOW,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: fingerprints_to_observations(
                output if isinstance(output, list) else output.get("results", []),
            ),
            arg_map={"target": "target"},
        ),
        make_hive_tool(
            name="execute_python",
            description="Execute a Python script in a sandbox for custom component checks.",
            func=python_exec,
            agent_id="component-vuln",
            risk_level=RiskLevel.HIGH,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: python_to_observations(
                output, kw.get("target", ""),
            ),
            arg_map={"code": "code", "target": "target"},
        ),
    ]

    component_agent = Agent(
        role="Component & Plugin Vulnerability Specialist Bee",
        goal=(
            "Detect vulnerabilities in third-party components, CMS plugins, JavaScript libraries, "
            "and infrastructure services. Analyze component versions (WordPress plugins, npm packages, "
            "Composer dependencies, Redis, MongoDB, MySQL, PostgreSQL) and identify known CVEs, "
            "default credentials, and misconfigurations."
        ),
        backstory=(
            "You are a software supply chain security expert. "
            "You know that the most dangerous vulnerabilities often hide in dependencies. "
            "When you see a WordPress site, you enumerate plugins before attacking the core. "
            "When you see Redis without auth, you know exactly what to check. "
            "You're thorough with service-level checks — default passwords, exposed admin panels, "
            "and version-specific exploits are your bread and butter."
        ),
        tools=comp_tools,
        llm=llm_model,
        verbose=verbose,
        allow_delegation=False,
    )

    crew = Crew(
        agents=[framework_agent, web_agent, component_agent],
        tasks=[],
        process=Process.sequential,
        verbose=verbose,
    )

    return crew, ctx


# ── exploit-verifier crew ───────────────────────────────────────────────

def build_exploit_crew(
    gateway: MCPGateway,
    ctx: CrewContext,
    *,
    llm_model: str = "gpt-4o",
    verbose: bool = False,
) -> tuple[Crew, CrewContext]:
    """Build the Exploit Verifier worker bee crew.

    One agent with sqlmap verification + python exploit execution.  HIGH risk.
    """
    tools = [
        make_hive_tool(
            name="verify_sqli",
            description="Verify SQL injection using sqlmap (--batch --risk 2 --level 3). Returns confirmed=true if vulnerable.",
            func=verify_sqli,
            agent_id="exploit-verifier",
            risk_level=RiskLevel.HIGH,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: sqlmap_to_observations(
                output, kw.get("url", ""),
            ),
            arg_map={"url": "url", "timeout": "timeout"},
        ),
        make_hive_tool(
            name="execute_python",
            description="Execute a Python script in a sandbox. Use for custom exploit verification scripts.",
            func=python_exec,
            agent_id="exploit-verifier",
            risk_level=RiskLevel.HIGH,
            gateway=gateway,
            ctx=ctx,
            observation_factory=lambda output, **kw: python_to_observations(
                output, kw.get("target", ""),
            ),
            arg_map={"code": "code", "target": "target", "timeout": "timeout"},
        ),
    ]

    agent = Agent(
        role="Exploit Verifier Bee",
        goal=(
            "Verify detected vulnerabilities through controlled exploitation. "
            "Use sqlmap to confirm SQL injection and custom Python scripts for other vulnerability types. "
            "Always operate within authorized scope — never escalate beyond verification."
        ),
        backstory=(
            "You are the final verification specialist — the closer. "
            "After the vulnerability detection bees find candidates, you confirm or disprove each one. "
            "You use sqlmap for SQL injection verification with surgical precision. "
            "For other vulnerability types, you write targeted Python scripts. "
            "You report verified = True only when you have concrete evidence, "
            "and verified = False when the finding turns out to be a false positive."
        ),
        tools=tools,
        llm=llm_model,
        verbose=verbose,
        allow_delegation=False,
    )

    crew = Crew(
        agents=[agent],
        tasks=[],
        process=Process.sequential,
        verbose=verbose,
    )

    return crew, ctx


# ── crew factory ────────────────────────────────────────────────────────

def build_crew_for_phase(
    phase: str,
    gateway: MCPGateway,
    ctx: CrewContext,
    *,
    llm_model: str = "gpt-4o",
    verbose: bool = False,
) -> tuple[Crew, CrewContext] | None:
    """Build the appropriate crew for a given HivePhase value.

    Returns None if the phase doesn't need a crew (DONE, BLOCKED).
    """
    if phase in ("recon", "seed"):
        return build_info_crew(gateway, ctx, llm_model=llm_model, verbose=verbose)
    elif phase in ("fingerprint", "vuln_detect"):
        return build_vuln_crew(gateway, ctx, llm_model=llm_model, verbose=verbose)
    elif phase == "exploit":
        return build_exploit_crew(gateway, ctx, llm_model=llm_model, verbose=verbose)
    return None