"""Dynamic CrewAI Task builders — create Tasks from blackboard facts.

Each builder reads the current blackboard snapshot and produces a list of
CrewAI ``Task`` objects scoped to the relevant targets / fingerprints / vulns.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlparse

from crewai import Agent, Task

from src.agents.component_vuln.planner import plan as component_plan
from src.agents.framework_vuln.planner import plan as framework_plan
from src.agents.hive.observation_bridge import (
    fingerprints_to_observations,
    vulnerabilities_to_observations,
)
from src.agents.web_attack.planner import plan as web_plan
from src.domain.models import BlackboardFact


# ── target parsing ──────────────────────────────────────────────────────

# Matches "host:port" where host is an IP or hostname (no scheme/path)
_IP_PORT_RE = re.compile(
    r"^(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<port>\d{1,5})$"
)
_HOST_PORT_RE = re.compile(
    r"^(?P<host>[\w.-]+?\.[\w-]+):(?P<port>\d{1,5})$"
)


def _parse_target(target: str) -> tuple[str, int | None, str]:
    """Extract (host, port, scheme) from a target string.

    >>> _parse_target("127.0.0.1:8000")
    ('127.0.0.1', 8000, 'http')
    >>> _parse_target("example.com:8443")
    ('example.com', 8443, 'https')
    >>> _parse_target("http://example.com:8000/path")
    ('example.com', 8000, 'http')
    >>> _parse_target("127.0.0.1")
    ('127.0.0.1', None, 'http')
    """
    # Full URL
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port
        scheme = parsed.scheme or "http"
        return host, port, scheme

    # IP:port
    m = _IP_PORT_RE.match(target)
    if m:
        host = m.group("host")
        port = int(m.group("port"))
        scheme = "https" if port == 443 else "http"
        return host, port, scheme

    # hostname:port
    m = _HOST_PORT_RE.match(target)
    if m:
        host = m.group("host")
        port = int(m.group("port"))
        scheme = "https" if port == 443 else "http"
        return host, port, scheme

    # Bare IP or hostname
    return target, None, "http"


def _build_url(host: str, port: int | None, scheme: str = "http", path: str = "") -> str:
    """Build a URL from host/port/scheme, omitting default ports."""
    if port is None:
        return f"{scheme}://{host}{path}"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


# ── fact extractors ─────────────────────────────────────────────────────

def _services_from_facts(facts: list[BlackboardFact]) -> list[dict[str, Any]]:
    """Extract service objects from service.exposed facts."""
    return [
        {
            "asset_ref": f.asset_ref,
            "service_name": f.data.get("service_name", "unknown"),
            "port": f.data.get("port", 0),
            "protocol": f.data.get("protocol", "tcp"),
        }
        for f in facts if f.fact_type == "service.exposed"
    ]


def _fingerprints_from_facts(facts: list[BlackboardFact]) -> list[dict[str, Any]]:
    """Extract fingerprint objects from fingerprint.detected facts."""
    return [
        {
            "name": f.data.get("name", ""),
            "extracted": f.data.get("extracted", ""),
            "host": f.asset_ref,
            "matched_at": f.asset_ref,
        }
        for f in facts if f.fact_type == "fingerprint.detected"
    ]


def _endpoints_from_facts(facts: list[BlackboardFact]) -> list[dict[str, Any]]:
    """Extract endpoint URLs from asset.discovered and subdomain.discovered facts."""
    endpoints: list[dict[str, Any]] = []
    for f in facts:
        if f.fact_type == "asset.discovered":
            url = f.data.get("url", f.asset_ref)
            if url.startswith("http"):
                endpoints.append({"url": url, "status": f.data.get("status", 0)})
        elif f.fact_type == "subdomain.discovered":
            hostname = f.asset_ref
            endpoints.append({"url": f"http://{hostname}", "status": f.data.get("http_status", 0)})
    return endpoints


def _unverified_vulns(facts: list[BlackboardFact]) -> list[BlackboardFact]:
    """Return vulnerability.detected facts that are not yet verified."""
    return [
        f for f in facts
        if f.fact_type == "vulnerability.detected"
        and not f.data.get("verified", False)
    ]


def _targets_needing_recon(
    facts: list[BlackboardFact],
    seed_targets: list[str],
) -> list[str]:
    """Find targets (IPs, hostnames) that don't yet have service.exposed facts.

    A seed target is "done" only when it has at least one service.exposed fact
    (meaning port scanning was performed).  asset.discovered and subdomain.discovered
    are informational and don't replace recon.

    Seed targets are normalized: ``127.0.0.1:8000`` and ``127.0.0.1`` match the
    same host — only the host portion is compared against service.exposed asset_refs.
    """
    already_scanned = {
        f.asset_ref for f in facts if f.fact_type == "service.exposed"
    }

    targets = []
    for t in seed_targets:
        host, _, _ = _parse_target(t)
        # Check if bare host or full target already has services
        if host not in already_scanned and t not in already_scanned:
            targets.append(t)

    # Also scan newly discovered subdomains that haven't been port-scanned yet
    sub_targets = [
        f.asset_ref for f in facts
        if f.fact_type == "subdomain.discovered"
        and f.asset_ref not in already_scanned
    ]
    targets.extend(sub_targets[:5])  # limit per round

    return list(dict.fromkeys(targets))  # dedup preserving order


# ── task builders ───────────────────────────────────────────────────────

def make_info_tasks(
    ctx,  # CrewContext
    facts: list[BlackboardFact],
    info_agent: Agent,
    seed_targets: list[str],
) -> list[Task]:
    """Build reconnaissance tasks: one per seed target needing service discovery."""
    targets = _targets_needing_recon(facts, seed_targets)
    if not targets:
        # Check if there are subdomains without ports scanned
        sub_targets = [
            f.asset_ref for f in facts
            if f.fact_type == "subdomain.discovered"
            and f.asset_ref not in {
                s.asset_ref for s in facts if s.fact_type == "service.exposed"
            }
        ]
        targets = sub_targets[:5]  # limit

    if not targets:
        return []

    tasks: list[Task] = []
    for target in targets:
        host, port, scheme = _parse_target(target)
        base_url = _build_url(host, port, scheme)

        desc = (
            f"Gather information about target: {target}\n\n"
            f"Use these tools in order:\n"
            f"1. scan_ports(target='{host}') — discover open TCP ports and services\n"
            f"2. resolve_dns(hostname='{host}') — resolve DNS records\n"
            f"3. If the target is a domain: enumerate_subdomains(domain='{host}') — discover subdomains\n"
            f"4. discover_endpoints(base_url='{base_url}') — brute-force web endpoints\n"
        )
        # 常见 HTTP 端口兜底探测（使用裸 host，再拼端口）
        for extra_port in (443, 8000, 8008, 8080, 8088, 8443, 8888, 3000, 5000, 7000, 9000):
            extra_scheme = "https" if extra_port == 443 else "http"
            extra_url = _build_url(host, extra_port, extra_scheme)
            desc += f"   discover_endpoints(base_url='{extra_url}')\n"
        desc += "Report all findings as structured observations."
        tasks.append(Task(
            description=desc,
            expected_output="JSON with observations list including service.exposed, "
                            "asset.discovered, and subdomain.discovered entries",
            agent=info_agent,
        ))

    return tasks


def make_fingerprint_tasks(
    ctx,  # CrewContext
    facts: list[BlackboardFact],
    framework_agent: Agent,
) -> list[Task]:
    """Build fingerprinting tasks: run nuclei tech-detect against discovered services."""
    services = _services_from_facts(facts)
    if not services:
        return []

    # Group services by host
    hosts: dict[str, list[dict]] = {}
    for svc in services:
        host = svc["asset_ref"]
        hosts.setdefault(host, []).append(svc)

    tasks: list[Task] = []
    for host, svc_list in hosts.items():
        http_ports = [s["port"] for s in svc_list if s["service_name"] in ("http", "https", "http-proxy", "http-alt")]
        urls = [f"http{'s' if p == 443 else ''}://{host}:{p}" for p in http_ports[:3]]

        svc_descs = ', '.join(f"{s['service_name']}:{s['port']}" for s in svc_list)
        if urls:
            desc = (
                f"Fingerprint technology on target: {host}\n\n"
                f"Discovered services: {svc_descs}\n\n"
                f"Run scan_fingerprints(target='{urls[0]}') to identify frameworks, "
                f"languages, web servers, and runtime versions.\n"
            )
            for extra in urls[1:3]:
                desc += f"Run scan_fingerprints(target='{extra}') for this service.\n"
        else:
            desc = (
                f"Fingerprint technology on target: {host}\n\n"
                f"Discovered services: {svc_descs}\n\n"
                f"Run scan_fingerprints(target='{host}') to identify frameworks, "
                f"languages, web servers, and runtime versions.\n"
            )
        desc += (
            f"Expected fingerprints help determine which CVEs to check later.\n\n"
            f"If web endpoints found: use discover_endpoints on {urls if urls else host}"
        )
        tasks.append(Task(
            description=desc,
            expected_output="List of fingerprint.detected observations with technology names and versions",
            agent=framework_agent,
        ))

    return tasks


def make_vuln_tasks(
    ctx,  # CrewContext
    facts: list[BlackboardFact],
    framework_agent: Agent,
    web_agent: Agent,
    component_agent: Agent,
) -> list[Task]:
    """Build vulnerability detection tasks from fingerprint + endpoint data."""
    fps = _fingerprints_from_facts(facts)
    endpoints = _endpoints_from_facts(facts)
    services = _services_from_facts(facts)

    if not fps and not endpoints:
        return []

    tasks: list[Task] = []

    # Framework vuln tasks
    if fps:
        fw_plan = _run_planner(framework_plan, fingerprints=fps)
        plan_steps = fw_plan.get("plan", [])
        if plan_steps:
            for step in plan_steps[:5]:  # limit per round
                actions = ", ".join(step.get("actions", []))
                tags = ", ".join(step.get("nuclei_tags", []))
                desc = (
                    f"Detect framework vulnerabilities on {step['target']}\n"
                    f"Detected: {step.get('detected', '')} (version: {step.get('version', 'unknown')})\n"
                    f"Actions: {actions}\n"
                    f"Run scan_vulnerabilities(target='{step['target']}', "
                    f"tags='{tags}') targeting these specific vulnerability classes."
                )
                tasks.append(Task(
                    description=desc,
                    expected_output="vulnerability.detected observations for framework CVEs",
                    agent=framework_agent,
                ))

    # Web attack tasks — also add one broad scan against the base URL
    # to ensure all vulnerability templates get a chance to match, regardless
    # of planner-generated per-endpoint probes (which may be too specific for
    # hand-written template sets).
    if endpoints or services:
        web_plan_result = _run_planner(web_plan, endpoints=endpoints, services=services)
        web_steps = web_plan_result.get("plan", [])

        # Broad scan: run ALL vuln templates against the first HTTP service
        for svc in services:
            if svc.get("service_name", "").lower() in ("http", "https", "http-alt", "http-proxy"):
                asset = svc.get("asset_ref", "")
                port = svc.get("port", 80)
                scheme = "https" if port == 443 else "http"
                broad_url = f"{scheme}://{asset}:{port}" if port not in (80, 443) else f"{scheme}://{asset}"
                tasks.append(Task(
                    description=(
                        f"Broad vulnerability scan against: {broad_url}\n"
                        f"Run scan_vulnerabilities(target='{broad_url}', "
                        f"tags='cve,exposures,misconfig,default-login,auth-bypass,file-upload') "
                        f"using the CVE and high-value exposure tags.\n"
                        f"Report each finding as a vulnerability.detected observation."
                    ),
                    expected_output="vulnerability.detected observations for all detected vulnerabilities",
                    agent=web_agent,
                ))
                break  # One broad scan is enough

        if web_steps:
            # Group by target
            seen_targets: set[str] = set()
            for step in web_steps[:5]:
                target = step.get("target", "")
                if target in seen_targets:
                    continue
                seen_targets.add(target)
                actions = ", ".join(step.get("actions", []))
                probe_url = _probe_url_for(target, step.get("actions", []), services)
                desc = (
                    f"Test web vulnerabilities on: {target}\n"
                    f"Reasoning: {step.get('reasoning', '')}\n"
                    f"Actions: {actions}\n"
                    f"Run scan_vulnerabilities(target='{probe_url}') to detect "
                    f"these vulnerability types.\n"
                    f"Report each finding as a vulnerability.detected observation."
                )
                tasks.append(Task(
                    description=desc,
                    expected_output="vulnerability.detected observations for web vulnerabilities",
                    agent=web_agent,
                ))

    # Component vuln tasks
    if fps or services:
        comp_plan_result = _run_planner(component_plan, fingerprints=fps, services=services)
        comp_steps = comp_plan_result.get("plan", [])
        if comp_steps:
            seen_components: set[str] = set()
            for step in comp_steps[:5]:
                comp_name = step.get("component", "")
                key = f"{step.get('target', '')}:{comp_name}"
                if key in seen_components:
                    continue
                seen_components.add(key)
                actions = ", ".join(step.get("actions", []))
                desc = (
                    f"Check component vulnerabilities on {step.get('target', '')}\n"
                    f"Component: {comp_name}\n"
                    f"Reasoning: {step.get('reasoning', '')}\n"
                    f"Actions: {actions}\n"
                    f"Priority: {step.get('priority', 'high')}\n"
                    f"Run scan_vulnerabilities(target='{step.get('target', '')}') targeting "
                    f"this specific component."
                )
                tasks.append(Task(
                    description=desc,
                    expected_output="vulnerability.detected observations for component/plugin CVEs",
                    agent=component_agent,
                ))

    return tasks


def _verification_code(category: str, target: str, vuln_name: str) -> str:
    """Generate a Python verification script for a given vuln category.

    All code uses double-quoted strings (no single quotes) and wraps the HTTP
    call in try/except so non-200 responses don't crash the sandbox subprocess.
    """
    head = "try:\n import urllib.request as U,json"
    tail = "\nexcept Exception as e:\n print(\"NOT_VERIFIED:\"+str(e)[:80])"

    if category == "xss":
        body = (
            f'\n r=U.urlopen("{target}",timeout=10)'
            '\n body=r.read()'
            '\n print("VERIFIED" if b"<script>alert(1)</script>" in body else "NOT_FOUND")'
        )
    elif category in ("sqli", "injection"):
        body = (
            f'\n r=U.urlopen("{target}",timeout=10)'
            '\n body=r.read().decode(errors="replace")'
            '\n print("VERIFIED" if ("SELECT" in body or "query" in body) else "NOT_FOUND")'
        )
    elif category in ("exposures", "misconfig"):
        body = (
            f'\n r=U.urlopen("{target}",timeout=10)'
            '\n body=r.read()'
            '\n print("VERIFIED" if len(body) > 30 else "NOT_FOUND")'
        )
    elif category in ("auth-bypass", "default-login"):
        body = (
            f'\n req=U.Request("{target}",headers={{"X-Admin":"1"}})'
            '\n r=U.urlopen(req,timeout=10)'
            '\n print("VERIFIED" if r.status == 200 else "NOT_FOUND")'
        )
    elif category == "rce":
        body = (
            f'\n r=U.urlopen("{target}",timeout=10)'
            '\n body=r.read().decode(errors="replace")'
            '\n print("VERIFIED" if ("stdout" in body or "uid=" in body) else "NOT_FOUND")'
        )
    else:
        # Generic: just check if the URL returns content
        body = (
            f'\n r=U.urlopen("{target}",timeout=10)'
            '\n body=r.read()'
            '\n print("VERIFIED" if len(body) > 50 else "NOT_FOUND")'
        )
    return head + body + tail


def make_exploit_tasks(
    ctx,  # CrewContext
    facts: list[BlackboardFact],
    exploit_agent: Agent,
) -> list[Task]:
    """Build exploitation/verification tasks for unverified vulnerabilities."""
    vulns = _unverified_vulns(facts)
    if not vulns:
        return []

    tasks: list[Task] = []
    for v in vulns[:3]:  # limit per round
        category = v.data.get("category", "")
        target = v.data.get("matched_at", v.asset_ref)
        vuln_name = v.data.get("name", "unknown")

        if category == "sqli":
            desc = (
                f"Verify SQL injection on: {target}\n"
                f"Vulnerability: {vuln_name}\n\n"
                f"Run verify_sqli(url='{target}') to confirm the injection with sqlmap.\n"
                f"Report the verified result as a vulnerability.detected observation with verified=True."
            )
        else:
            code = _verification_code(category, target, vuln_name)
            desc = (
                f"Verify vulnerability on: {target}\n"
                f"Vulnerability: {vuln_name}\n"
                f"Category: {category}\n\n"
                f"Run execute_python(code='{code}', target='{target}') to verify this finding.\n"
                f"Report the result as a vulnerability.detected observation with verified=True "
                f"if the verification script prints VERIFIED."
            )

        tasks.append(Task(
            description=desc,
            expected_output="vulnerability.detected observation with verified field set to True/False",
            agent=exploit_agent,
        ))

    return tasks


# ── helpers ────────────────────────────────────────────────────────────

def _probe_url_for(target: str, actions: list[str], services: list[dict]) -> str:
    """Build a probe URL carrying a test parameter so param-based templates fire.

    ffuf-discovered endpoints have no query string, but sqli/xss templates need
    a parameter value to test.  Attach an educated guess based on the path.
    Service-based planner steps carry a bare host — rebuild the URL with port.
    """
    if "?" in target:
        return target

    # Service-based steps: bare host → reconstruct http(s)://host:port
    if "://" not in target:
        for svc in services:
            if svc.get("asset_ref") == target:
                name = svc.get("service_name", "").lower()
                if name in ("http", "https", "http-alt", "http-proxy", "https-alt"):
                    scheme = "https" if name in ("https", "https-alt") else "http"
                    target = f"{scheme}://{target}:{svc.get('port')}"
                break

    path = target.rstrip("/").lower()
    if "search" in path or "find" in path or "query" in path:
        return f"{target}?q=test"
    if "login" in path or "auth" in path or "signin" in path:
        return f"{target}?username=admin&password=admin123"
    if "redirect" in path or "goto" in path or "next" in path:
        return f"{target}?url=https://example.com"
    if "upload" in path:
        return target  # upload checks are POST-driven; keep path as-is
    return f"{target}?id=1"


def _run_planner(planner_func, **kwargs) -> dict[str, Any]:
    """Run an async planner function synchronously."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(planner_func(**kwargs))

    # Already in a loop — use thread
    import concurrent.futures

    def _run():
        new_loop = asyncio.new_event_loop()
        try:
            return new_loop.run_until_complete(planner_func(**kwargs))
        finally:
            new_loop.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(_run).result(timeout=60)