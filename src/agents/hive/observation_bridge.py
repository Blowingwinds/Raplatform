"""Observation factories — convert raw tool output into AgentObservation-shaped dicts.

Extracted from ``info_gatherer/server.py`` so both the MCP stdio server and the
CrewAI HiveTool wrapper produce identical observation payloads.  Single source
of truth for observation shapes; do not duplicate these mappings elsewhere.
"""

from __future__ import annotations

from typing import Any


def ports_to_observations(
    results: list[dict], target: str
) -> list[dict[str, Any]]:
    """Convert port scan results → service.exposed observations."""
    return [
        {
            "fact_type": "service.exposed",
            "asset_ref": target,
            "data": {
                "protocol": "tcp",
                "port": r["port"],
                "service_name": r.get("service", "unknown"),
                "banner": r.get("banner", ""),
            },
            "identity": {"protocol": "tcp", "port": r["port"]},
            "confidence": 0.95,
            "state": "active",
        }
        for r in results
    ]


def subdomains_to_observations(
    results: list[dict],
) -> list[dict[str, Any]]:
    """Convert subdomain enumeration results → asset + subdomain observations."""
    obs: list[dict[str, Any]] = []
    for r in results:
        for ip in r.get("ips", []):
            obs.append({
                "fact_type": "asset.discovered",
                "asset_ref": ip,
                "data": {"ip": ip, "hostname": r["hostname"]},
                "identity": {"ip": ip},
                "confidence": 0.9,
                "state": "active",
            })
        obs.append({
            "fact_type": "subdomain.discovered",
            "asset_ref": r["hostname"],
            "data": {
                "hostname": r["hostname"],
                "ips": r.get("ips", []),
                "http_status": r.get("http_status"),
            },
            "identity": {"hostname": r["hostname"]},
            "confidence": 0.85,
            "state": "active",
        })
    return obs


def dns_to_observations(
    results: list[dict],
) -> list[dict[str, Any]]:
    """Convert DNS resolution results → asset.discovered observations."""
    return [
        {
            "fact_type": "asset.discovered",
            "asset_ref": r.get("value", r["hostname"]),
            "data": r,
            "identity": {},
            "confidence": 0.95,
            "state": "active",
        }
        for r in results
    ]


def endpoints_to_observations(
    results: list[dict],
) -> list[dict[str, Any]]:
    """Convert endpoint discovery results → asset.discovered observations."""
    return [
        {
            "fact_type": "asset.discovered",
            "asset_ref": r["url"],
            "data": r,
            "identity": {"ip": r["url"]},
            "confidence": 0.7,
            "state": "active",
        }
        for r in results
    ]


def fingerprints_to_observations(
    results: list[dict],
) -> list[dict[str, Any]]:
    """Convert nuclei fingerprint results → fingerprint.detected observations."""
    return [
        {
            "fact_type": "fingerprint.detected",
            "asset_ref": r.get("host", r.get("matched_at", "")),
            "data": {
                "name": r.get("name", ""),
                "extracted": r.get("extracted", ""),
                "host": r.get("host", r.get("matched_at", "")),
                "severity": r.get("severity", "info"),
                "template": r.get("template_id", ""),
            },
            "identity": {
                "host": r.get("host", r.get("matched_at", "")),
                "name": r.get("name", ""),
            },
            "confidence": r.get("confidence", 0.9),
            "state": "active",
        }
        for r in results
    ]


def vulnerabilities_to_observations(
    results: list[dict],
) -> list[dict[str, Any]]:
    """Convert nuclei vulnerability scan results → vulnerability.detected observations.

    Accepts both the normalized flat dict from ``nuclei_runner._normalize_vuln``
    (title/category/matched_at) and raw nuclei JSON (info.name/info.tags).
    """
    observations = []
    for r in results:
        info = r.get("info") or {}
        name = r.get("title") or info.get("name") or r.get("name", "")
        category = r.get("category") or r.get("type") or _category_from_raw(r, info)
        severity = r.get("severity") or info.get("severity") or "unknown"
        matched_at = r.get("matched_at") or r.get("host", "")
        if not name:
            continue
        observations.append({
            "fact_type": "vulnerability.detected",
            "asset_ref": matched_at,
            "data": {
                "vulnerability_id": r.get("vulnerability_id") or r.get("template_id", ""),
                "name": name,
                "severity": severity,
                "category": category,
                "matched_at": matched_at,
                "description": r.get("description") or info.get("description", ""),
                "verified": bool(r.get("verified", False)),
                "service_ref": matched_at,
            },
            "identity": {
                "vulnerability_id": r.get("vulnerability_id") or r.get("template_id", ""),
                "service_ref": matched_at,
            },
            "confidence": r.get("confidence", 0.85),
            "state": "active",
        })
    return observations


def _category_from_raw(r: dict, info: dict) -> str:
    """Derive category from raw nuclei entry (tags → template-id fallback)."""
    tags = info.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if tag in {
                "sqli", "xss", "ssrf", "ssti", "lfi", "rfi", "file-upload",
                "auth-bypass", "redirect", "cors", "exposures", "misconfig",
                "default-login", "tech-detect", "cve",
            }:
                return tag
    template_id = r.get("template-id", "")
    if "CVE-" in template_id.upper():
        return "cve"
    for cat in ("sqli", "xss", "ssrf", "exposures", "misconfig", "cors"):
        if cat in template_id.lower():
            return cat
    return "unknown"


def sqlmap_to_observations(
    result: dict | None, url: str,
) -> list[dict[str, Any]]:
    """Convert sqlmap result → vulnerability.detected observations."""
    if result is None:
        return []
    vuln_id = f"sqli-{url}"
    return [{
        "fact_type": "vulnerability.detected",
        "asset_ref": url,
        "data": {
            "vulnerability_id": vuln_id,
            "name": f"SQL Injection: {url}",
            "severity": result.get("severity", "high"),
            "category": "sqli",
            "matched_at": url,
            "description": result.get("technique", ""),
            "verified": result.get("confirmed", False),
            "service_ref": url,
        },
        "identity": {"vulnerability_id": vuln_id, "service_ref": url},
        "confidence": 0.95 if result.get("confirmed") else 0.6,
        "state": "active",
    }]


def python_to_observations(
    result: dict, target: str,
) -> list[dict[str, Any]]:
    """Convert Python exec result → vulnerability.detected observations."""
    if not result or result.get("error"):
        return []
    vuln_id = f"py-{target}-{result.get('exit_code', 0)}"
    return [{
        "fact_type": "vulnerability.detected",
        "asset_ref": target,
        "data": {
            "vulnerability_id": vuln_id,
            "name": f"Python exploit: {target}",
            "severity": "high",
            "category": "custom",
            "matched_at": target,
            "description": result.get("stdout", "")[:500],
            "verified": result.get("exit_code", -1) == 0,
            "service_ref": target,
        },
        "identity": {"vulnerability_id": vuln_id, "service_ref": target},
        "confidence": 0.8 if result.get("exit_code") == 0 else 0.3,
        "state": "active",
    }]