"""Nuclei scanner wrapper — two-pass: tech fingerprints, then targeted CVE + vuln scan."""

from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
from pathlib import Path

from src.agents.shared.tool_paths import resolve_tool

# Pass 1: technology fingerprinting (single Wappalyzer-style template)
_TECH_IDS = "tech-detect"

# Pass 2: default vulnerability tags (lightweight demo set; the heavy "cve"
# tag is only pulled in via planner-driven tags for fingerprinted products)
_VULN_TAGS = ",".join([
    # P0
    "sqli", "xss", "file-upload", "auth-bypass",
    # P1
    "ssrf", "ssti", "lfi", "rfi", "redirect", "cors",
    # Config
    "exposures", "misconfig", "default-login",
])

_SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "unknown": "low",
}

_ALL_CATEGORIES = {
    "sqli", "xss", "ssrf", "ssti", "lfi", "rfi",
    "file-upload", "auth-bypass", "redirect", "cors",
    "exposures", "misconfig", "default-login", "tech-detect",
    "cve",
}


# ---------------------------------------------------------------------------
# public API — two-pass scan
# ---------------------------------------------------------------------------
import re as _re

# Patterns for splitting tech-detect results into specific fingerprint entries
_TECH_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, name_template, category)
    ("Server:\\s*(.+)", "Server: {}", "server"),
    ("X-Powered-By:\\s*(.+)", "X-Powered-By: {}", "runtime"),
    ("Generator:\\s*(.+)", "Generator: {}", "framework"),
    ("Set-Cookie:\\s*(.+?);", "Cookie: {}", "framework"),
]

# Body patterns for framework detection
_BODY_PATTERNS: list[tuple[str, str, str]] = [
    ("wp-content", "WordPress", "cms"),
    ("wp-includes", "WordPress", "cms"),
    ("<!-- Generator: (.+) -->", "{}", "framework"),
    ('<meta name="generator" content="(.+?)"', "{}", "framework"),
]


def _split_tech_detect(entry: dict) -> list[dict]:
    """Split a tech-detect result into specific technology fingerprint entries."""
    response = entry.get("response", "")
    info = entry.get("info", {}) or {}
    host = entry.get("host", entry.get("matched-at", ""))
    matched_at = entry.get("matched-at", "")

    results: list[dict] = []
    seen: set[str] = set()

    if not response:
        return []

    # Split response into headers and body
    parts = response.split("\r\n\r\n", 1)
    headers = parts[0] if parts else ""
    body = parts[1] if len(parts) > 1 else ""

    # Check header patterns
    for pattern, name_tpl, category in _TECH_PATTERNS:
        m = _re.search(pattern, headers, _re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            key = f"{category}:{val}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "template_id": "tech-detect",
                    "host": host,
                    "matched_at": matched_at,
                    "name": name_tpl.format(val),
                    "severity": "info",
                    "extracted": val,
                    "category": category,
                })

    # Check body patterns
    for pattern, name_tpl, category in _BODY_PATTERNS:
        m = _re.search(pattern, body, _re.IGNORECASE)
        if m:
            val = m.group(1).strip() if m.lastindex else name_tpl
            key = f"{category}:{val}"
            if key not in seen:
                seen.add(key)
                results.append({
                    "template_id": "tech-detect",
                    "host": host,
                    "matched_at": matched_at,
                    "name": name_tpl.format(val) if "{}" in name_tpl else name_tpl,
                    "severity": "info",
                    "extracted": val if m.lastindex else "",
                    "category": category,
                })

    # If no patterns matched, return the original generic result
    if not results:
        extracted = (
            entry.get("matcher-name", "")
            or info.get("metadata", {}).get("product", "")
            or entry.get("extracted-results", [])
        )
        return [{
            "template_id": entry.get("template-id", ""),
            "host": host,
            "matched_at": matched_at,
            "name": info.get("name", ""),
            "severity": "info",
            "extracted": extracted,
        }]

    return results


async def scan_fingerprints(targets: list[str], timeout: float = 120.0) -> list[dict]:
    """Pass 1: detect frameworks, services, and component versions."""
    raw = await _run_nuclei(targets, ids=_TECH_IDS, severity="info,low,medium,high,critical",
                            timeout=timeout, concurrency=15)
    fingerprints: list[dict] = []
    for entry in raw:
        if entry.get("template-id") == "tech-detect":
            fingerprints.extend(_split_tech_detect(entry))
        else:
            info = entry.get("info", {}) or {}
            extracted = (
                entry.get("matcher-name", "")
                or info.get("metadata", {}).get("product", "")
                or entry.get("extracted-results", [])
            )
            fingerprints.append({
                "template_id": entry.get("template-id", ""),
                "host": entry.get("host", entry.get("matched-at", "")),
                "matched_at": entry.get("matched-at", ""),
                "name": info.get("name", ""),
                "severity": _SEVERITY_MAP.get(info.get("severity", "info"), "info"),
                "extracted": extracted,
            })
    return fingerprints[:50]


async def scan_vulnerabilities(
    targets: list[str],
    fingerprints: list[dict] | None = None,
    timeout: float = 600.0,
    tags: str | None = None,
) -> list[dict]:
    """Pass 2: run CVE + vuln templates.

    *fingerprints* are passed as context (consumed by Planner in phase 4-5,
    but also used here to optionally scope CVE templates to detected products).
    *tags* scopes the nuclei -tags selection (planner-driven precision strike);
    defaults to the lightweight demo tag set (heavy tags like cve only via tags).
    """
    raw = await _run_nuclei(targets, tags=tags or _VULN_TAGS,
                            severity="critical,high,medium,low",
                            timeout=timeout, concurrency=50)
    results: list[dict] = []
    for entry in raw:
        results.append(_normalize_vuln(entry))

    return results[:100]


async def scan(
    targets: list[str],
    fingerprint_timeout: float = 120.0,
    vuln_timeout: float = 300.0,
) -> tuple[list[dict], list[dict]]:
    """Combined two-pass: returns (fingerprints, vulnerabilities)."""
    fps = await scan_fingerprints(targets, timeout=fingerprint_timeout)
    vulns = await scan_vulnerabilities(targets, fingerprints=fps, timeout=vuln_timeout)
    return fps, vulns


# ---------------------------------------------------------------------------
# internal
# ---------------------------------------------------------------------------
async def _run_nuclei(
    targets: list[str],
    tags: str | None = None,
    ids: str | None = None,
    severity: str = "info,low,medium,high,critical",
    timeout: float = 120.0,
    concurrency: int = 15,
    # Per-request timeout: 10s keeps slow/legacy services from eating the
    # whole wall-clock budget (was 30s and dominated runtime on old targets).
    request_timeout: float = 10.0,
) -> list[dict]:
    nuclei_path = resolve_tool("nuclei")
    if nuclei_path is None:
        return []

    if tags is None and ids is None:
        raise ValueError("_run_nuclei requires tags or ids")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8",
    ) as f:
        f.write("\n".join(targets))
        targets_file = f.name

    cmd = [
        nuclei_path,
        "-list", targets_file,
        "-severity", severity,
        "-jsonl",
        "-duc",  # disable update check (prevents network hang)
        "-no-mhe", "-no-interactsh",
        "-timeout", str(int(request_timeout)),
        "-concurrency", str(concurrency),
    ]
    if ids is not None:
        cmd += ["-id", ids]
    else:
        cmd += ["-tags", tags]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=timeout + 60.0,
        )
    except asyncio.TimeoutError:
        return []
    finally:
        Path(targets_file).unlink(missing_ok=True)

    return [
        json.loads(line)
        for line in stdout.decode(errors="replace").splitlines()
        if line.strip().startswith("{")
    ]


def _normalize_vuln(entry: dict) -> dict:
    info = entry.get("info", {}) or {}
    classification = info.get("classification", {}) or {}
    matched_at = _canonical_url(entry.get("matched-at", entry.get("host", "")))
    return {
        "vulnerability_id": _make_vuln_id(entry, matched_at),
        "category": _extract_category(entry),
        "severity": _SEVERITY_MAP.get(info.get("severity", "low"), "low"),
        "title": info.get("name", "Unknown"),
        "cve_ref": _first(classification.get("cve-id", [])),
        "cwe_ref": _first(classification.get("cwe-id", [])),
        "matched_at": matched_at,
        "template_id": entry.get("template-id", ""),
        "curl_command": entry.get("curl-command", ""),
        "verified": False,
        "waf_detected": False,
        "raw_output": entry.get("extracted-results", []),
    }


def _make_vuln_id(entry: dict, matched_at: str | None = None) -> str:
    template = entry.get("template-id", "unknown")
    host = matched_at or entry.get("host", entry.get("matched-at", "unknown"))
    key = f"{template}:{host}"
    return f"vuln-{hashlib.sha256(key.encode()).hexdigest()[:16]}"


def _canonical_url(value: str) -> str:
    """Drop default ports so ``http://h`` and ``http://h:80`` dedupe as one finding."""
    if not value or "://" not in value:
        return value
    from urllib.parse import urlparse, urlunparse

    parsed = urlparse(value)
    host = parsed.hostname or ""
    port = parsed.port
    netloc = host if port in (None, 80, 443) else f"{host}:{port}"
    return urlunparse((parsed.scheme, netloc, parsed.path, "", parsed.query, ""))


def _extract_category(entry: dict) -> str:
    info = entry.get("info", {}) or {}
    tags = info.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if tag in _ALL_CATEGORIES:
                return tag
    template_id = entry.get("template-id", "")
    # CVE templates often have "CVE-YYYY-NNNNN" in the template ID
    if "CVE-" in template_id.upper():
        return "cve"
    for cat in _ALL_CATEGORIES:
        if cat in template_id.lower():
            return cat
    return "unknown"


def _first(lst: list) -> str | None:
    return lst[0] if lst else None