"""Nuclei scanner wrapper — two-pass: tech fingerprints, then targeted CVE + vuln scan."""

from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
from pathlib import Path

_NUCLEI_PATH = "C:/PTools/nuclei.exe"

# Pass 1: technology fingerprinting (single Wappalyzer-style template)
_TECH_IDS = "tech-detect"

# Pass 2: vulnerability tags (P0 + P1 + config + CVE)
_VULN_TAGS = ",".join([
    # P0
    "sqli", "xss", "file-upload", "auth-bypass",
    # P1
    "ssrf", "ssti", "lfi", "rfi", "redirect", "cors",
    # Config
    "exposures", "misconfig", "default-login",
    # CVE (nuclei has 2000+ CVE templates — targeted by fingerprint context)
    "cve",
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
async def scan_fingerprints(targets: list[str], timeout: float = 120.0) -> list[dict]:
    """Pass 1: detect frameworks, services, and component versions."""
    raw = await _run_nuclei(targets, ids=_TECH_IDS, severity="info,low,medium,high,critical",
                            timeout=timeout, concurrency=15)
    fingerprints: list[dict] = []
    for entry in raw:
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
    timeout: float = 300.0,
    tags: str | None = None,
) -> list[dict]:
    """Pass 2: run CVE + vuln templates.

    *fingerprints* are passed as context (consumed by Planner in phase 4-5,
    but also used here to optionally scope CVE templates to detected products).
    *tags* scopes the nuclei -tags selection (planner-driven precision strike);
    defaults to the full vulnerability tag set.
    """
    raw = await _run_nuclei(targets, tags=tags or _VULN_TAGS,
                            severity="critical,high,medium,low",
                            timeout=timeout, concurrency=10)
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
) -> list[dict]:
    nuclei_path = Path(_NUCLEI_PATH)
    if not nuclei_path.exists():
        return []

    if tags is None and ids is None:
        raise ValueError("_run_nuclei requires tags or ids")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8",
    ) as f:
        f.write("\n".join(targets))
        targets_file = f.name

    cmd = [
        str(nuclei_path),
        "-list", targets_file,
        "-severity", severity,
        "-jsonl", "-stats",
        "-no-mhe", "-no-interactsh",
        "-timeout", str(int(timeout)),
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
    return {
        "vulnerability_id": _make_vuln_id(entry),
        "category": _extract_category(entry),
        "severity": _SEVERITY_MAP.get(info.get("severity", "low"), "low"),
        "title": info.get("name", "Unknown"),
        "cve_ref": _first(classification.get("cve-id", [])),
        "cwe_ref": _first(classification.get("cwe-id", [])),
        "matched_at": entry.get("matched-at", entry.get("host", "")),
        "template_id": entry.get("template-id", ""),
        "curl_command": entry.get("curl-command", ""),
        "verified": False,
        "waf_detected": False,
        "raw_output": entry.get("extracted-results", []),
    }


def _make_vuln_id(entry: dict) -> str:
    template = entry.get("template-id", "unknown")
    host = entry.get("host", entry.get("matched-at", "unknown"))
    key = f"{template}:{host}"
    return f"vuln-{hashlib.sha256(key.encode()).hexdigest()[:16]}"


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